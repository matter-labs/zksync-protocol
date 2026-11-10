//! vm2 against `zk_evm` for a hash decommitted before execution.
//!
//! [`zk_evm_vm`] seeds the entry program on `BOOTLOADER_CODE_PAGE` as the prover does
//! (`zkevm_test_harness::run_vms`); vm2 seeds it with [`VirtualMachine::manually_decommit`], as
//! the Airbender verifier does for the bootloader. A later decommit of the hash must be a repeat
//! in both: the `decommit` opcode refunds its extra cost and reads the same bytes, and a far call
//! to that code pays no decommit. vm2's seed takes its first dynamic page group, so
//! [`zk_evm_page`] maps vm2 pages back before pointers are compared.

use std::cmp::Ordering;

use primitive_types::{H160, U256};
use zk_evm::{utils::bytecode_to_code_hash, vm_state::PrimitiveValue};
use zkevm_opcode_defs::{
    decoding::EncodingModeProduction, system_params::DEPLOYER_SYSTEM_CONTRACT_ADDRESS_LOW,
    AddOpcode, Condition, DecodedOpcode, FarCallOpcode, ImmMemHandlerFlags, JumpOpcode, LogOpcode,
    Opcode, Operand, PtrOpcode, RegOrImmFlags, SubOpcode, UMAOpcode, BOOTLOADER_CODE_PAGE,
    ERGS_PER_CODE_WORD_DECOMMITTMENT, NEW_MEMORY_PAGES_PER_FAR_CALL, STARTING_BASE_PAGE,
};

use self::zk_evm_harness::{encode_ret, find_variant, zk_evm_vm, ZkNoopTracer, ZkVm};
use crate::{
    instruction::ExecutionStatus, instruction_handlers::address_into_u256, testonly::TestWorld,
    Predicate, Program, Settings, VirtualMachine,
};

mod zk_evm_harness;

/// Kernel, so the program may use `decommit`.
const ROOT: u64 = 0x8009;
const CALLEE: u64 = 0x1_2345;
const GAS: u32 = 1 << 24;
const EXTRA_COST: u32 = 100_000;
const FAR_CALL_GAS: u32 = 100_000;
/// Odd, as EraVM requires; long enough that a fresh far-call decommit costs a visible amount.
const CODE_WORDS: usize = 101;
/// Last code word, so the code's final bytes are nonzero.
const MARKER: [u8; 32] = [0xab; 32];
const STEP_LIMIT: usize = 1_000;

type Vm2 = VirtualMachine<(), TestWorld<()>>;

#[derive(Clone, Copy)]
enum Src0 {
    Reg(u8),
    Imm(u16),
}

fn is_reg(operand: Operand) -> bool {
    matches!(
        operand,
        Operand::RegOnly
            | Operand::RegOrImm(RegOrImmFlags::UseRegOnly)
            | Operand::Full(ImmMemHandlerFlags::UseRegOnly)
    )
}

fn is_imm(operand: Operand) -> bool {
    matches!(
        operand,
        Operand::RegOrImm(RegOrImmFlags::UseImm16Only)
            | Operand::Full(ImmMemHandlerFlags::UseImm16Only)
    )
}

/// One raw instruction word with register operands. `imm_0` is the jump target or the far-call
/// exception handler.
fn encode(
    opcode: Opcode,
    condition: Condition,
    src0: Src0,
    src1: u8,
    dst0: u8,
    set_flags: bool,
    imm_0: u16,
) -> u64 {
    let variant = find_variant(|variant| {
        variant.opcode == opcode
            && match src0 {
                Src0::Reg(_) => is_reg(variant.src0_operand_type),
                Src0::Imm(_) => is_imm(variant.src0_operand_type),
            }
            && is_reg(variant.dst0_operand_type)
            && variant.flags == [set_flags, false]
    });
    let (src0_reg_idx, imm_0) = match src0 {
        Src0::Reg(reg) => (reg, imm_0),
        Src0::Imm(imm) => (0, imm),
    };
    DecodedOpcode::<8, EncodingModeProduction> {
        variant,
        condition,
        src0_reg_idx,
        src1_reg_idx: src1,
        dst0_reg_idx: dst0,
        dst1_reg_idx: 0,
        imm_0,
        imm_1: 0,
    }
    .serialize_as_integer()
}

/// Packs four instructions per word, pads with zero words and ends on [`MARKER`].
fn assemble(instructions: &[u64]) -> Vec<[u8; 32]> {
    let mut words: Vec<[u8; 32]> = instructions
        .chunks(4)
        .map(|chunk| {
            let mut word = [0; 32];
            for (position, instruction) in chunk.iter().enumerate() {
                word[position * 8..][..8].copy_from_slice(&instruction.to_be_bytes());
            }
            word
        })
        .collect();
    words.resize(CODE_WORDS - 1, [0; 32]);
    words.push(MARKER);
    words
}

/// `zk_evm`'s page for vm2's `page`, given vm2's seed took the first group.
fn zk_evm_page(page: u32) -> u32 {
    match page.cmp(&STARTING_BASE_PAGE) {
        Ordering::Less => page,
        Ordering::Equal => BOOTLOADER_CODE_PAGE,
        Ordering::Greater => {
            assert!(page >= STARTING_BASE_PAGE + NEW_MEMORY_PAGES_PER_FAR_CALL);
            page - NEW_MEMORY_PAGES_PER_FAR_CALL
        }
    }
}

fn page_of(pointer: U256) -> u32 {
    (pointer >> 32).low_u32()
}

fn with_page(pointer: U256, page: u32) -> U256 {
    let mask = U256::from(u32::MAX) << 32;
    (pointer & !mask) | (U256::from(page) << 32)
}

/// What both VMs must agree on at a stop point.
#[derive(Debug, PartialEq)]
struct Snapshot {
    /// r1..r15 with pointer flags; vm2's pointer pages in `zk_evm` numbering.
    registers: Vec<(U256, bool)>,
    /// (lt, eq, gt)
    flags: (bool, bool, bool),
    gas: u32,
}

fn vm2_snapshot(vm: &Vm2) -> Snapshot {
    Snapshot {
        registers: (1..16)
            .map(|index| {
                let value = vm.state.registers[index];
                let is_pointer = vm.state.register_pointer_flags & (1 << index) != 0;
                let value = if is_pointer {
                    with_page(value, zk_evm_page(page_of(value)))
                } else {
                    value
                };
                (value, is_pointer)
            })
            .collect(),
        flags: (
            Predicate::IfLT.satisfied(&vm.state.flags),
            Predicate::IfEQ.satisfied(&vm.state.flags),
            Predicate::IfGT.satisfied(&vm.state.flags),
        ),
        gas: vm.state.current_frame.gas,
    }
}

fn zk_snapshot(zk: &ZkVm) -> Snapshot {
    let state = &zk.local_state;
    Snapshot {
        registers: state
            .registers
            .iter()
            .map(|register| (register.value, register.is_pointer))
            .collect(),
        flags: (
            state.flags.overflow_or_less_than_flag,
            state.flags.equality_flag,
            state.flags.greater_than_flag,
        ),
        gas: state.callstack.get_current_stack().ergs_remaining,
    }
}

/// One program loaded into both VMs, the callee address bound to its hash in both.
struct Setup {
    code: Vec<u8>,
    zk: ZkVm,
    vm2: Vm2,
    world: TestWorld<()>,
}

impl Setup {
    /// `registers` gets the program's hash.
    fn new(
        instructions: &[u64],
        seed_vm2: bool,
        registers: impl Fn(U256) -> Vec<(usize, U256)>,
    ) -> Self {
        let bytecode = assemble(instructions);
        let code: Vec<u8> = bytecode.iter().flatten().copied().collect();
        let hash = U256::from_big_endian(&bytecode_to_code_hash(&bytecode).unwrap());
        let root = H160::from_low_u64_be(ROOT);
        let callee = address_into_u256(H160::from_low_u64_be(CALLEE));

        let mut zk = zk_evm_vm(&bytecode, root, GAS);
        zk.storage.populate(vec![(
            0,
            H160::from_low_u64_be(DEPLOYER_SYSTEM_CONTRACT_ADDRESS_LOW.into()),
            callee,
            hash,
        )]);

        let program = Program::new(&code, false);
        let mut world = TestWorld::new(&[]);
        world.hash_to_contract.insert(hash, program.clone());
        world.address_to_hash.insert(callee, hash);
        let mut vm2 = VirtualMachine::new(
            root,
            program,
            H160::zero(),
            &[],
            GAS,
            Settings {
                default_aa_code_hash: [0; 32],
                evm_interpreter_code_hash: [0; 32],
                hook_address: 0,
            },
        );
        if seed_vm2 {
            assert!(vm2.manually_decommit(&mut world, &mut (), hash));
        }

        vm2.state.register_pointer_flags = 0;
        let zeroed = (1..16).map(|index| (index, U256::zero()));
        for (index, value) in zeroed.chain(registers(hash)) {
            vm2.state.registers[index] = value;
            zk.local_state.registers[index - 1] = PrimitiveValue {
                value,
                is_pointer: false,
            };
        }
        Self {
            code,
            zk,
            vm2,
            world,
        }
    }

    /// Runs both VMs until the root frame is about to execute `pc`.
    fn run_to(&mut self, pc: u16) {
        let root = H160::from_low_u64_be(ROOT);
        let vm2_at_stop = |vm: &Vm2| {
            vm.state.previous_frames.is_empty()
                && vm.state.current_frame.near_calls.is_empty()
                && vm.state.current_frame.get_pc_as_u16() == pc
        };
        for step in 0.. {
            assert!(step < STEP_LIMIT, "vm2 didn't reach pc {pc}");
            if vm2_at_stop(&self.vm2) {
                break;
            }
            let status = unsafe {
                ((*self.vm2.state.current_frame.pc).handler)(
                    &mut self.vm2,
                    &mut self.world,
                    &mut (),
                )
            };
            assert!(
                matches!(status, ExecutionStatus::Running),
                "vm2 ended before pc {pc}"
            );
        }
        for step in 0.. {
            assert!(step < STEP_LIMIT, "zk_evm didn't reach pc {pc}");
            let frame = self.zk.local_state.callstack.get_current_stack();
            if frame.this_address == root
                && !frame.is_local_frame
                && frame.pc == pc
                && !self.zk.local_state.pending_exception
            {
                break;
            }
            self.zk
                .cycle(&mut ZkNoopTracer)
                .expect("zk_evm cycle must not fail");
            assert!(
                !self.zk.execution_has_ended(),
                "zk_evm ended before pc {pc}"
            );
        }
    }
}

/// r9 = decommit(r7) with extra cost r8, then two reads through r9: the first code word, and the
/// last 16 code bytes followed by 16 bytes past the end (r14 holds that offset).
#[rustfmt::skip]
fn decommit_program() -> [u64; 5] {
    let always = Condition::Always;
    [
        encode(Opcode::Log(LogOpcode::Decommit), always, Src0::Reg(7), 8, 9, false, 0),
        encode(Opcode::UMA(UMAOpcode::FatPointerRead), always, Src0::Reg(9), 0, 10, false, 0),
        encode(Opcode::Ptr(PtrOpcode::Add), always, Src0::Reg(9), 14, 11, false, 0),
        encode(Opcode::UMA(UMAOpcode::FatPointerRead), always, Src0::Reg(11), 0, 12, false, 0),
        encode_ret(false), // pc 4: stop
    ]
}

const DECOMMIT_STOP: u16 = 4;

fn decommit_setup(seed_vm2: bool) -> Setup {
    let code_len = u64::try_from(CODE_WORDS * 32).unwrap();
    Setup::new(&decommit_program(), seed_vm2, |hash| {
        vec![
            (7, hash),
            (8, EXTRA_COST.into()),
            (14, (code_len - 16).into()),
        ]
    })
}

#[test]
fn decommit_of_the_seeded_hash_is_a_refunded_repeat() {
    let mut setup = decommit_setup(true);
    setup.run_to(DECOMMIT_STOP);
    let theirs = zk_snapshot(&setup.zk);
    assert_eq!(vm2_snapshot(&setup.vm2), theirs);

    // The repeat points at the seeded page in each VM's numbering.
    assert_eq!(
        page_of(setup.zk.local_state.registers[8].value),
        BOOTLOADER_CODE_PAGE
    );
    assert_eq!(page_of(setup.vm2.state.registers[9]), STARTING_BASE_PAGE);
    // It reads the code, with zeros after it.
    let code = &setup.code;
    assert_eq!(theirs.registers[9].0, U256::from_big_endian(&code[..32]));
    let mut straddle = [0; 32];
    straddle[..16].copy_from_slice(&code[code.len() - 16..]);
    assert_eq!(theirs.registers[11].0, U256::from_big_endian(&straddle));
    assert!(
        GAS - theirs.gas < EXTRA_COST,
        "the extra cost must be refunded"
    );
}

#[test]
fn without_the_seed_vm2_charges_the_decommit_extra_cost() {
    let mut seeded = decommit_setup(true);
    seeded.run_to(DECOMMIT_STOP);
    let mut unseeded = decommit_setup(false);
    unseeded.run_to(DECOMMIT_STOP);
    assert_eq!(
        seeded.vm2.state.current_frame.gas - unseeded.vm2.state.current_frame.gas,
        EXTRA_COST
    );
}

/// The root far-calls `CALLEE`, whose code hash is the program's own, and stops after the return.
/// The callee runs the same code; r13 is 1 in the root and zeroed on far-call entry, which sends
/// the callee straight to an empty return.
#[rustfmt::skip]
fn far_call_program() -> [u64; 7] {
    let always = Condition::Always;
    [
        encode(Opcode::Sub(SubOpcode::Sub), always, Src0::Reg(13), 0, 0, true, 0),
        encode(Opcode::Jump(JumpOpcode), Condition::Eq, Src0::Imm(4), 0, 0, false, 0),
        encode(Opcode::FarCall(FarCallOpcode::Normal), always, Src0::Reg(5), 6, 0, false, 6),
        encode_ret(false), // pc 3: stop
        encode(Opcode::Add(AddOpcode::Add), always, Src0::Reg(0), 0, 1, false, 0), // callee: r1 = 0
        encode_ret(false),
        encode_ret(true), // far-call exception handler
    ]
}

const FAR_CALL_STOP: u16 = 3;

fn far_call_setup(seed_vm2: bool) -> Setup {
    // Far-call ABI: empty calldata from the heap, `FAR_CALL_GAS` passed.
    let abi = U256([0, 0, 0, FAR_CALL_GAS.into()]);
    let callee = address_into_u256(H160::from_low_u64_be(CALLEE));
    Setup::new(&far_call_program(), seed_vm2, |_| {
        vec![(5, abi), (6, callee), (13, U256::one())]
    })
}

#[test]
fn far_call_to_the_seeded_hash_pays_no_decommit() {
    let mut setup = far_call_setup(true);
    setup.run_to(FAR_CALL_STOP);
    assert_eq!(vm2_snapshot(&setup.vm2), zk_snapshot(&setup.zk));
}

#[test]
fn without_the_seed_vm2_charges_the_far_call_decommit() {
    let mut seeded = far_call_setup(true);
    seeded.run_to(FAR_CALL_STOP);
    let mut unseeded = far_call_setup(false);
    unseeded.run_to(FAR_CALL_STOP);
    let words = u32::try_from(CODE_WORDS).unwrap();
    assert_eq!(
        seeded.vm2.state.current_frame.gas - unseeded.vm2.state.current_frame.gas,
        words * ERGS_PER_CODE_WORD_DECOMMITTMENT
    );
}
