//! Repeat far calls use the previously decommitted page.
//!
//! `CodeOracle` leaves the last four hash bytes past a one-word contract's bytecode.
//! A later far call must read those bytes through `code[1]`, matching `zk_evm`.

use std::collections::BTreeMap;

use primitive_types::{H160, U256};
use zkevm_opcode_defs::{
    bytecode_to_code_hash, decoding::EncodingModeProduction, ethereum_types::Address,
    system_params::DEPLOYER_SYSTEM_CONTRACT_ADDRESS_LOW, DecodedOpcode, Opcode, OpcodeVariant,
    Operand, RetOpcode,
};
use zksync_vm2_interface::{opcodes::Normal, CallframeInterface, StateInterface};

use crate::{
    addressing_modes::*,
    page_ids::{code_page_from_base, first_dynamic_base_page},
    testonly::TestWorld,
    *,
};

type I = Instruction<(), TestWorld<()>>;

fn a() -> Arguments {
    Arguments::new(Predicate::Always, 5, ModeRequirements::none())
}
fn r(i: u8) -> Register {
    Register::new(i)
}
fn code(i: u16, dst: u8) -> I {
    let src = CodePage(RegisterAndImmediate {
        immediate: i,
        register: r(0),
    });
    Instruction::from_add(
        src.into(),
        Register2(r(0)),
        Register1(r(dst)).into(),
        a(),
        false,
        false,
    )
}
fn call(fail: u16) -> I {
    Instruction::from_far_call::<Normal>(
        Register1(r(4)),
        Register2(r(5)),
        Immediate1(fail),
        false,
        false,
        a(),
    )
}
fn mstore(addr: u8, val: u8, hook: bool) -> I {
    Instruction::from_heap_write(
        Register1(r(addr)).into(),
        Register2(r(val)),
        None,
        a(),
        hook,
    )
}
fn ret() -> I {
    Instruction::from_ret(Register1(r(0)), None, a())
}

/// Returns (X's slot 0, X's code hash, word 1 of X's decommit page if it has one).
fn run(oracle_first: bool) -> (U256, U256, Option<U256>) {
    let (x, k) = (
        Address::from_low_u64_be(0x1_eeee),
        Address::from_low_u64_be(0x8012),
    );
    let sstore = Instruction::from_storage_write(Register1(r(0)), Register2(r(2)), a());
    let x_code = Program::from_raw(vec![code(1, 2), sstore, ret()], vec![U256::from(0xc0de)]);
    // `TestWorld` hashes by index and code page; X is first in both worlds.
    let hash = TestWorld::new(&[(x, x_code.clone())]).address_to_hash[&U256::from(0x1_eeee)];

    let decommit =
        Instruction::from_decommit(Register1(r(1)), Register2(r(0)), Register1(r(3)), a());
    let k_code = Program::from_raw(
        vec![code(0, 1), code(1, 2), mstore(2, 1, false), decommit, ret()],
        vec![hash, U256::from(4)],
    );

    let fail = if oracle_first { 7 } else { 4 };
    let mut b = if oracle_first {
        vec![code(0, 4), code(1, 5), call(fail)]
    } else {
        vec![]
    };
    b.extend([code(0, 4), code(2, 5), call(fail), mstore(0, 0, true)]);
    b.push(Instruction::from_revert(Register1(r(0)), None, a()));
    let mut gas = U256::zero();
    gas.0[3] = 1_000_000;
    let b = Program::from_raw(b, vec![gas, U256::from(0x8012), U256::from(0x1_eeee)]);

    let mut world = TestWorld::new(&[(x, x_code), (k, k_code)]);
    let settings = Settings {
        default_aa_code_hash: [0; 32],
        evm_interpreter_code_hash: [0; 32],
        hook_address: 0,
    };
    let mut vm = VirtualMachine::new(
        Address::from_low_u64_be(0x8001),
        b,
        Address::zero(),
        &[],
        10_000_000,
        settings,
    );
    assert_eq!(
        vm.run(&mut world, &mut ()),
        ExecutionEnd::SuspendedOnHook(0)
    );
    let page_word_1 = vm
        .world_diff
        .decommit_page(hash)
        .map(|page| vm.state.heaps[page].read_u256(32));
    (
        vm.world_diff.get_storage_state()[&(x, U256::zero())].value,
        hash,
        page_word_1,
    )
}

#[test]
fn code_read_past_end_after_code_oracle_decommit() {
    assert_eq!(run(false).0, U256::zero());
    let (written, hash, page_word_1) = run(true);
    let leftover = (hash & U256::from(u32::MAX)) << 224;
    // The premise holds in vm2 too: the decommit page keeps `H[28..32]` past the code.
    assert_eq!(
        page_word_1,
        Some(leftover),
        "decommit page lost the leftover bytes"
    );
    // zk_evm runs X from that page, so `code[1]` reads the leftover; vm2 reads its own copy.
    assert_eq!(written, leftover, "vm2 != zk_evm");
}

// ---- Shared scenario pieces ---------------------------------------------------------------

const X: u64 = 0x1_eeee;
const Y: u64 = 0x1_ffff;
const K1: u64 = 0x8012;
const K2: u64 = 0x8013;
const K3: u64 = 0x8014;

type P = Program<(), TestWorld<()>>;

fn addr(low: u64) -> Address {
    Address::from_low_u64_be(low)
}

fn settings() -> Settings {
    Settings {
        default_aa_code_hash: [0; 32],
        evm_interpreter_code_hash: [0; 32],
        hook_address: 0,
    }
}

fn new_vm(bootloader: P) -> VirtualMachine<(), TestWorld<()>> {
    VirtualMachine::new(
        addr(0x8001),
        bootloader,
        Address::zero(),
        &[],
        10_000_000,
        settings(),
    )
}

fn gas_abi() -> U256 {
    let mut gas = U256::zero();
    gas.0[3] = 1_000_000;
    gas
}

fn hook() -> I {
    mstore(0, 0, true)
}

fn revert() -> I {
    Instruction::from_revert(Register1(r(0)), None, a())
}

/// Far call to the address at code word `addr_idx` with the gas ABI at code word 0.
fn far_call(addr_idx: u16, fail: u16) -> [I; 3] {
    [code(0, 4), code(addr_idx, 5), call(fail)]
}

/// `ret.ok r0` as the 8-byte word an instruction fetch decodes.
fn encoded_ret_ok() -> u64 {
    DecodedOpcode::<8, EncodingModeProduction> {
        variant: OpcodeVariant {
            opcode: Opcode::Ret(RetOpcode::Ok),
            src0_operand_type: Operand::RegOnly,
            dst0_operand_type: Operand::RegOnly,
            flags: [false; 2],
        },
        ..Default::default()
    }
    .serialize_as_integer()
}

/// A code word whose first instruction slot is `raw`.
fn word_starting_with(raw: u64) -> U256 {
    U256::from(raw) << 192
}

/// Contract that stores `code[1]` into its slot 0 and returns. One word of code, so word 1 is
/// past its end.
fn store_code_word_1(code_word: u64) -> P {
    let sstore = Instruction::from_storage_write(Register1(r(0)), Register2(r(2)), a());
    Program::from_raw(vec![code(1, 2), sstore, ret()], vec![U256::from(code_word)])
}

/// `CodeOracle` stand-in: writes `leftover` at heap offset 32, then `decommit`s `hash`.
fn oracle(hash: U256, leftover: U256) -> P {
    let decommit =
        Instruction::from_decommit(Register1(r(1)), Register2(r(0)), Register1(r(3)), a());
    Program::from_raw(
        vec![
            code(0, 1),
            code(1, 2),
            code(2, 3),
            mstore(3, 2, false),
            decommit,
            ret(),
        ],
        vec![hash, leftover, U256::from(32)],
    )
}

fn hashes_of(x: &P, y: &P) -> (U256, U256) {
    let world = TestWorld::new(&[(addr(X), x.clone()), (addr(Y), y.clone())]);
    (
        world.address_to_hash[&U256::from(X)],
        world.address_to_hash[&U256::from(Y)],
    )
}

fn slot(vm: &VirtualMachine<(), TestWorld<()>>, contract: u64, key: U256) -> Option<U256> {
    vm.world_diff
        .get_storage_state()
        .get(&(addr(contract), key))
        .map(|slot| slot.value)
}

#[test]
fn alias_decommit_feeds_canonical_far_call() {
    let x_code = store_code_word_1(0xc0de);
    let (hash, _) = hashes_of(&x_code, &x_code);
    // Same normalized preimage, "yet constructed" marker in the header.
    let alias = hash | (U256::one() << 240);
    let leftover = U256::from(0x1111_u64) << 128;

    let bootloader = Program::from_raw(
        [
            far_call(1, 7).as_slice(),
            &far_call(2, 7),
            &[hook(), revert()],
        ]
        .concat(),
        vec![gas_abi(), U256::from(K1), U256::from(X)],
    );
    let mut world = TestWorld::new(&[
        (addr(X), x_code.clone()),
        (addr(K1), oracle(alias, leftover)),
    ]);
    world.hash_to_contract.insert(alias, x_code);
    let mut vm = new_vm(bootloader);

    assert_eq!(
        vm.run(&mut world, &mut ()),
        ExecutionEnd::SuspendedOnHook(0)
    );
    assert_eq!(slot(&vm, X, U256::zero()), Some(leftover));
    assert_eq!(world.decommit_code_calls(), 1);
    assert_eq!(
        vm.world_diff.decommit_page(alias),
        vm.world_diff.decommit_page(hash)
    );
}

/// X jumps past its one word of code; whether that word holds `ret.ok` or zeros decides
/// whether X returns or panics.
fn run_jump_past_end(leftover: U256) -> ExecutionEnd {
    let x_code = Program::from_raw(
        vec![Instruction::from_jump(
            Immediate1(4).into(),
            Register1(r(0)),
            a(),
        )],
        vec![U256::from(0xc0de)],
    );
    let (hash, _) = hashes_of(&x_code, &x_code);
    let bootloader = Program::from_raw(
        [
            far_call(1, 7).as_slice(),
            &far_call(2, 7),
            &[hook(), revert()],
        ]
        .concat(),
        vec![gas_abi(), U256::from(K1), U256::from(X)],
    );
    let mut world = TestWorld::new(&[(addr(X), x_code), (addr(K1), oracle(hash, leftover))]);
    new_vm(bootloader).run(&mut world, &mut ())
}

#[test]
fn leftover_past_end_executes() {
    assert_eq!(
        run_jump_past_end(U256::zero()),
        ExecutionEnd::Reverted(vec![])
    );
    assert_eq!(
        run_jump_past_end(word_starting_with(encoded_ret_ok())),
        ExecutionEnd::SuspendedOnHook(0)
    );
}

#[test]
fn live_owner_rewrites_page_between_calls() {
    // X stores `code[1]` under key `code[1]`, so both reads stay visible.
    let sstore = Instruction::from_storage_write(Register1(r(2)), Register2(r(2)), a());
    let x_code = Program::from_raw(vec![code(1, 2), sstore, ret()], vec![U256::from(0xc0de)]);
    let (hash, _) = hashes_of(&x_code, &x_code);
    let (v1, v2) = (U256::from(0xaaaa_u64) << 128, U256::from(0xbbbb_u64) << 128);

    let decommit =
        Instruction::from_decommit(Register1(r(1)), Register2(r(0)), Register1(r(3)), a());
    // Code words: hash, v1, 32, gas, X, v2. Registers are cleared by each far call.
    let kernel = Program::from_raw(
        [
            vec![
                code(0, 1),
                code(1, 2),
                code(2, 3),
                mstore(3, 2, false),
                decommit,
            ],
            vec![code(3, 4), code(4, 5), call(14)],
            vec![code(2, 3), code(5, 2), mstore(3, 2, false)],
            vec![code(3, 4), code(4, 5), call(14)],
            vec![ret(), revert()],
        ]
        .concat(),
        vec![hash, v1, U256::from(32), gas_abi(), U256::from(X), v2],
    );
    let bootloader = Program::from_raw(
        [far_call(1, 4).as_slice(), &[hook(), revert()]].concat(),
        vec![gas_abi(), U256::from(K1)],
    );
    let mut world = TestWorld::new(&[(addr(X), x_code), (addr(K1), kernel)]);
    let mut vm = new_vm(bootloader);

    assert_eq!(
        vm.run(&mut world, &mut ()),
        ExecutionEnd::SuspendedOnHook(0)
    );
    assert_eq!(slot(&vm, X, v1), Some(v1));
    assert_eq!(slot(&vm, X, v2), Some(v2));
    assert!(
        vm.state.page_programs.as_ref().is_empty(),
        "a page whose owner is alive must not be cached"
    );
}

/// The kernel decommits X, then overwrites X's first code word (or leaves it, for the control).
fn run_overwritten_prefix(overwrite: bool) -> ExecutionEnd {
    let x_code = Program::from_raw(vec![revert()], vec![U256::from(0xc0de)]);
    let (hash, _) = hashes_of(&x_code, &x_code);
    let decommit =
        Instruction::from_decommit(Register1(r(1)), Register2(r(0)), Register1(r(3)), a());
    let mut kernel = vec![code(0, 1), decommit];
    if overwrite {
        kernel.extend([code(1, 2), mstore(0, 2, false)]);
    }
    kernel.push(ret());
    let kernel = Program::from_raw(kernel, vec![hash, word_starting_with(encoded_ret_ok())]);
    let bootloader = Program::from_raw(
        [
            far_call(1, 7).as_slice(),
            &far_call(2, 7),
            &[hook(), revert()],
        ]
        .concat(),
        vec![gas_abi(), U256::from(K1), U256::from(X)],
    );
    let mut world = TestWorld::new(&[(addr(X), x_code), (addr(K1), kernel)]);
    new_vm(bootloader).run(&mut world, &mut ())
}

#[test]
fn overwritten_prefix_runs_the_page() {
    assert_eq!(
        run_overwritten_prefix(false),
        ExecutionEnd::Reverted(vec![])
    );
    assert_eq!(
        run_overwritten_prefix(true),
        ExecutionEnd::SuspendedOnHook(0)
    );
}

#[test]
fn rollback_drops_cached_page_programs() {
    let x_code = store_code_word_1(0xc0de);
    let y_code = store_code_word_1(0xbeef);
    let (hash_x, hash_y) = hashes_of(&x_code, &y_code);
    let [l1, l2, l3] = [1_u64, 2, 3].map(|v| U256::from(v) << 128);

    // Segments, each ending in a hook: 0: K1, X | 7: K2, Y | 14: K3, Y | 21: X | 25: revert.
    let bootloader = Program::from_raw(
        [
            far_call(1, 25).as_slice(),
            &far_call(2, 25),
            &[hook()],
            &far_call(3, 25),
            &far_call(4, 25),
            &[hook()],
            &far_call(5, 25),
            &far_call(4, 25),
            &[hook()],
            &far_call(2, 25),
            &[hook(), revert()],
        ]
        .concat(),
        vec![
            gas_abi(),
            U256::from(K1),
            U256::from(X),
            U256::from(K2),
            U256::from(Y),
            U256::from(K3),
        ],
    );
    let mut world = TestWorld::new(&[
        (addr(X), x_code),
        (addr(Y), y_code),
        (addr(K1), oracle(hash_x, l1)),
        (addr(K2), oracle(hash_y, l2)),
        (addr(K3), oracle(hash_y, l3)),
    ]);
    let mut vm = new_vm(bootloader);

    assert_eq!(
        vm.run(&mut world, &mut ()),
        ExecutionEnd::SuspendedOnHook(0)
    );
    assert_eq!(slot(&vm, X, U256::zero()), Some(l1));
    assert_eq!(vm.state.page_programs.as_ref().len(), 1);

    vm.make_snapshot();
    assert_eq!(
        vm.run(&mut world, &mut ()),
        ExecutionEnd::SuspendedOnHook(0)
    );
    assert_eq!(slot(&vm, Y, U256::zero()), Some(l2));
    assert_eq!(vm.state.page_programs.as_ref().len(), 2);
    let y_page = vm.world_diff.decommit_page(hash_y).unwrap();

    vm.rollback();
    assert_eq!(slot(&vm, Y, U256::zero()), None);
    assert_eq!(vm.world_diff.decommit_page(hash_y), None);
    assert_eq!(vm.state.page_programs.as_ref().len(), 1);

    // K3 gets K2's page id back and fills it with a different leftover.
    vm.current_frame().set_program_counter(14);
    assert_eq!(
        vm.run(&mut world, &mut ()),
        ExecutionEnd::SuspendedOnHook(0)
    );
    assert_eq!(vm.world_diff.decommit_page(hash_y), Some(y_page));
    assert_eq!(slot(&vm, Y, U256::zero()), Some(l3));

    assert_eq!(
        vm.run(&mut world, &mut ()),
        ExecutionEnd::SuspendedOnHook(0)
    );
    assert_eq!(slot(&vm, X, U256::zero()), Some(l1));
}

#[test]
fn clean_code_page_is_unchanged_by_later_decommit() {
    let x_code = store_code_word_1(0xc0de);
    let (hash, _) = hashes_of(&x_code, &x_code);
    let bootloader = Program::from_raw(
        [
            far_call(2, 10).as_slice(),
            &far_call(1, 10),
            &far_call(2, 10),
            &[hook(), revert()],
        ]
        .concat(),
        vec![gas_abi(), U256::from(K1), U256::from(X)],
    );
    let leftover = U256::from(0x2222_u64) << 128;
    let mut world = TestWorld::new(&[(addr(X), x_code), (addr(K1), oracle(hash, leftover))]);
    let mut vm = new_vm(bootloader);

    assert_eq!(
        vm.run(&mut world, &mut ()),
        ExecutionEnd::SuspendedOnHook(0)
    );
    assert_eq!(slot(&vm, X, U256::zero()), Some(U256::zero()));
    assert_eq!(world.decommit_code_calls(), 0);
    let page = vm.world_diff.decommit_page(hash).unwrap();
    assert_eq!(page, code_page_from_base(first_dynamic_base_page()));
    assert_eq!(vm.state.heaps[page].read_u256(32), U256::zero());
    assert!(vm.state.page_programs.as_ref().is_empty());
}

// ---- The zkevm_test_harness scenario, on the same assembled bytecode -----------------------

/// Assembly shared with `zkevm_test_harness::tests::simple_tests::far_call`, which runs it
/// through `zk_evm` and the circuits.
macro_rules! shared_asm {
    ($file:literal) => {
        include_str!(concat!(
            "../../../../../protocol/crates/zkevm_test_harness/src/tests/simple_tests/testdata/",
            "far_call/code_page_past_end/",
            $file
        ))
    };
}

fn assemble(source: &str) -> Vec<u8> {
    zkevm_assembly::Assembly::try_from(source.to_owned())
        .unwrap()
        .compile_to_bytecode()
        .unwrap()
        .concat()
}

/// World keyed by real bytecode hashes, with the deployer storage the harness seeds.
struct AsmWorld {
    hash_by_address: BTreeMap<U256, U256>,
    code_by_hash: BTreeMap<U256, Vec<u8>>,
}

impl AsmWorld {
    fn new(contracts: &[(u64, Vec<u8>)]) -> Self {
        let mut world = Self {
            hash_by_address: BTreeMap::new(),
            code_by_hash: BTreeMap::new(),
        };
        for (address, code) in contracts {
            let (words, []) = code.as_chunks::<32>() else {
                panic!("bytecode is not a whole number of words");
            };
            let hash = U256::from_big_endian(&bytecode_to_code_hash(words).unwrap());
            world.hash_by_address.insert(U256::from(*address), hash);
            world.code_by_hash.insert(hash, code.clone());
        }
        world
    }
}

impl World<()> for AsmWorld {
    fn decommit(&mut self, hash: U256) -> Program<(), Self> {
        Program::new(&self.decommit_code(hash), false)
    }

    fn decommit_code(&mut self, hash: U256) -> Vec<u8> {
        self.code_by_hash[&hash].clone()
    }
}

impl StorageInterface for AsmWorld {
    fn read_storage(&mut self, contract: H160, key: U256) -> StorageSlot {
        let deployer = Address::from_low_u64_be(DEPLOYER_SYSTEM_CONTRACT_ADDRESS_LOW.into());
        if contract == deployer {
            StorageSlot {
                value: self.hash_by_address.get(&key).copied().unwrap_or_default(),
                is_write_initial: false,
            }
        } else {
            StorageSlot::EMPTY
        }
    }

    fn cost_of_writing_storage(&mut self, _: StorageSlot, _: U256) -> u32 {
        50
    }

    fn is_free_storage_slot(&self, _: &H160, _: &U256) -> bool {
        false
    }
}

#[test]
fn harness_scenario_on_assembled_bytecode() {
    let x = assemble(shared_asm!("65536.asm"));
    // The kernel's heap layout and X's read offset assume this layout.
    assert_eq!(x.len(), 5 * 32);
    assert_eq!(U256::from_big_endian(&x[96..128]), U256::from(32) << 96);
    let mut world = AsmWorld::new(&[
        (
            u64::from(DEPLOYER_SYSTEM_CONTRACT_ADDRESS_LOW),
            assemble(shared_asm!("32770.asm")),
        ),
        (1 << 16, x),
    ]);
    let mut vm = VirtualMachine::new(
        addr(0x8001),
        Program::new(&assemble(shared_asm!("entry.asm")), false),
        Address::zero(),
        &[],
        10_000_000,
        settings(),
    );
    assert_eq!(
        vm.run(&mut world, &mut ()),
        ExecutionEnd::ProgramFinished(vec![])
    );
}
