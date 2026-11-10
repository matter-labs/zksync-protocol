use primitive_types::{H160, U256};
use zkevm_opcode_defs::{
    ethereum_types::Address, system_params::DEPLOYER_SYSTEM_CONTRACT_ADDRESS_LOW,
};
use zksync_vm2_interface::{CycleStats, HeapId, Tracer};

use crate::{
    program::Program,
    world_diff::{DecommitPageOrigin, DecommitState, WorldDiff},
    VirtualMachine, World,
};

/// Upper bound on the bytes of a decommit page a program can observe: `CodePage` operands index
/// `1 << 16` words and the `pc` covers the first quarter of that.
const OBSERVABLE_PAGE_BYTES: usize = 32 << 16;

/// Ensures that a decommit hash has a materialized reusable page and returns it.
///
/// The resulting page is pinned globally in [`WorldDiff`]. If that page is not owned by the
/// current frame, it is also recorded as kept alive in the bootloader frame (or current frame if
/// no bootloader frame exists), matching decommit opcode teardown semantics.
pub(crate) fn materialize_decommit_page<T: Tracer, W: World<T>>(
    vm: &mut VirtualMachine<T, W>,
    code_hash: U256,
    code: &[u8],
    candidate_page: HeapId,
    origin: DecommitPageOrigin,
) -> HeapId {
    if let Some(existing) = vm.world_diff.decommit_page(code_hash) {
        return existing;
    }

    vm.state.heaps.write_bytes(candidate_page, 0, code);
    let heap = candidate_page;
    vm.world_diff.set_decommit_page(code_hash, heap, origin);

    if heap != vm.state.current_frame.heap && heap != vm.state.current_frame.aux_heap {
        let heaps_to_keep_alive =
            if let Some(bootloader_frame) = vm.state.previous_frames.first_mut() {
                &mut bootloader_frame.heaps_i_am_keeping_alive
            } else {
                &mut vm.state.current_frame.heaps_i_am_keeping_alive
            };
        heaps_to_keep_alive.push(heap);
    }

    heap
}

/// Returns the program a repeat far call must run from the decommit `page` it resolved to: the
/// decoded bytecode for a clean code page, otherwise the page itself (see [`DecommitPageOrigin`]).
///
/// Page programs are cached in `State::page_programs` once the owner frame is gone: only the
/// owner writes the page, and it is suspended while any callee runs. The exception is a kernel
/// `precompile` call directing its output at a foreign page id, which no system contract does.
pub(crate) fn program_for_repeat_decommit<T: Tracer, W: World<T>>(
    vm: &mut VirtualMachine<T, W>,
    (page, origin): (HeapId, DecommitPageOrigin),
    hash_program: Program<T, W>,
) -> Program<T, W> {
    if origin == DecommitPageOrigin::CodePage {
        return hash_program;
    }
    if let Some(program) = vm.state.page_programs.as_ref().get(&page.as_u32()) {
        return program.clone();
    }

    let code_len = (hash_program.code_page().len() * 32).min(OBSERVABLE_PAGE_BYTES);
    let heap = &vm.state.heaps[page];
    let len = heap
        .high_water_mark()
        .clamp(code_len, OBSERVABLE_PAGE_BYTES);
    let bytes = heap.read_range_big_endian(0..u32::try_from(len).expect("page length overflow"));
    let (cells, _) = bytes.as_chunks::<32>();
    let words: Vec<U256> = cells
        .iter()
        .map(|cell| U256::from_big_endian(cell))
        .collect();
    let program = Program::from_decommit_page(&words, &hash_program);

    let owner_alive = vm.state.current_frame.heap == page
        || vm.state.previous_frames.iter().any(|f| f.heap == page);
    if !owner_alive {
        vm.state
            .page_programs
            .insert(page.as_u32(), program.clone());
    }
    program
}

impl WorldDiff {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn decommit<T: Tracer>(
        &mut self,
        world: &mut impl World<T>,
        tracer: &mut T,
        address: U256,
        default_aa_code_hash: [u8; 32],
        evm_interpreter_code_hash: [u8; 32],
        is_constructor_call: bool,
        tx_number_in_block: u16,
    ) -> Option<(UnpaidDecommit, bool, bool)> {
        let deployer_system_contract_address =
            Address::from_low_u64_be(DEPLOYER_SYSTEM_CONTRACT_ADDRESS_LOW.into());

        let mut is_evm = false;
        // zk_evm grants the larger EVM frame stipend based on the version byte alone.
        // Keep this separate from `is_evm`: calls masked to default AA should not execute
        // via the EVM interpreter, but their frame bounds still expose the original blob
        // format classification.
        let mut is_evm_blob_format = false;

        let mut code_info = {
            let code_info = self.read_storage_without_refund(
                world,
                tracer,
                deployer_system_contract_address,
                address,
                tx_number_in_block,
            );
            let mut code_info_bytes = [0; 32];
            code_info.to_big_endian(&mut code_info_bytes);

            // Note that EOAs are considered constructed because their code info is all zeroes.
            let is_constructed = match code_info_bytes[1] {
                0 => true,
                1 => false,
                _ => {
                    return None;
                }
            };

            let try_default_aa = if is_kernel(u256_into_address(address)) {
                None
            } else {
                Some(default_aa_code_hash)
            };

            // The address aliasing contract implements Ethereum-like behavior of calls to EOAs
            // returning successfully (and address aliasing when called from the bootloader).
            // It makes sense that unconstructed code is treated as an EOA but for some reason
            // a constructor call to constructed code is also treated as EOA.
            match code_info_bytes[0] {
                1 => {
                    if is_constructed == is_constructor_call {
                        try_default_aa?
                    } else {
                        code_info_bytes
                    }
                }
                2 => {
                    is_evm_blob_format = true;
                    if is_constructed == is_constructor_call {
                        try_default_aa?
                    } else {
                        is_evm = true;
                        evm_interpreter_code_hash
                    }
                }
                _ if code_info == U256::zero() => try_default_aa?,
                _ => return None,
            }
        };

        code_info[1] = 0;
        let code_key: U256 = U256::from_big_endian(&code_info);

        let existing_page = self.decommit_page_with_origin(code_key);
        let cost = if existing_page.is_some() {
            0
        } else {
            let code_length_in_words = u16::from_be_bytes([code_info[2], code_info[3]]);
            u32::from(code_length_in_words) * zkevm_opcode_defs::ERGS_PER_CODE_WORD_DECOMMITTMENT
        };

        Some((
            UnpaidDecommit {
                cost,
                code_key,
                existing_page,
            },
            is_evm,
            is_evm_blob_format,
        ))
    }

    /// Fetches the contract code for a `decommit` opcode if this is a fresh decommit (i.e., the
    /// code wasn't decommitted previously in the same VM run), and otherwise reports the page
    /// that already holds it.
    ///
    /// A repeated decommit deliberately does *not* fetch the code: the only consumer of the
    /// returned bytes is [`materialize_decommit_page()`], which returns early for a hash that
    /// already has a page without reading them. Both functions branch on the same
    /// [`Self::decommit_page()`] predicate, so the outcome here decides which of them applies.
    #[doc(hidden)] // should be used for testing purposes only; can break VM operation otherwise
    pub fn decommit_opcode<T: Tracer>(
        &mut self,
        world: &mut impl World<T>,
        tracer: &mut T,
        code_hash: U256,
    ) -> DecommitOpcodeOutcome {
        if let Some(page) = self.decommit_page(code_hash) {
            self.record_repeated_decommit(code_hash, page);
            return DecommitOpcodeOutcome::Cached(page);
        }

        let code = world.decommit_code(code_hash);
        let code_len = u32::try_from(code.len()).expect("bytecode length overflow");
        // Decommitter can process two words per cycle, hence division by 2 * 32 = 64.
        tracer.on_extra_prover_cycles(CycleStats::Decommit(code_len.div_ceil(64)));
        DecommitOpcodeOutcome::Fresh(code)
    }

    pub(crate) fn pay_for_decommit<T: Tracer, W: World<T>>(
        &mut self,
        world: &mut W,
        tracer: &mut T,
        decommit: UnpaidDecommit,
        gas: &mut u32,
    ) -> Option<Program<T, W>> {
        if decommit.cost > *gas {
            // We intentionally keep this hash visible even though decommit did not execute.
            // Legacy VM includes far-call OOG attempts in "used contracts", and shadow mode
            // compares that output.
            if !matches!(
                self.decommitted_hashes.as_ref().get(&decommit.code_key),
                Some(DecommitState::Succeeded(_))
            ) {
                self.decommitted_hashes
                    .insert(decommit.code_key, DecommitState::Unsuccessful);
            }
            // Unlike all other gas costs, this one is not paid if low on gas.
            return None;
        }

        if let Some((page, _)) = decommit.existing_page {
            self.record_repeated_decommit(decommit.code_key, page);
        }
        let is_new = decommit.existing_page.is_none();
        *gas -= decommit.cost;

        let decommit = world.decommit(decommit.code_key);
        if is_new {
            let code_len_in_words =
                u32::try_from(decommit.code_page().len()).expect("bytecode length overflow");
            // Decommitter can process two words per cycle.
            tracer.on_extra_prover_cycles(CycleStats::Decommit(code_len_in_words.div_ceil(2)));
        }

        Some(decommit)
    }
}

/// Outcome of [`WorldDiff::decommit_opcode()`].
#[derive(Debug)]
#[doc(hidden)] // should be used for testing purposes only; can break VM operation otherwise
pub enum DecommitOpcodeOutcome {
    /// The bytecode hash wasn't decommitted previously in this VM run. Carries the fetched
    /// bytecode, which the caller is expected to materialize into a heap page using
    /// [`materialize_decommit_page()`].
    Fresh(Vec<u8>),
    /// The bytecode hash was already decommitted in this VM run and already has a materialized
    /// heap page, which is provided here. The decommit cost must be refunded by the caller.
    Cached(HeapId),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct UnpaidDecommit {
    cost: u32,
    code_key: U256,
    /// The page an earlier decommit of the same preimage left, looked up once here: a `U256`-keyed
    /// map lookup is a visible cost per far call on the guest. `None` means a fresh decommit that
    /// must be materialized after payment.
    existing_page: Option<(HeapId, DecommitPageOrigin)>,
}

impl UnpaidDecommit {
    pub(crate) const fn code_key(self) -> U256 {
        self.code_key
    }

    pub(crate) const fn existing_page(self) -> Option<(HeapId, DecommitPageOrigin)> {
        self.existing_page
    }
}

pub(crate) fn u256_into_address(source: U256) -> H160 {
    let mut result = H160::zero();
    let mut bytes = [0; 32];
    source.to_big_endian(&mut bytes);
    result.assign_from_slice(&bytes[12..]);
    result
}

pub(crate) fn is_kernel(address: H160) -> bool {
    address.0[..18].iter().all(|&byte| byte == 0)
}
