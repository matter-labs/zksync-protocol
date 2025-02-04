use crate::aux::*;
use crate::queries::*;
use crate::vm::*;

pub mod ecadd;
pub mod ecmul;
pub mod ecrecover;
pub mod keccak256;
pub mod modexp;
pub mod secp256r1_verify;
pub mod sha256;
pub mod ecmultipairing_naive;

use num_enum::TryFromPrimitive;
use zkevm_opcode_defs::ECMULTIPAIRING_NAIVE_PRECOMPILE_ADDRESS;
use std::convert::TryFrom;
use zkevm_opcode_defs::system_params::{
    ECRECOVER_INNER_FUNCTION_PRECOMPILE_ADDRESS, KECCAK256_ROUND_FUNCTION_PRECOMPILE_ADDRESS,
    SECP256R1_VERIFY_PRECOMPILE_ADDRESS, SHA256_ROUND_FUNCTION_PRECOMPILE_ADDRESS,
};

use zkevm_opcode_defs::{
    PrecompileCallABI, ECADD_PRECOMPILE_ADDRESS, ECMUL_PRECOMPILE_ADDRESS, MODEXP_PRECOMPILE_ADDRESS,
};

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TryFromPrimitive)]
pub enum PrecompileAddress {
    Ecrecover = ECRECOVER_INNER_FUNCTION_PRECOMPILE_ADDRESS,
    SHA256 = SHA256_ROUND_FUNCTION_PRECOMPILE_ADDRESS,
    Keccak256 = KECCAK256_ROUND_FUNCTION_PRECOMPILE_ADDRESS,
    Secp256r1Verify = SECP256R1_VERIFY_PRECOMPILE_ADDRESS,
    Modexp = MODEXP_PRECOMPILE_ADDRESS,
    ECAdd = ECADD_PRECOMPILE_ADDRESS,
    ECMul = ECMUL_PRECOMPILE_ADDRESS,
    ECMultiPairingNaive = ECMULTIPAIRING_NAIVE_PRECOMPILE_ADDRESS,
}

pub const fn precompile_abi_in_log(query: LogQuery) -> PrecompileCallABI {
    PrecompileCallABI::from_u256(query.key)
}

#[derive(Clone, Copy, Debug)]
pub struct DefaultPrecompilesProcessor<const B: bool>;

impl<const B: bool> PrecompilesProcessor for DefaultPrecompilesProcessor<B> {
    fn start_frame(&mut self) {
        // there are no precompiles to rollback, do nothing
    }
    fn execute_precompile<M: Memory>(
        &mut self,
        monotonic_cycle_counter: u32,
        query: LogQuery,
        memory: &mut M,
    ) -> Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, PrecompileCyclesWitness)> {
        let address_low = u16::from_le_bytes([query.address.0[19], query.address.0[18]]);
        let Ok(precompile_address) = PrecompileAddress::try_from(address_low) else {
            // it's formally allowed for purposes of ergs-burning
            // by special contracts
            return None;
        };

        match precompile_address {
            PrecompileAddress::Keccak256 => {
                // pure function call, non-revertable
                if B {
                    let (reads, writes, round_witness) =
                        keccak256::keccak256_rounds_function::<M, B>(
                            monotonic_cycle_counter,
                            query,
                            memory,
                        )
                        .1
                        .expect("must generate intermediate witness");

                    Some((
                        reads,
                        writes,
                        PrecompileCyclesWitness::Keccak256(round_witness),
                    ))
                } else {
                    let _ = keccak256::keccak256_rounds_function::<M, B>(
                        monotonic_cycle_counter,
                        query,
                        memory,
                    );

                    None
                }
            }
            PrecompileAddress::SHA256 => {
                // pure function call, non-revertable
                if B {
                    let (reads, writes, round_witness) = sha256::sha256_rounds_function::<M, B>(
                        monotonic_cycle_counter,
                        query,
                        memory,
                    )
                    .1
                    .expect("must generate intermediate witness");

                    Some((
                        reads,
                        writes,
                        PrecompileCyclesWitness::Sha256(round_witness),
                    ))
                } else {
                    let _ = sha256::sha256_rounds_function::<M, B>(
                        monotonic_cycle_counter,
                        query,
                        memory,
                    );

                    None
                }
            }
            PrecompileAddress::Ecrecover => {
                // pure function call, non-revertable
                if B {
                    let (reads, writes, round_witness) = ecrecover::ecrecover_function::<M, B>(
                        monotonic_cycle_counter,
                        query,
                        memory,
                    )
                    .1
                    .expect("must generate intermediate witness");

                    Some((
                        reads,
                        writes,
                        PrecompileCyclesWitness::ECRecover(round_witness),
                    ))
                } else {
                    let _ = ecrecover::ecrecover_function::<M, B>(
                        monotonic_cycle_counter,
                        query,
                        memory,
                    );

                    None
                }
            }
            PrecompileAddress::Secp256r1Verify => {
                if B {
                    let (reads, writes, round_witness) =
                        secp256r1_verify::secp256r1_verify_function::<M, B>(
                            monotonic_cycle_counter,
                            query,
                            memory,
                        )
                        .1
                        .expect("must generate intermediate witness");

                    Some((
                        reads,
                        writes,
                        PrecompileCyclesWitness::Secp256r1Verify(round_witness),
                    ))
                } else {
                    let _ = secp256r1_verify::secp256r1_verify_function::<M, B>(
                        monotonic_cycle_counter,
                        query,
                        memory,
                    );

                    None
                }
            }
            PrecompileAddress::Modexp => {
                // pure function call, non-revertable
                if B {
                    let (reads, writes, round_witness) =
                        modexp::modexp_function::<M, B>(monotonic_cycle_counter, query, memory)
                            .1
                            .expect("must generate intermediate witness");

                    Some((
                        reads,
                        writes,
                        PrecompileCyclesWitness::Modexp(round_witness),
                    ))
                } else {
                    let _ = modexp::modexp_function::<M, B>(monotonic_cycle_counter, query, memory);

                    None
                }
            }
            PrecompileAddress::ECAdd => {
                // pure function call, non-revertable
                if B {
                    let (reads, writes, round_witness) =
                        ecadd::ecadd_function::<M, B>(monotonic_cycle_counter, query, memory)
                            .1
                            .expect("must generate intermediate witness");

                    Some((reads, writes, PrecompileCyclesWitness::ECAdd(round_witness)))
                } else {
                    let _ = ecadd::ecadd_function::<M, B>(monotonic_cycle_counter, query, memory);

                    None
                }
            }
            PrecompileAddress::ECMul => {
                // pure function call, non-revertable
                if B {
                    let (reads, writes, round_witness) =
                        ecmul::ecmul_function::<M, B>(monotonic_cycle_counter, query, memory)
                            .1
                            .expect("must generate intermediate witness");

                    Some((reads, writes, PrecompileCyclesWitness::ECMul(round_witness)))
                } else {
                    let _ = ecmul::ecmul_function::<M, B>(monotonic_cycle_counter, query, memory);

                    None
                }
            }
            PrecompileAddress::ECMultiPairingNaive => {
                // pure function call, non-revertable
                if B {
                    let (reads, writes, round_witness) = ecmultipairing_naive::ecmultipairing_naive_function::<M, B>(
                        monotonic_cycle_counter,
                        query,
                        memory,
                    )
                    .1
                    .expect("must generate intermediate witness");

                    Some((
                        reads,
                        writes,
                        PrecompileCyclesWitness::ECMultiPairingNaive(round_witness),
                    ))
                } else {
                    let _ = ecmultipairing_naive::ecmultipairing_naive_function::<M, B>(
                        monotonic_cycle_counter,
                        query,
                        memory,
                    );

                    None
                }
            }
        }
    }

    fn finish_frame(&mut self, _panicked: bool) {
        // there are no revertable precompile yes, so we are ok
    }
}
