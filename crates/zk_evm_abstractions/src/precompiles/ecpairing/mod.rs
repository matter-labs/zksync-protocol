use anyhow::{Error, Result};
use cfg_if::cfg_if;
use zkevm_opcode_defs::bn254::bn256::{
    self, Fq, Fq12, Fq2, G1Affine, G2Affine, FROBENIUS_COEFF_FQ6_C1, XI_TO_Q_MINUS_1_OVER_2,
};
use zkevm_opcode_defs::bn254::ff::{Field, PrimeField};
use zkevm_opcode_defs::bn254::{CurveAffine, CurveProjective};
use zkevm_opcode_defs::ethereum_types::U256;

use super::*;
use crate::utils::bn254::validate_values_in_field;

#[cfg(feature = "airbender-precompile-delegations")]
mod airbender_backend;
#[cfg(any(not(feature = "airbender-precompile-delegations"), test))]
mod legacy_backend;
#[cfg(test)]
mod tests;

cfg_if! {
    if #[cfg(feature = "airbender-precompile-delegations")] {
        use self::airbender_backend::DelegatedECPairingBackend as ActiveECPairingBackend;
    } else {
        use self::legacy_backend::LegacyECPairingBackend as ActiveECPairingBackend;
    }
}

// NOTE: We need x1, y1, x2, y2, x3, y3.
pub const MEMORY_READS_PER_CYCLE: usize = 6;
// NOTE: We write the status marker plus the pairing result.
pub const MEMORY_WRITES_PER_CYCLE: usize = 2;

type EcPairingInputTuple = [U256; 6];

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ECPairingRoundWitness {
    pub new_request: Option<LogQuery>,
    pub reads: [MemoryQuery; MEMORY_READS_PER_CYCLE],
    pub writes: Option<[MemoryQuery; MEMORY_WRITES_PER_CYCLE]>,
}

trait ECPairingBackend {
    fn pairing(inputs: Vec<EcPairingInputTuple>) -> Result<bool>;
}

// ==============================================================================
// Legacy-Compatible Pairing Helpers
// ==============================================================================
//
// `zkevm_test_harness` reconstructs the precompile's internal pairing accumulator
// while building witnesses, so the legacy `pair` helper remains part of the module's
// public surface even after the backend split.

pub(super) fn check_if_in_subgroup(point: G2Affine) -> bool {
    let mut x_p = point.into_projective();

    let x = bn256::Fr::from_str("147946756881789318990833708069417712966").unwrap();
    x_p.mul_assign(x);
    let (mut pi_1_q_x, mut pi_1_q_y) = point.into_xy_unchecked();

    pi_1_q_x.conjugate();
    pi_1_q_x.mul_assign(&FROBENIUS_COEFF_FQ6_C1[1]);
    pi_1_q_y.conjugate();
    pi_1_q_y.mul_assign(&XI_TO_Q_MINUS_1_OVER_2);
    let frob_affine = G2Affine::from_xy_checked(pi_1_q_x, pi_1_q_y).unwrap();

    x_p == frob_affine.into_projective()
}

pub fn pair(input: &EcPairingInputTuple) -> Result<Fq12> {
    let (x1, y1, x2, y2, x3, y3) = (input[0], input[1], input[2], input[3], input[4], input[5]);

    if !validate_values_in_field(&[
        &x1.to_string(),
        &y1.to_string(),
        &x2.to_string(),
        &y2.to_string(),
        &x3.to_string(),
        &y3.to_string(),
    ]) {
        return Err(Error::msg("invalid values"));
    }

    let x1_field = Fq::from_str(x1.to_string().as_str()).ok_or(Error::msg("invalid x1"))?;
    let y1_field = Fq::from_str(y1.to_string().as_str()).ok_or(Error::msg("invalid y1"))?;
    let x2_field = Fq::from_str(x2.to_string().as_str()).ok_or(Error::msg("invalid x2"))?;
    let y2_field = Fq::from_str(y2.to_string().as_str()).ok_or(Error::msg("invalid y2"))?;
    let x3_field = Fq::from_str(x3.to_string().as_str()).ok_or(Error::msg("invalid x3"))?;
    let y3_field = Fq::from_str(y3.to_string().as_str()).ok_or(Error::msg("invalid y3"))?;

    let point_1 = G1Affine::from_xy_checked(x1_field, y1_field)?;

    // NOTE: In EIP-197, the tuple stores the imaginary component before the real one.
    let point_2_x = Fq2 {
        c0: y2_field,
        c1: x2_field,
    };
    let point_2_y = Fq2 {
        c0: y3_field,
        c1: x3_field,
    };
    let point_2 = G2Affine::from_xy_checked(point_2_x, point_2_y)?;

    if !check_if_in_subgroup(point_2) {
        anyhow::bail!("G2 not on the subgroup");
    }

    Ok(point_1.pairing_with(&point_2))
}

fn execute_ecpairing_precompile<M: Memory, Backend: ECPairingBackend, const B: bool>(
    monotonic_cycle_counter: u32,
    query: LogQuery,
    memory: &mut M,
) -> (
    usize,
    Option<(
        Vec<MemoryQuery>,
        Vec<MemoryQuery>,
        Vec<ECPairingRoundWitness>,
    )>,
) {
    let precompile_call_params = query;
    let params = precompile_abi_in_log(precompile_call_params);
    let num_rounds = params.precompile_interpreted_data as usize;
    let timestamp_to_read = precompile_call_params.timestamp;
    let timestamp_to_write = Timestamp(timestamp_to_read.0 + 1);

    let mut current_read_location = MemoryLocation {
        memory_type: MemoryType::Heap,
        page: MemoryPage(params.memory_page_to_read),
        index: MemoryIndex(params.input_memory_offset),
    };

    let mut read_history = if B {
        Vec::with_capacity(num_rounds * MEMORY_READS_PER_CYCLE)
    } else {
        vec![]
    };
    let mut write_history = if B {
        Vec::with_capacity(MEMORY_WRITES_PER_CYCLE)
    } else {
        vec![]
    };

    let mut inputs = Vec::with_capacity(num_rounds);
    let mut witnesses = if B {
        Vec::with_capacity(num_rounds)
    } else {
        vec![]
    };

    for round_idx in 0..num_rounds {
        let mut round_witness = ECPairingRoundWitness {
            new_request: (round_idx == 0).then_some(precompile_call_params),
            reads: [MemoryQuery::empty(); MEMORY_READS_PER_CYCLE],
            writes: None,
        };

        let mut input_tuple = [U256::zero(); MEMORY_READS_PER_CYCLE];
        for (idx, input_word) in input_tuple.iter_mut().enumerate() {
            let read_query = MemoryQuery {
                timestamp: timestamp_to_read,
                location: current_read_location,
                value: U256::zero(),
                value_is_pointer: false,
                rw_flag: false,
            };
            let read_query = memory.execute_partial_query(monotonic_cycle_counter, read_query);
            *input_word = read_query.value;

            if B {
                round_witness.reads[idx] = read_query;
                read_history.push(read_query);
            }

            current_read_location.index.0 += 1;
        }

        inputs.push(input_tuple);
        if B {
            witnesses.push(round_witness);
        }
    }

    let result = Backend::pairing(inputs);
    let output_values = match result {
        Ok(is_valid) => [U256::one(), U256::from(is_valid as u64)],
        Err(_) => [U256::zero(), U256::zero()],
    };

    let mut write_location = MemoryLocation {
        memory_type: MemoryType::Heap,
        page: MemoryPage(params.memory_page_to_write),
        index: MemoryIndex(params.output_memory_offset),
    };

    let mut write_queries = [MemoryQuery::empty(); MEMORY_WRITES_PER_CYCLE];
    for (idx, value) in output_values.into_iter().enumerate() {
        let write_query = MemoryQuery {
            timestamp: timestamp_to_write,
            location: write_location,
            value,
            value_is_pointer: false,
            rw_flag: true,
        };
        let write_query = memory.execute_partial_query(monotonic_cycle_counter, write_query);
        write_queries[idx] = write_query;

        if B {
            write_history.push(write_query);
        }

        write_location.index.0 += 1;
    }

    let witness = if B {
        if let Some(last_round) = witnesses.last_mut() {
            last_round.writes = Some(write_queries);
        } else {
            witnesses.push(ECPairingRoundWitness {
                new_request: None,
                reads: [MemoryQuery::empty(); MEMORY_READS_PER_CYCLE],
                writes: Some(write_queries),
            });
        }
        Some((read_history, write_history, witnesses))
    } else {
        None
    };

    (num_rounds, witness)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ECPairingPrecompile<const B: bool>;

impl<const B: bool> Precompile for ECPairingPrecompile<B> {
    type CycleWitness = ECPairingRoundWitness;

    fn execute_precompile<M: Memory>(
        &mut self,
        monotonic_cycle_counter: u32,
        query: LogQuery,
        memory: &mut M,
    ) -> (
        usize,
        Option<(Vec<MemoryQuery>, Vec<MemoryQuery>, Vec<Self::CycleWitness>)>,
    ) {
        execute_ecpairing_precompile::<M, ActiveECPairingBackend, B>(
            monotonic_cycle_counter,
            query,
            memory,
        )
    }
}

pub fn ecpairing_function<M: Memory, const B: bool>(
    monotonic_cycle_counter: u32,
    precompile_call_params: LogQuery,
    memory: &mut M,
) -> (
    usize,
    Option<(
        Vec<MemoryQuery>,
        Vec<MemoryQuery>,
        Vec<ECPairingRoundWitness>,
    )>,
) {
    execute_ecpairing_precompile::<M, ActiveECPairingBackend, B>(
        monotonic_cycle_counter,
        precompile_call_params,
        memory,
    )
}
