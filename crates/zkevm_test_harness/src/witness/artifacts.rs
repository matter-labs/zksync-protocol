use crate::boojum::field::SmallField;
use crate::boojum::gadgets::queue::QueueStateWitness;
use crate::witness::aux_data_structs::one_per_circuit_accumulator::CircuitsEntryAccumulatorSparse;
use crate::witness::aux_data_structs::per_circuit_accumulator::PerCircuitAccumulatorSparse;
use crate::zk_evm::aux_structures::{DecommittmentQuery, LogQuery, MemoryQuery};
use crate::zkevm_circuits::base_structures::vm_state::FULL_SPONGE_QUEUE_STATE_WIDTH;
use crate::zkevm_circuits::code_unpacker_sha256::input::CodeDecommitterCircuitInstanceWitness;
use crate::zkevm_circuits::ecrecover::EcrecoverCircuitInstanceWitness;
use crate::zkevm_circuits::keccak256_round_function::input::Keccak256RoundFunctionCircuitInstanceWitness;
use crate::zkevm_circuits::linear_hasher::input::LinearHasherCircuitInstanceWitness;
use crate::zkevm_circuits::log_sorter::input::EventsDeduplicatorInstanceWitness;
use crate::zkevm_circuits::sha256_round_function::input::Sha256RoundFunctionCircuitInstanceWitness;
use crate::zkevm_circuits::sort_decommittment_requests::input::CodeDecommittmentsDeduplicatorInstanceWitness;
use crate::zkevm_circuits::storage_validity_by_grand_product::input::StorageDeduplicatorInstanceWitness;
use circuit_definitions::encodings::decommittment_request::DecommittmentQueueState;
use circuit_definitions::encodings::*;
use circuit_definitions::zk_evm::zkevm_opcode_defs::{
    ECADD_PRECOMPILE_FORMAL_ADDRESS, ECMUL_PRECOMPILE_FORMAL_ADDRESS,
    ECPAIRING_PRECOMPILE_FORMAL_ADDRESS, MODEXP_PRECOMPILE_FORMAL_ADDRESS,
};
use circuit_definitions::zkevm_circuits::bn254::ec_add::input::EcAddCircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::bn254::ec_mul::input::EcMulCircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::bn254::ec_pairing::input::EcPairingCircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::modexp::input::ModexpCircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::secp256r1_verify::Secp256r1VerifyCircuitInstanceWitness;
use circuit_definitions::zkevm_circuits::transient_storage_validity_by_grand_product::input::TransientStorageDeduplicatorInstanceWitness;
use circuit_sequencer_api::toolset::GeometryConfig;
use derivative::Derivative;
use zkevm_circuits::fsm_input_output::ClosedFormInputCompactFormWitness;

use crate::zk_evm::zkevm_opcode_defs::system_params::{
    EVENT_AUX_BYTE, L1_MESSAGE_AUX_BYTE, PRECOMPILE_AUX_BYTE, STORAGE_AUX_BYTE,
    TRANSIENT_STORAGE_AUX_BYTE,
};

use crate::zk_evm::zkevm_opcode_defs::system_params::{
    ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
    KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
    SECP256R1_VERIFY_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
    SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS,
};

#[derive(Derivative)]
#[derivative(Default)]
pub struct DemuxedLogQueries {
    pub io: DemuxedIOLogQueries,
    pub precompiles: DemuxedPrecompilesLogQueries,
}

#[derive(Derivative)]
#[derivative(Default)]
pub struct DemuxedIOLogQueries {
    pub rollup_storage: Vec<LogQuery>,
    pub porter_storage: Vec<LogQuery>,
    pub transient_storage: Vec<LogQuery>,
    pub event: Vec<LogQuery>,
    pub to_l1: Vec<LogQuery>,
}

#[derive(Derivative)]
#[derivative(Default)]
pub struct DemuxedPrecompilesLogQueries {
    pub keccak: Vec<LogQuery>,
    pub sha256: Vec<LogQuery>,
    pub ecrecover: Vec<LogQuery>,
    pub secp256r1_verify: Vec<LogQuery>,
    pub modexp: Vec<LogQuery>,
    pub ecadd: Vec<LogQuery>,
    pub ecmul: Vec<LogQuery>,
    pub ecpairing: Vec<LogQuery>,
}

impl DemuxedLogQueries {
    pub fn sort_and_push(&mut self, query: LogQuery) {
        match query.aux_byte {
            STORAGE_AUX_BYTE => {
                // sort rollup and porter
                match query.shard_id {
                    0 => {
                        self.io.rollup_storage.push(query);
                    }
                    1 => {
                        self.io.porter_storage.push(query);
                    }
                    _ => unreachable!(),
                }
            }
            TRANSIENT_STORAGE_AUX_BYTE => {
                self.io.transient_storage.push(query);
            }
            L1_MESSAGE_AUX_BYTE => {
                self.io.to_l1.push(query);
            }
            EVENT_AUX_BYTE => {
                self.io.event.push(query);
            }
            PRECOMPILE_AUX_BYTE => {
                let precompiles = &mut self.precompiles;
                assert!(!query.rollback);
                match query.address {
                    a if a == *KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                        precompiles.keccak.push(query);
                    }
                    a if a == *SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                        precompiles.sha256.push(query);
                    }
                    a if a == *ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                        precompiles.ecrecover.push(query);
                    }
                    a if a == *SECP256R1_VERIFY_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS => {
                        precompiles.secp256r1_verify.push(query);
                    }
                    a if a == *MODEXP_PRECOMPILE_FORMAL_ADDRESS => {
                        precompiles.modexp.push(query);
                    }
                    a if a == *ECADD_PRECOMPILE_FORMAL_ADDRESS => {
                        precompiles.ecadd.push(query);
                    }
                    a if a == *ECMUL_PRECOMPILE_FORMAL_ADDRESS => {
                        precompiles.ecmul.push(query);
                    }
                    a if a == *ECPAIRING_PRECOMPILE_FORMAL_ADDRESS => {
                        precompiles.ecpairing.push(query);
                    }
                    _ => {
                        // just burn ergs
                    }
                }
            }
            _ => unreachable!(),
        }
    }
}

pub struct DecommitmentArtifactsForMainVM<F: SmallField> {
    pub prepared_decommittment_queries: PerCircuitAccumulatorSparse<(u32, DecommittmentQuery)>,
    pub decommittment_queue_entry_states:
        CircuitsEntryAccumulatorSparse<(u32, QueueStateWitness<F, FULL_SPONGE_QUEUE_STATE_WIDTH>)>,
}

pub struct MemoryArtifacts<F: SmallField> {
    pub memory_queue_entry_states:
        CircuitsEntryAccumulatorSparse<(u32, QueueStateWitness<F, FULL_SPONGE_QUEUE_STATE_WIDTH>)>,
}

#[derive(Derivative)]
#[derivative(Default)]
pub(crate) struct LogCircuitsArtifacts<F: SmallField> {
    pub storage_application_artifacts: (
        FirstAndLastCircuitWitness<StorageApplicationObservableWitness<F>>,
        Vec<ClosedFormInputCompactFormWitness<F>>,
    ),
    pub storage_deduplicator_artifacts: (
        FirstAndLastCircuitWitness<StorageDeduplicatorObservableWitness<F>>,
        Vec<ClosedFormInputCompactFormWitness<F>>,
    ),
    pub events_deduplicator_artifacts: (
        FirstAndLastCircuitWitness<EventsDeduplicatorObservableWitness<F>>,
        Vec<ClosedFormInputCompactFormWitness<F>>,
    ),
    pub l1_messages_deduplicator_artifacts: (
        FirstAndLastCircuitWitness<EventsDeduplicatorObservableWitness<F>>,
        Vec<ClosedFormInputCompactFormWitness<F>>,
    ),
    pub transient_storage_sorter_artifacts: (
        FirstAndLastCircuitWitness<TransientStorageDeduplicatorObservableWitness<F>>,
        Vec<ClosedFormInputCompactFormWitness<F>>,
    ),
    pub l1_messages_linear_hash_artifacts: (
        FirstAndLastCircuitWitness<LinearHasherObservableWitness<F>>,
        Vec<ClosedFormInputCompactFormWitness<F>>,
    ),
}

#[derive(Derivative)]
#[derivative(Default)]
pub(crate) struct MemoryCircuitsArtifacts<F: SmallField> {
    pub ram_permutation_artifacts: (
        FirstAndLastCircuitWitness<RamPermutationObservableWitness<F>>,
        Vec<ClosedFormInputCompactFormWitness<F>>,
    ),
    pub code_decommitter_artifacts: (
        FirstAndLastCircuitWitness<CodeDecommitterObservableWitness<F>>,
        Vec<ClosedFormInputCompactFormWitness<F>>,
    ),
    pub keccak256_circuits_data: (
        FirstAndLastCircuitWitness<Keccak256RoundFunctionObservableWitness<F>>,
        Vec<ClosedFormInputCompactFormWitness<F>>,
    ),
    pub sha256_circuits_data: (
        FirstAndLastCircuitWitness<Sha256RoundFunctionObservableWitness<F>>,
        Vec<ClosedFormInputCompactFormWitness<F>>,
    ),
    pub ecrecover_circuits_data: (
        FirstAndLastCircuitWitness<EcrecoverObservableWitness<F>>,
        Vec<ClosedFormInputCompactFormWitness<F>>,
    ),
    pub secp256r1_verify_circuits_data: (
        FirstAndLastCircuitWitness<Secp256r1VerifyObservableWitness<F>>,
        Vec<ClosedFormInputCompactFormWitness<F>>,
    ),
    pub modexp_circuits_data: (
        FirstAndLastCircuitWitness<ModexpObservableWitness<F>>,
        Vec<ClosedFormInputCompactFormWitness<F>>,
    ),
    pub ecadd_circuits_data: (
        FirstAndLastCircuitWitness<ECAddObservableWitness<F>>,
        Vec<ClosedFormInputCompactFormWitness<F>>,
    ),
    pub ecmul_circuits_data: (
        FirstAndLastCircuitWitness<ECMulObservableWitness<F>>,
        Vec<ClosedFormInputCompactFormWitness<F>>,
    ),
    pub ecpairing_circuits_data: (
        FirstAndLastCircuitWitness<ECPairingObservableWitness<F>>,
        Vec<ClosedFormInputCompactFormWitness<F>>,
    ),
}

use crate::witness::aux_data_structs::one_per_circuit_accumulator::LastPerCircuitAccumulator;

use super::postprocessing::observable_witness::{
    CodeDecommitterObservableWitness, ECAddObservableWitness, ECMulObservableWitness,
    ECPairingObservableWitness, EcrecoverObservableWitness, EventsDeduplicatorObservableWitness,
    Keccak256RoundFunctionObservableWitness, LinearHasherObservableWitness,
    ModexpObservableWitness, RamPermutationObservableWitness, Secp256r1VerifyObservableWitness,
    Sha256RoundFunctionObservableWitness, StorageApplicationObservableWitness,
    StorageDeduplicatorObservableWitness, TransientStorageDeduplicatorObservableWitness,
};
use super::postprocessing::FirstAndLastCircuitWitness;

#[derive(Derivative)]
#[derivative(Default)]
pub struct LogQueueStates<F: SmallField> {
    pub states_accumulator: LastPerCircuitAccumulator<LogQueueState<F>>,
    pub simulator: LogQueueSimulator<F>,
}

impl<F: SmallField> LogQueueStates<F> {
    pub fn new(cycles_per_circuit: usize) -> Self {
        Self {
            states_accumulator: LastPerCircuitAccumulator::new(cycles_per_circuit),
            simulator: LogQueueSimulator::<F>::empty(),
        }
    }

    pub fn with_flat_capacity(cycles_per_circuit: usize, flat_capacity: usize) -> Self {
        Self {
            states_accumulator: LastPerCircuitAccumulator::with_flat_capacity(
                cycles_per_circuit,
                flat_capacity,
            ),
            simulator: LogQueueSimulator::<F>::with_capacity(flat_capacity),
        }
    }
}
