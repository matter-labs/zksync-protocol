use std::collections::VecDeque;

use super::*;

use crate::base_structures::precompile_input_outputs::*;
use crate::base_structures::vm_state::*;
use boojum::cs::Variable;
use boojum::gadgets::queue::*;
use boojum::gadgets::traits::allocatable::CSAllocatable;
use boojum::gadgets::traits::allocatable::CSPlaceholder;
use boojum::gadgets::traits::encodable::CircuitVarLengthEncodable;
use boojum::gadgets::traits::encodable::WitnessVarLengthEncodable;

use boojum::cs::traits::cs::ConstraintSystem;
use boojum::field::SmallField;
use boojum::gadgets::boolean::Boolean;
use boojum::gadgets::traits::auxiliary::PrettyComparison;
use boojum::gadgets::traits::selectable::Selectable;
use boojum::gadgets::traits::witnessable::WitnessHookable;
use serde::{Deserialize, Serialize};

#[derive(
    Derivative,
    CSAllocatable,
    CSSelectable,
    WitnessHookable,
)]
#[derivative(Clone, Debug)]
#[DerivePrettyComparison("true")]
pub struct EcPairingFunctionFSM<F: SmallField> {
    pub read_precompile_call: Boolean<F>,
    pub read_words_for_round: Boolean<F>,
    pub completed: Boolean<F>,
    // Accumulated result of all the previous pairings:
    pub pairing_inner_state: BN256Fq12NNField<F>,

    pub timestamp_to_use_for_read: UInt32<F>,
    pub timestamp_to_use_for_write: UInt32<F>,
    pub precompile_call_params: EcPairingPrecompileCallParams<F>,
}

impl<F: SmallField> CircuitVarLengthEncodable<F> for EcPairingFunctionFSM<F> {
    #[inline(always)]
    fn encoding_length(&self) -> usize {
        let mut total_len = 0;
        total_len += CircuitVarLengthEncodable::<F>::encoding_length(&self.read_precompile_call);
        total_len += CircuitVarLengthEncodable::<F>::encoding_length(&self.read_words_for_round);
        total_len += CircuitVarLengthEncodable::<F>::encoding_length(&self.completed);
        // total_len += CircuitVarLengthEncodable::<F>::encoding_length(&self.pairing_inner_state);
        total_len +=
            CircuitVarLengthEncodable::<F>::encoding_length(&self.timestamp_to_use_for_read);
        total_len +=
            CircuitVarLengthEncodable::<F>::encoding_length(&self.timestamp_to_use_for_write);
        total_len += CircuitVarLengthEncodable::<F>::encoding_length(&self.precompile_call_params);
        total_len
    }
    fn encode_to_buffer<CS: ConstraintSystem<F>>(&self, cs: &mut CS, dst: &mut Vec<Variable>) {
        CircuitVarLengthEncodable::<F>::encode_to_buffer(&self.read_precompile_call, cs, dst);
        CircuitVarLengthEncodable::<F>::encode_to_buffer(&self.read_words_for_round, cs, dst);
        CircuitVarLengthEncodable::<F>::encode_to_buffer(&self.completed, cs, dst);
        // CircuitVarLengthEncodable::<F>::encode_to_buffer(&self.pairing_inner_state, cs, dst);
        CircuitVarLengthEncodable::<F>::encode_to_buffer(&self.timestamp_to_use_for_read, cs, dst);
        CircuitVarLengthEncodable::<F>::encode_to_buffer(&self.timestamp_to_use_for_write, cs, dst);
        CircuitVarLengthEncodable::<F>::encode_to_buffer(&self.precompile_call_params, cs, dst);
    }
}

impl<F: SmallField> WitnessVarLengthEncodable<F> for EcPairingFunctionFSM<F> {
    fn witness_encoding_length(witness: &Self::Witness) -> usize {
        let mut total_len = 0;
        total_len += <Boolean<F> as WitnessVarLengthEncodable<F>>::witness_encoding_length(
            &witness.read_precompile_call,
        );
        total_len += <Boolean<F> as WitnessVarLengthEncodable<F>>::witness_encoding_length(
            &witness.read_words_for_round,
        );
        total_len += <Boolean<F> as WitnessVarLengthEncodable<F>>::witness_encoding_length(
            &witness.completed,
        );
        // total_len += <BN256Fq12NNField<F> as WitnessVarLengthEncodable<F>>::witness_encoding_length(&witness. pairing_inner_state);
        total_len += <UInt32<F> as WitnessVarLengthEncodable<F>>::witness_encoding_length(
            &witness.timestamp_to_use_for_read,
        );
        total_len += <UInt32<F> as WitnessVarLengthEncodable<F>>::witness_encoding_length(
            &witness.timestamp_to_use_for_write,
        );
        total_len += <EcPairingPrecompileCallParams<F> as WitnessVarLengthEncodable<F>>::witness_encoding_length(&witness. precompile_call_params);
        total_len
    }
    fn encode_witness_to_buffer(witness: &Self::Witness, dst: &mut Vec<F>) {
        <Boolean<F> as WitnessVarLengthEncodable<F>>::encode_witness_to_buffer(
            &witness.read_precompile_call,
            dst,
        );
        <Boolean<F> as WitnessVarLengthEncodable<F>>::encode_witness_to_buffer(
            &witness.read_words_for_round,
            dst,
        );
        <Boolean<F> as WitnessVarLengthEncodable<F>>::encode_witness_to_buffer(
            &witness.completed,
            dst,
        );
        // <BN256Fq12NNField<F> as WitnessVarLengthEncodable<F>>::encode_witness_to_buffer(&witness. pairing_inner_state, dst);
        <UInt32<F> as WitnessVarLengthEncodable<F>>::encode_witness_to_buffer(
            &witness.timestamp_to_use_for_read,
            dst,
        );
        <UInt32<F> as WitnessVarLengthEncodable<F>>::encode_witness_to_buffer(
            &witness.timestamp_to_use_for_write,
            dst,
        );
        <EcPairingPrecompileCallParams<F> as WitnessVarLengthEncodable<F>>::encode_witness_to_buffer(&witness. precompile_call_params, dst);
    }
}

impl<F: SmallField> CSPlaceholder<F> for EcPairingFunctionFSM<F> {
    fn placeholder<CS: ConstraintSystem<F>>(cs: &mut CS) -> Self {
        let boolean_false = Boolean::allocated_constant(cs, false);
        let zero_u32 = UInt32::zero(cs);
        let params = &Arc::new(bn254_base_field_params());

        Self {
            read_precompile_call: boolean_false,
            read_words_for_round: boolean_false,
            completed: boolean_false,
            pairing_inner_state: BN256Fq12NNField::one(cs, params),
            timestamp_to_use_for_read: zero_u32,
            timestamp_to_use_for_write: zero_u32,
            precompile_call_params: EcPairingPrecompileCallParams::<F>::placeholder(cs),
        }
    }
}

#[derive(
    Derivative,
    CSAllocatable,
    CSSelectable,
    CSVarLengthEncodable,
    WitnessHookable,
    WitVarLengthEncodable,
)]
#[derivative(Clone, Debug)]
#[DerivePrettyComparison("true")]
pub struct EcPairingCircuitFSMInputOutput<F: SmallField> {
    pub internal_fsm: EcPairingFunctionFSM<F>,
    pub log_queue_state: QueueState<F, QUEUE_STATE_WIDTH>,
    pub memory_queue_state: QueueState<F, FULL_SPONGE_QUEUE_STATE_WIDTH>,
}

impl<F> CSPlaceholder<F> for EcPairingCircuitFSMInputOutput<F>
where
    F: SmallField,
{
    fn placeholder<CS>(cs: &mut CS) -> Self
    where
        CS: ConstraintSystem<F>,
    {
        Self {
            internal_fsm: EcPairingFunctionFSM::placeholder(cs),
            log_queue_state: QueueState::<F, QUEUE_STATE_WIDTH>::placeholder(cs),
            memory_queue_state: QueueState::<F, FULL_SPONGE_QUEUE_STATE_WIDTH>::placeholder(cs),
        }
    }
}

pub type EcPairingCircuitInputOutput<F> = ClosedFormInput<
    F,
    EcPairingCircuitFSMInputOutput<F>,
    PrecompileFunctionInputData<F>,
    PrecompileFunctionOutputData<F>,
>;
pub type EcPairingCircuitInputOutputWitness<F> = ClosedFormInputWitness<
    F,
    EcPairingCircuitFSMInputOutput<F>,
    PrecompileFunctionInputData<F>,
    PrecompileFunctionOutputData<F>,
>;

#[derive(Derivative, Serialize, Deserialize)]
#[derivative(Clone, Debug, Default)]
#[serde(bound = "")]
pub struct EcPairingCircuitInstanceWitness<F: SmallField> {
    pub closed_form_input: EcPairingCircuitInputOutputWitness<F>,
    pub requests_queue_witness: CircuitQueueRawWitness<F, LogQuery<F>, 4, LOG_QUERY_PACKED_WIDTH>,
    pub memory_reads_witness: VecDeque<U256>,
}
