pub trait TupleFirst {
    fn first(&self) -> u32;
}

impl TupleFirst for u32 {
    fn first(&self) -> u32 {
        *self
    }
}

impl<T> TupleFirst for (u32, T) {
    fn first(&self) -> u32 {
        self.0
    }
}
impl<T, U> TupleFirst for (u32, T, U) {
    fn first(&self) -> u32 {
        self.0
    }
}

use crate::witness::aux_data_structs::per_circuit_accumulator::PerCircuitAccumulator;
use crate::zkevm_circuits::base_structures::{
    memory_query::MEMORY_QUERY_PACKED_WIDTH, vm_state::FULL_SPONGE_QUEUE_STATE_WIDTH,
};
use circuit_definitions::encodings::memory_query::CustomMemoryQueueSimulator;
use circuit_definitions::encodings::memory_query::QueueWitness;
use circuit_definitions::zk_evm::aux_structures::MemoryQuery;
use circuit_encodings::FullWidthMemoryQueueSimulator;

pub type MemoryQueuePerCircuitSimulator<F> = FullWidthMemoryQueueSimulator<
    F,
    MemoryQuery,
    MEMORY_QUERY_PACKED_WIDTH,
    FULL_SPONGE_QUEUE_STATE_WIDTH,
    1,
>;

pub(crate) mod one_per_circuit_accumulator;
pub(crate) mod per_circuit_accumulator;
