use circuit_encodings::zk_evm::{
    reference_impls::memory::SimpleMemory,
    tracing::{
        AfterDecodingData, AfterExecutionData, BeforeExecutionData, Tracer, VmLocalStateData,
    },
};
use zkevm_assembly::zkevm_opcode_defs::decoding::EncodingModeProduction;

use crate::tracers::evm_deploy_tracer::EvmDeployTracer;

#[derive(Debug)]
pub(crate) struct DefaultTracer<'a, A: Tracer<SupportedMemory = SimpleMemory>> {
    pub evm_tracer: EvmDeployTracer,
    pub out_of_circuit_tracer: &'a mut A,
}

impl<'a, A: Tracer<SupportedMemory = SimpleMemory>> DefaultTracer<'a, A> {
    pub(crate) fn new(out_of_circuit_tracer: &'a mut A) -> Self {
        Self {
            evm_tracer: EvmDeployTracer::new(),
            out_of_circuit_tracer,
        }
    }
}

impl<'a, A: Tracer<SupportedMemory = SimpleMemory>> Tracer for DefaultTracer<'a, A> {
    const CALL_BEFORE_DECODING: bool = A::CALL_BEFORE_DECODING;
    const CALL_AFTER_DECODING: bool = A::CALL_AFTER_DECODING;
    const CALL_BEFORE_EXECUTION: bool = A::CALL_BEFORE_EXECUTION;
    const CALL_AFTER_EXECUTION: bool = true;
    type SupportedMemory = SimpleMemory;

    fn before_decoding(
        &mut self,
        state: VmLocalStateData<
            '_,
            8,
            zkevm_assembly::zkevm_opcode_defs::decoding::EncodingModeProduction,
        >,
        memory: &Self::SupportedMemory,
    ) {
        if A::CALL_BEFORE_DECODING {
            self.out_of_circuit_tracer.before_decoding(state, memory);
        }
    }

    fn after_decoding(
        &mut self,
        state: VmLocalStateData<
            '_,
            8,
            zkevm_assembly::zkevm_opcode_defs::decoding::EncodingModeProduction,
        >,
        data: circuit_encodings::zk_evm::tracing::AfterDecodingData<
            8,
            zkevm_assembly::zkevm_opcode_defs::decoding::EncodingModeProduction,
        >,
        memory: &Self::SupportedMemory,
    ) {
        if A::CALL_AFTER_DECODING {
            self.out_of_circuit_tracer
                .after_decoding(state, data, memory);
        }
    }

    fn before_execution(
        &mut self,
        state: VmLocalStateData<
            '_,
            8,
            zkevm_assembly::zkevm_opcode_defs::decoding::EncodingModeProduction,
        >,
        data: circuit_encodings::zk_evm::tracing::BeforeExecutionData<
            8,
            zkevm_assembly::zkevm_opcode_defs::decoding::EncodingModeProduction,
        >,
        memory: &Self::SupportedMemory,
    ) {
        if A::CALL_BEFORE_EXECUTION {
            self.out_of_circuit_tracer
                .before_execution(state, data, memory);
        }
    }

    fn after_execution(
        &mut self,
        state: VmLocalStateData<
            '_,
            8,
            zkevm_assembly::zkevm_opcode_defs::decoding::EncodingModeProduction,
        >,
        data: AfterExecutionData<
            8,
            zkevm_assembly::zkevm_opcode_defs::decoding::EncodingModeProduction,
        >,
        memory: &Self::SupportedMemory,
    ) {
        self.evm_tracer.after_execution(state, data, memory);

        if A::CALL_AFTER_EXECUTION {
            self.out_of_circuit_tracer
                .after_execution(state, data, memory);
        }
    }
}
