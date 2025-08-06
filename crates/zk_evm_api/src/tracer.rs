use zk_evm::{
    reference_impls::memory::SimpleMemory,
    tracing::{
        AfterDecodingData, AfterExecutionData, BeforeExecutionData, Tracer, VmLocalStateData,
    },
};

#[derive(Debug, Clone, Copy)]
pub struct LocalTracer;

impl Tracer for LocalTracer {
    type SupportedMemory = SimpleMemory;
    #[inline]
    fn before_decoding(&mut self, _state: VmLocalStateData<'_>, _memory: &Self::SupportedMemory) {}
    #[inline]
    fn after_decoding(
        &mut self,
        _state: VmLocalStateData<'_>,
        _data: AfterDecodingData,
        _memory: &Self::SupportedMemory,
    ) {
    }
    #[inline]
    fn before_execution(
        &mut self,
        _state: VmLocalStateData<'_>,
        _data: BeforeExecutionData,
        _memory: &Self::SupportedMemory,
    ) {
    }
    #[inline]
    fn after_execution(
        &mut self,
        _state: VmLocalStateData<'_>,
        _data: AfterExecutionData,
        _memory: &Self::SupportedMemory,
    ) {
    }
}
