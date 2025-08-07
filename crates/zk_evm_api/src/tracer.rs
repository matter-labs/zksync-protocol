use zk_evm::{
    reference_impls::memory::SimpleMemory,
    tracing::{
        AfterDecodingData, AfterExecutionData, BeforeExecutionData, Tracer, VmLocalStateData,
    },
};

#[derive(Debug, Clone, Copy)]
pub struct LocalTracer;

impl Tracer for LocalTracer {
    const CALL_AFTER_DECODING: bool = true;
    const CALL_AFTER_EXECUTION: bool = true;

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
        //println!("decoding");
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
        /*println!("State after exec");
        let registers = &_state.vm_local_state.registers;
        for (i, reg) in registers.iter().enumerate() {
            println!("Register {}: {:?}", i, reg.value);
        }*/

        //println!("Registers: {:?}", _state.vm_local_state.registers);
    }
}
