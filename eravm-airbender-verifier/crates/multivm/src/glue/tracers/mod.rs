use crate::{interface::storage::WriteStorage, tracers::old::OldTracers, HistoryMode};

pub type MultiVmTracerPointer<S, H> = Box<dyn MultiVmTracer<S, H>>;

pub trait MultiVmTracer<S: WriteStorage, H: HistoryMode>:
    IntoLatestTracer<S, H> + IntoOldVmTracer
{
    fn into_tracer_pointer(self) -> MultiVmTracerPointer<S, H>
    where
        Self: Sized + 'static,
    {
        Box::new(self)
    }
}

pub trait IntoLatestTracer<S: WriteStorage, H: HistoryMode> {
    fn latest(&self) -> crate::vm_latest::TracerPointer<S, H::Vm1_5_2>;
}

/// Tracers may optionally provide legacy VM hooks.
pub trait IntoOldVmTracer {
    fn old_tracer(&self) -> OldTracers {
        OldTracers::None
    }
}

impl<S, T, H> IntoLatestTracer<S, H> for T
where
    S: WriteStorage,
    H: HistoryMode,
    T: crate::vm_latest::VmTracer<S, H::Vm1_5_2> + Clone + 'static,
{
    fn latest(&self) -> crate::vm_latest::TracerPointer<S, H::Vm1_5_2> {
        Box::new(self.clone())
    }
}

impl<S, H, T> MultiVmTracer<S, H> for T
where
    S: WriteStorage,
    H: HistoryMode,
    T: IntoLatestTracer<S, H> + IntoOldVmTracer,
{
}
