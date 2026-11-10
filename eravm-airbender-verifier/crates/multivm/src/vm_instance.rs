use std::{mem, rc::Rc};

use zksync_types::{vm::VmVersion, ProtocolVersionId, Transaction};
use zksync_vm_interface::{pubdata::PubdataBuilder, InspectExecutionMode};

use crate::{
    glue::history_mode::HistoryMode,
    interface::{
        storage::{ImmutableStorageView, ReadStorage, StoragePtr, StorageView},
        BytecodeCompressionResult, FinishedL1Batch, L1BatchEnv, L2BlockEnv, PushTransactionResult,
        SystemEnv, VmExecutionResultAndLogs, VmFactory, VmInterface, VmInterfaceHistoryEnabled,
        VmMemoryMetrics,
    },
    tracers::TracerDispatcher,
    vm_fast::{self, interface::Tracer, FastValidationTracer, FastVmVersion},
    vm_latest::{self, HistoryEnabled},
};

/// Enumeration encompassing all supported legacy VM versions.
///
/// # Important
///
/// Methods with a tracer arg take the provided tracer, replacing it with the default value. Legacy tracers
/// are adapted for this workflow (previously, tracers were passed by value), so they provide means to extract state after execution
/// if necessary (e.g., using `Arc<OnceCell<_>>`).
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum LegacyVmInstance<S: ReadStorage, H: HistoryMode> {
    Vm1_5_2(vm_latest::Vm<StorageView<S>, H>),
}

macro_rules! dispatch_legacy_vm {
    ($self:ident.$function:ident($($params:tt)*)) => {
        match $self {
            Self::Vm1_5_2(vm) => vm.$function($($params)*),
        }
    };
}

impl<S: ReadStorage, H: HistoryMode> VmInterface for LegacyVmInstance<S, H> {
    type TracerDispatcher = TracerDispatcher<StorageView<S>, H>;

    fn push_transaction(&mut self, tx: Transaction) -> PushTransactionResult<'_> {
        dispatch_legacy_vm!(self.push_transaction(tx))
    }

    /// Execute next transaction with custom tracers
    fn inspect(
        &mut self,
        dispatcher: &mut Self::TracerDispatcher,
        execution_mode: InspectExecutionMode,
    ) -> VmExecutionResultAndLogs {
        dispatch_legacy_vm!(self.inspect(&mut mem::take(dispatcher).into(), execution_mode))
    }

    fn start_new_l2_block(&mut self, l2_block_env: L2BlockEnv) {
        dispatch_legacy_vm!(self.start_new_l2_block(l2_block_env))
    }

    /// Inspect transaction with optional bytecode compression.
    fn inspect_transaction_with_bytecode_compression(
        &mut self,
        dispatcher: &mut Self::TracerDispatcher,
        tx: Transaction,
        with_compression: bool,
    ) -> (BytecodeCompressionResult<'_>, VmExecutionResultAndLogs) {
        dispatch_legacy_vm!(self.inspect_transaction_with_bytecode_compression(
            &mut mem::take(dispatcher).into(),
            tx,
            with_compression
        ))
    }

    /// Return the results of execution of all batch
    fn finish_batch(&mut self, pubdata_builder: Rc<dyn PubdataBuilder>) -> FinishedL1Batch {
        dispatch_legacy_vm!(self.finish_batch(pubdata_builder))
    }
}

impl<S: ReadStorage, H: HistoryMode> VmFactory<StorageView<S>> for LegacyVmInstance<S, H> {
    fn new(
        batch_env: L1BatchEnv,
        system_env: SystemEnv,
        storage_view: StoragePtr<StorageView<S>>,
    ) -> Self {
        let protocol_version = system_env.version;
        let vm_version: VmVersion = protocol_version.into();
        Self::new_with_specific_version(batch_env, system_env, storage_view, vm_version)
    }
}

impl<S: ReadStorage> VmInterfaceHistoryEnabled for LegacyVmInstance<S, HistoryEnabled> {
    fn make_snapshot(&mut self) {
        dispatch_legacy_vm!(self.make_snapshot());
    }

    fn rollback_to_the_latest_snapshot(&mut self) {
        dispatch_legacy_vm!(self.rollback_to_the_latest_snapshot());
    }

    fn pop_snapshot_no_rollback(&mut self) {
        dispatch_legacy_vm!(self.pop_snapshot_no_rollback());
    }

    fn pop_front_snapshot_no_rollback(&mut self) {
        dispatch_legacy_vm!(self.pop_front_snapshot_no_rollback());
    }
}

impl<S: ReadStorage, H: HistoryMode> LegacyVmInstance<S, H> {
    pub fn new_with_specific_version(
        l1_batch_env: L1BatchEnv,
        system_env: SystemEnv,
        storage_view: StoragePtr<StorageView<S>>,
        vm_version: VmVersion,
    ) -> Self {
        match vm_version {
            VmVersion::Vm1_5_0SmallBootloaderMemory => {
                let vm = crate::vm_latest::Vm::new_with_subversion(
                    l1_batch_env,
                    system_env,
                    storage_view,
                    crate::vm_latest::MultiVmSubversion::SmallBootloaderMemory,
                );
                Self::Vm1_5_2(vm)
            }
            VmVersion::Vm1_5_0IncreasedBootloaderMemory => {
                let vm = crate::vm_latest::Vm::new_with_subversion(
                    l1_batch_env,
                    system_env,
                    storage_view,
                    crate::vm_latest::MultiVmSubversion::IncreasedBootloaderMemory,
                );
                Self::Vm1_5_2(vm)
            }
            VmVersion::VmGateway => {
                let vm = crate::vm_latest::Vm::new_with_subversion(
                    l1_batch_env,
                    system_env,
                    storage_view,
                    crate::vm_latest::MultiVmSubversion::Gateway,
                );
                Self::Vm1_5_2(vm)
            }
            VmVersion::VmEvmEmulator => {
                let vm = crate::vm_latest::Vm::new_with_subversion(
                    l1_batch_env,
                    system_env,
                    storage_view,
                    crate::vm_latest::MultiVmSubversion::EvmEmulator,
                );
                Self::Vm1_5_2(vm)
            }
            VmVersion::VmEcPrecompiles => {
                let vm = crate::vm_latest::Vm::new_with_subversion(
                    l1_batch_env,
                    system_env,
                    storage_view,
                    crate::vm_latest::MultiVmSubversion::EcPrecompiles,
                );
                Self::Vm1_5_2(vm)
            }
            VmVersion::VmInterop => {
                let vm = vm_latest::Vm::new_with_subversion(
                    l1_batch_env,
                    system_env,
                    storage_view,
                    vm_latest::MultiVmSubversion::Interop,
                );
                Self::Vm1_5_2(vm)
            }
            VmVersion::VmMediumInterop => {
                let vm = vm_latest::Vm::new_with_subversion(
                    l1_batch_env,
                    system_env,
                    storage_view,
                    vm_latest::MultiVmSubversion::MediumInterop,
                );
                Self::Vm1_5_2(vm)
            }
            VmVersion::VmMediumInteropForceFail => {
                let vm = vm_latest::Vm::new_with_subversion(
                    l1_batch_env,
                    system_env,
                    storage_view,
                    vm_latest::MultiVmSubversion::ForceFail,
                );
                Self::Vm1_5_2(vm)
            }
            _ => panic!("Unsupported VM version {:?}", vm_version),
        }
    }

    /// Returns memory-related oracle metrics.
    pub fn record_vm_memory_metrics(&self) -> VmMemoryMetrics {
        dispatch_legacy_vm!(self.record_vm_memory_metrics())
    }
}

/// Fast VM variants.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum FastVmInstance<S: ReadStorage, Tr = (), Val = FastValidationTracer> {
    /// Fast VM running in isolation.
    Fast(vm_fast::Vm<ImmutableStorageView<S>, Tr, Val>),
}

impl<S, Tr, Val> VmInterface for FastVmInstance<S, Tr, Val>
where
    S: ReadStorage,
    Tr: Tracer + Default,
    Val: vm_fast::ValidationTracer,
{
    type TracerDispatcher = (Tr, Val);

    fn push_transaction(&mut self, tx: Transaction) -> PushTransactionResult<'_> {
        match self {
            Self::Fast(vm) => vm.push_transaction(tx),
        }
    }

    fn inspect(
        &mut self,
        tracer: &mut Self::TracerDispatcher,
        execution_mode: InspectExecutionMode,
    ) -> VmExecutionResultAndLogs {
        match self {
            Self::Fast(vm) => vm.inspect(tracer, execution_mode),
        }
    }

    fn start_new_l2_block(&mut self, l2_block_env: L2BlockEnv) {
        match self {
            Self::Fast(vm) => vm.start_new_l2_block(l2_block_env),
        }
    }

    fn inspect_transaction_with_bytecode_compression(
        &mut self,
        tracer: &mut Self::TracerDispatcher,
        tx: Transaction,
        with_compression: bool,
    ) -> (BytecodeCompressionResult<'_>, VmExecutionResultAndLogs) {
        match self {
            Self::Fast(vm) => {
                vm.inspect_transaction_with_bytecode_compression(tracer, tx, with_compression)
            }
        }
    }

    fn finish_batch(&mut self, pubdata_builder: Rc<dyn PubdataBuilder>) -> FinishedL1Batch {
        match self {
            Self::Fast(vm) => vm.finish_batch(pubdata_builder),
        }
    }
}

impl<S, Tr, Val> VmInterfaceHistoryEnabled for FastVmInstance<S, Tr, Val>
where
    S: ReadStorage,
    Tr: Tracer + Default,
    Val: vm_fast::ValidationTracer,
{
    fn make_snapshot(&mut self) {
        match self {
            Self::Fast(vm) => vm.make_snapshot(),
        }
    }

    fn rollback_to_the_latest_snapshot(&mut self) {
        match self {
            Self::Fast(vm) => vm.rollback_to_the_latest_snapshot(),
        }
    }

    fn pop_snapshot_no_rollback(&mut self) {
        match self {
            Self::Fast(vm) => vm.pop_snapshot_no_rollback(),
        }
    }

    fn pop_front_snapshot_no_rollback(&mut self) {
        match self {
            Self::Fast(vm) => vm.pop_front_snapshot_no_rollback(),
        }
    }
}

impl<S, Tr, Val> FastVmInstance<S, Tr, Val>
where
    S: ReadStorage,
    Tr: Tracer + Default,
    Val: vm_fast::ValidationTracer,
{
    /// Creates an isolated fast VM.
    pub fn fast(
        l1_batch_env: L1BatchEnv,
        system_env: SystemEnv,
        storage_view: StoragePtr<StorageView<S>>,
    ) -> Self {
        Self::Fast(vm_fast::Vm::new(l1_batch_env, system_env, storage_view))
    }

    pub fn skip_signature_verification(&mut self) {
        match self {
            Self::Fast(vm) => vm.skip_signature_verification(),
        }
    }
}

/// Checks whether the protocol version is supported by the fast VM.
pub fn is_supported_by_fast_vm(protocol_version: ProtocolVersionId) -> bool {
    FastVmVersion::try_from(VmVersion::from(protocol_version)).is_ok()
}
