use crate::boojum::cs::gates::*;
use crate::boojum::cs::implementations::proof::Proof;
use crate::boojum::cs::implementations::setup::FinalizationHintsForProver;
use crate::boojum::cs::traits::gate::GatePlacementStrategy;
use crate::boojum::field::goldilocks::{GoldilocksExt2, GoldilocksField};
use crate::boojum::gadgets::tables::*;
use crate::zkevm_circuits::base_structures::vm_state::saved_context::ExecutionContextRecord;
use crate::zkevm_circuits::boojum::config::CSConfig;
use crate::zkevm_circuits::boojum::dag::CircuitResolver;
use crate::zkevm_circuits::storage_validity_by_grand_product::TimestampedStorageLogRecord;
use crate::zkevm_circuits::tables::*;
use snark_wrapper::boojum::dag::StCircuitResolver;

use super::*;

pub const TARGET_CIRCUIT_TRACE_LENGTH: usize = 1 << 20;

// should follow in the same sequence as we will logically process sequences
pub mod code_decommitter;
pub mod ecrecover;
pub mod events_sort_dedup;
pub mod keccak256_round_function;
pub mod log_demux;
pub mod ram_permutation;
pub mod secp256r1_verify;
pub mod sha256_round_function;
pub mod sort_code_decommits;
pub mod storage_apply;
pub mod storage_sort_dedup;
pub mod transient_storage_sort;
pub mod vm_main;
// pub mod l1_messages_sort_dedup; // equal to one above
pub mod ecadd;
pub mod ecmul;
pub mod ecpairing;
pub mod eip4844;
pub mod linear_hasher;
pub mod modexp;

pub use self::code_decommitter::CodeDecommitterInstanceSynthesisFunction;
pub use self::ecadd::ECAddFunctionInstanceSynthesisFunction;
pub use self::ecmul::ECMulFunctionInstanceSynthesisFunction;
pub use self::ecpairing::ECPairingFunctionInstanceSynthesisFunction;
pub use self::ecrecover::ECRecoverFunctionInstanceSynthesisFunction;
pub use self::eip4844::EIP4844InstanceSynthesisFunction;
pub use self::events_sort_dedup::EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction;
pub use self::keccak256_round_function::Keccak256RoundFunctionInstanceSynthesisFunction;
pub use self::linear_hasher::LinearHasherInstanceSynthesisFunction;
pub use self::log_demux::LogDemuxInstanceSynthesisFunction;
pub use self::modexp::ModexpFunctionInstanceSynthesisFunction;
pub use self::ram_permutation::RAMPermutationInstanceSynthesisFunction;
pub use self::secp256r1_verify::Secp256r1VerifyFunctionInstanceSynthesisFunction;
pub use self::sha256_round_function::Sha256RoundFunctionInstanceSynthesisFunction;
pub use self::sort_code_decommits::CodeDecommittmentsSorterSynthesisFunction;
pub use self::storage_apply::StorageApplicationInstanceSynthesisFunction;
pub use self::storage_sort_dedup::StorageSortAndDedupInstanceSynthesisFunction;
pub use self::transient_storage_sort::TransientStorageSortAndDedupInstanceSynthesisFunction;
pub use self::vm_main::VmMainInstanceSynthesisFunction;

// Type definitions for circuits, so one can easily form circuits with witness, and their definition
// will take care of particular synthesis function. There is already an implementation of Circuit<F> for ZkSyncUniformCircuitInstance,
// so as soon as the structure is instantiated it is ready for proving
pub type VMMainCircuit =
    ZkSyncUniformCircuitInstance<GoldilocksField, VmMainInstanceSynthesisFunction>;
pub type CodeDecommittsSorterCircuit =
    ZkSyncUniformCircuitInstance<GoldilocksField, CodeDecommittmentsSorterSynthesisFunction>;
pub type CodeDecommitterCircuit =
    ZkSyncUniformCircuitInstance<GoldilocksField, CodeDecommitterInstanceSynthesisFunction>;
pub type LogDemuxerCircuit =
    ZkSyncUniformCircuitInstance<GoldilocksField, LogDemuxInstanceSynthesisFunction>;
pub type Keccak256RoundFunctionCircuit =
    ZkSyncUniformCircuitInstance<GoldilocksField, Keccak256RoundFunctionInstanceSynthesisFunction>;
pub type Sha256RoundFunctionCircuit =
    ZkSyncUniformCircuitInstance<GoldilocksField, Sha256RoundFunctionInstanceSynthesisFunction>;
pub type ECRecoverFunctionCircuit =
    ZkSyncUniformCircuitInstance<GoldilocksField, ECRecoverFunctionInstanceSynthesisFunction>;
pub type ModexpCircuit =
    ZkSyncUniformCircuitInstance<GoldilocksField, ModexpFunctionInstanceSynthesisFunction>;
pub type ECAddCircuit =
    ZkSyncUniformCircuitInstance<GoldilocksField, ECAddFunctionInstanceSynthesisFunction>;
pub type ECMulCircuit =
    ZkSyncUniformCircuitInstance<GoldilocksField, ECMulFunctionInstanceSynthesisFunction>;
pub type ECPairingCircuit =
    ZkSyncUniformCircuitInstance<GoldilocksField, ECPairingFunctionInstanceSynthesisFunction>;

pub type RAMPermutationCircuit =
    ZkSyncUniformCircuitInstance<GoldilocksField, RAMPermutationInstanceSynthesisFunction>;
pub type StorageSorterCircuit =
    ZkSyncUniformCircuitInstance<GoldilocksField, StorageSortAndDedupInstanceSynthesisFunction>;
pub type StorageApplicationCircuit =
    ZkSyncUniformCircuitInstance<GoldilocksField, StorageApplicationInstanceSynthesisFunction>;
pub type EventsSorterCircuit = ZkSyncUniformCircuitInstance<
    GoldilocksField,
    EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction,
>;
pub type L1MessagesSorterCircuit = ZkSyncUniformCircuitInstance<
    GoldilocksField,
    EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction,
>;
pub type L1MessagesHasherCircuit =
    ZkSyncUniformCircuitInstance<GoldilocksField, LinearHasherInstanceSynthesisFunction>;
pub type TransientStorageSorterCircuit = ZkSyncUniformCircuitInstance<
    GoldilocksField,
    TransientStorageSortAndDedupInstanceSynthesisFunction,
>;
pub type Secp256r1VerifyCircuit =
    ZkSyncUniformCircuitInstance<GoldilocksField, Secp256r1VerifyFunctionInstanceSynthesisFunction>;
pub type EIP4844Circuit =
    ZkSyncUniformCircuitInstance<GoldilocksField, EIP4844InstanceSynthesisFunction>;

#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""), Debug)]
#[serde(bound = "")]
pub enum ZkSyncBaseLayerStorage<
    T: Clone + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned,
> {
    MainVM(T),
    CodeDecommittmentsSorter(T),
    CodeDecommitter(T),
    LogDemuxer(T),
    KeccakRoundFunction(T),
    Sha256RoundFunction(T),
    ECRecover(T),
    RAMPermutation(T),
    StorageSorter(T),
    StorageApplication(T),
    EventsSorter(T),
    L1MessagesSorter(T),
    L1MessagesHasher(T),
    TransientStorageSorter(T),
    Secp256r1Verify(T),
    EIP4844Repack(T),
    Modexp(T),
    ECAdd(T),
    ECMul(T),
    ECPairing(T),
}

impl<T: Clone + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned>
    ZkSyncBaseLayerStorage<T>
{
    pub fn short_description(&self) -> &'static str {
        match &self {
            ZkSyncBaseLayerStorage::MainVM(..) => "Main VM",
            ZkSyncBaseLayerStorage::CodeDecommittmentsSorter(..) => "Decommitts sorter",
            ZkSyncBaseLayerStorage::CodeDecommitter(..) => "Code decommitter",
            ZkSyncBaseLayerStorage::LogDemuxer(..) => "Log demuxer",
            ZkSyncBaseLayerStorage::KeccakRoundFunction(..) => "Keccak",
            ZkSyncBaseLayerStorage::Sha256RoundFunction(..) => "SHA256",
            ZkSyncBaseLayerStorage::ECRecover(..) => "ECRecover",
            ZkSyncBaseLayerStorage::RAMPermutation(..) => "RAM permutation",
            ZkSyncBaseLayerStorage::StorageSorter(..) => "Storage sorter",
            ZkSyncBaseLayerStorage::StorageApplication(..) => "Storage application",
            ZkSyncBaseLayerStorage::EventsSorter(..) => "Events sorter",
            ZkSyncBaseLayerStorage::L1MessagesSorter(..) => "L1 messages sorter",
            ZkSyncBaseLayerStorage::L1MessagesHasher(..) => "L1 messages rehasher",
            ZkSyncBaseLayerStorage::TransientStorageSorter(..) => "Transient storage sorter",
            ZkSyncBaseLayerStorage::Secp256r1Verify(..) => "Secp256r1 signature verifier",
            ZkSyncBaseLayerStorage::EIP4844Repack(..) => "EIP4844 repacker",
            ZkSyncBaseLayerStorage::Modexp(..) => "Modexp",
            ZkSyncBaseLayerStorage::ECAdd(..) => "ECAdd",
            ZkSyncBaseLayerStorage::ECMul(..) => "ECMul",
            ZkSyncBaseLayerStorage::ECPairing(..) => "ECPairing",
        }
    }

    pub fn numeric_circuit_type(&self) -> u8 {
        use crate::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;

        match &self {
            ZkSyncBaseLayerStorage::MainVM(..) => BaseLayerCircuitType::VM as u8,
            ZkSyncBaseLayerStorage::CodeDecommittmentsSorter(..) => {
                BaseLayerCircuitType::DecommitmentsFilter as u8
            }
            ZkSyncBaseLayerStorage::CodeDecommitter(..) => BaseLayerCircuitType::Decommiter as u8,
            ZkSyncBaseLayerStorage::LogDemuxer(..) => BaseLayerCircuitType::LogDemultiplexer as u8,
            ZkSyncBaseLayerStorage::KeccakRoundFunction(..) => {
                BaseLayerCircuitType::KeccakPrecompile as u8
            }
            ZkSyncBaseLayerStorage::Sha256RoundFunction(..) => {
                BaseLayerCircuitType::Sha256Precompile as u8
            }
            ZkSyncBaseLayerStorage::ECRecover(..) => {
                BaseLayerCircuitType::EcrecoverPrecompile as u8
            }
            ZkSyncBaseLayerStorage::RAMPermutation(..) => BaseLayerCircuitType::RamValidation as u8,
            ZkSyncBaseLayerStorage::StorageSorter(..) => BaseLayerCircuitType::StorageFilter as u8,
            ZkSyncBaseLayerStorage::StorageApplication(..) => {
                BaseLayerCircuitType::StorageApplicator as u8
            }
            ZkSyncBaseLayerStorage::EventsSorter(..) => {
                BaseLayerCircuitType::EventsRevertsFilter as u8
            }
            ZkSyncBaseLayerStorage::L1MessagesSorter(..) => {
                BaseLayerCircuitType::L1MessagesRevertsFilter as u8
            }
            ZkSyncBaseLayerStorage::L1MessagesHasher(..) => {
                BaseLayerCircuitType::L1MessagesHasher as u8
            }
            ZkSyncBaseLayerStorage::TransientStorageSorter(..) => {
                BaseLayerCircuitType::TransientStorageChecker as u8
            }
            ZkSyncBaseLayerStorage::Secp256r1Verify(..) => {
                BaseLayerCircuitType::Secp256r1Verify as u8
            }
            ZkSyncBaseLayerStorage::EIP4844Repack(..) => BaseLayerCircuitType::EIP4844Repack as u8,
            ZkSyncBaseLayerStorage::Modexp(..) => BaseLayerCircuitType::ModexpPrecompile as u8,
            ZkSyncBaseLayerStorage::ECAdd(..) => BaseLayerCircuitType::ECAddPrecompile as u8,
            ZkSyncBaseLayerStorage::ECMul(..) => BaseLayerCircuitType::ECMulPrecompile as u8,
            ZkSyncBaseLayerStorage::ECPairing(..) => {
                BaseLayerCircuitType::ECPairingPrecompile as u8
            }
        }
    }

    pub fn into_inner(self) -> T {
        match self {
            ZkSyncBaseLayerStorage::MainVM(inner) => inner,
            ZkSyncBaseLayerStorage::CodeDecommittmentsSorter(inner) => inner,
            ZkSyncBaseLayerStorage::CodeDecommitter(inner) => inner,
            ZkSyncBaseLayerStorage::LogDemuxer(inner) => inner,
            ZkSyncBaseLayerStorage::KeccakRoundFunction(inner) => inner,
            ZkSyncBaseLayerStorage::Sha256RoundFunction(inner) => inner,
            ZkSyncBaseLayerStorage::ECRecover(inner) => inner,
            ZkSyncBaseLayerStorage::RAMPermutation(inner) => inner,
            ZkSyncBaseLayerStorage::StorageSorter(inner) => inner,
            ZkSyncBaseLayerStorage::StorageApplication(inner) => inner,
            ZkSyncBaseLayerStorage::EventsSorter(inner) => inner,
            ZkSyncBaseLayerStorage::L1MessagesSorter(inner) => inner,
            ZkSyncBaseLayerStorage::L1MessagesHasher(inner) => inner,
            ZkSyncBaseLayerStorage::TransientStorageSorter(inner) => inner,
            ZkSyncBaseLayerStorage::Secp256r1Verify(inner) => inner,
            ZkSyncBaseLayerStorage::EIP4844Repack(inner) => inner,
            ZkSyncBaseLayerStorage::Modexp(inner) => inner,
            ZkSyncBaseLayerStorage::ECAdd(inner) => inner,
            ZkSyncBaseLayerStorage::ECMul(inner) => inner,
            ZkSyncBaseLayerStorage::ECPairing(inner) => inner,
        }
    }

    pub fn from_inner(numeric_type: u8, inner: T) -> Self {
        use crate::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;

        match numeric_type {
            a if a == BaseLayerCircuitType::VM as u8 => Self::MainVM(inner),
            a if a == BaseLayerCircuitType::DecommitmentsFilter as u8 => {
                Self::CodeDecommittmentsSorter(inner)
            }
            a if a == BaseLayerCircuitType::Decommiter as u8 => Self::CodeDecommitter(inner),
            a if a == BaseLayerCircuitType::LogDemultiplexer as u8 => Self::LogDemuxer(inner),
            a if a == BaseLayerCircuitType::KeccakPrecompile as u8 => {
                Self::KeccakRoundFunction(inner)
            }
            a if a == BaseLayerCircuitType::Sha256Precompile as u8 => {
                Self::Sha256RoundFunction(inner)
            }
            a if a == BaseLayerCircuitType::EcrecoverPrecompile as u8 => Self::ECRecover(inner),
            a if a == BaseLayerCircuitType::RamValidation as u8 => Self::RAMPermutation(inner),
            a if a == BaseLayerCircuitType::StorageFilter as u8 => Self::StorageSorter(inner),
            a if a == BaseLayerCircuitType::StorageApplicator as u8 => {
                Self::StorageApplication(inner)
            }
            a if a == BaseLayerCircuitType::EventsRevertsFilter as u8 => Self::EventsSorter(inner),
            a if a == BaseLayerCircuitType::L1MessagesRevertsFilter as u8 => {
                Self::L1MessagesSorter(inner)
            }
            a if a == BaseLayerCircuitType::L1MessagesHasher as u8 => Self::L1MessagesHasher(inner),
            a if a == BaseLayerCircuitType::TransientStorageChecker as u8 => {
                Self::TransientStorageSorter(inner)
            }
            a if a == BaseLayerCircuitType::Secp256r1Verify as u8 => Self::Secp256r1Verify(inner),
            a if a == BaseLayerCircuitType::EIP4844Repack as u8 => Self::EIP4844Repack(inner),
            a if a == BaseLayerCircuitType::ModexpPrecompile as u8 => Self::Modexp(inner),
            a if a == BaseLayerCircuitType::ECAddPrecompile as u8 => Self::ECAdd(inner),
            a if a == BaseLayerCircuitType::ECMulPrecompile as u8 => Self::ECMul(inner),
            a if a == BaseLayerCircuitType::ECPairingPrecompile as u8 => Self::ECPairing(inner),

            a @ _ => panic!("unknown numeric type {}", a),
        }
    }
}

type F = GoldilocksField;

#[derive(derivative::Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""))]
#[serde(bound = "")]
pub enum ZkSyncBaseLayerCircuit
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    MainVM(VMMainCircuit),
    CodeDecommittmentsSorter(CodeDecommittsSorterCircuit),
    CodeDecommitter(CodeDecommitterCircuit),
    LogDemuxer(LogDemuxerCircuit),
    KeccakRoundFunction(Keccak256RoundFunctionCircuit),
    Sha256RoundFunction(Sha256RoundFunctionCircuit),
    ECRecover(ECRecoverFunctionCircuit),
    RAMPermutation(RAMPermutationCircuit),
    StorageSorter(StorageSorterCircuit),
    StorageApplication(StorageApplicationCircuit),
    EventsSorter(EventsSorterCircuit),
    L1MessagesSorter(L1MessagesSorterCircuit),
    L1MessagesHasher(L1MessagesHasherCircuit),
    TransientStorageSorter(TransientStorageSorterCircuit),
    Secp256r1Verify(Secp256r1VerifyCircuit),
    EIP4844Repack(EIP4844Circuit),
    Modexp(ModexpCircuit),
    ECAdd(ECAddCircuit),
    ECMul(ECMulCircuit),
    ECPairing(ECPairingCircuit),
}

impl ZkSyncBaseLayerCircuit
where
    [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:,
    [(); <ExecutionContextRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <TimestampedStorageLogRecord<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
{
    pub fn short_description(&self) -> &'static str {
        match &self {
            ZkSyncBaseLayerCircuit::MainVM(..) => "Main VM",
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(..) => "Decommitts sorter",
            ZkSyncBaseLayerCircuit::CodeDecommitter(..) => "Code decommitter",
            ZkSyncBaseLayerCircuit::LogDemuxer(..) => "Log demuxer",
            ZkSyncBaseLayerCircuit::KeccakRoundFunction(..) => "Keccak",
            ZkSyncBaseLayerCircuit::Sha256RoundFunction(..) => "SHA256",
            ZkSyncBaseLayerCircuit::ECRecover(..) => "ECRecover",
            ZkSyncBaseLayerCircuit::RAMPermutation(..) => "RAM permutation",
            ZkSyncBaseLayerCircuit::StorageSorter(..) => "Storage sorter",
            ZkSyncBaseLayerCircuit::StorageApplication(..) => "Storage application",
            ZkSyncBaseLayerCircuit::EventsSorter(..) => "Events sorter",
            ZkSyncBaseLayerCircuit::L1MessagesSorter(..) => "L1 messages sorter",
            ZkSyncBaseLayerCircuit::L1MessagesHasher(..) => "L1 messages rehasher",
            ZkSyncBaseLayerCircuit::TransientStorageSorter(..) => "Transient storage sorter",
            ZkSyncBaseLayerCircuit::Secp256r1Verify(..) => "Secp256r1 verify",
            ZkSyncBaseLayerCircuit::EIP4844Repack(..) => "EIP4844 repacker",
            ZkSyncBaseLayerCircuit::Modexp(..) => "Modexp",
            ZkSyncBaseLayerCircuit::ECAdd(..) => "ECAdd",
            ZkSyncBaseLayerCircuit::ECMul(..) => "ECMul",
            ZkSyncBaseLayerCircuit::ECPairing(..) => "ECPairing",
        }
    }

    pub fn size_hint(&self) -> (Option<usize>, Option<usize>) {
        match &self {
            ZkSyncBaseLayerCircuit::MainVM(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::LogDemuxer(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::Sha256RoundFunction(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::ECRecover(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::RAMPermutation(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::StorageSorter(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::StorageApplication(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::EventsSorter(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::L1MessagesSorter(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::L1MessagesHasher(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::TransientStorageSorter(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::Secp256r1Verify(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::EIP4844Repack(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::Modexp(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::ECAdd(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::ECMul(inner) => inner.size_hint(),
            ZkSyncBaseLayerCircuit::ECPairing(inner) => inner.size_hint(),
        }
    }

    fn synthesis_inner<P, CR>(
        inner: &ZkSyncUniformCircuitInstance<F, impl ZkSyncUniformSynthesisFunction<F>>,
        hint: &FinalizationHintsForProver,
    ) -> CSReferenceAssembly<F, P, ProvingCSConfig>
    where
        P: PrimeFieldLikeVectorized<Base = F>,
        CR: CircuitResolver<
            F,
            crate::boojum::config::Resolver<crate::boojum::config::DontPerformRuntimeAsserts>,
        >,
        usize: Into<<CR as CircuitResolver<F, <ProvingCSConfig as CSConfig>::ResolverConfig>>::Arg>,
    {
        let geometry = inner.geometry_proxy();
        let (max_trace_len, num_vars) = inner.size_hint();
        let builder_impl = CsReferenceImplementationBuilder::<F, P, ProvingCSConfig, CR>::new(
            geometry,
            max_trace_len.unwrap(),
        );
        let cs_builder = new_builder::<_, F>(builder_impl);
        let builder = inner.configure_builder_proxy(cs_builder);
        let mut cs = builder.build(num_vars.unwrap());
        inner.add_tables_proxy(&mut cs);
        inner.clone().synthesize_proxy(&mut cs);
        cs.pad_and_shrink_using_hint(hint);
        cs.into_assembly()
    }

    pub fn synthesis<P: PrimeFieldLikeVectorized<Base = F>>(
        &self,
        hint: &FinalizationHintsForProver,
    ) -> CSReferenceAssembly<F, P, ProvingCSConfig> {
        self.synthesis_wrapped::<
            P,
            StCircuitResolver<F, <ProvingCSConfig as CSConfig>::ResolverConfig>
        >(hint)
    }

    pub fn synthesis_wrapped<P, CR>(
        &self,
        hint: &FinalizationHintsForProver,
    ) -> CSReferenceAssembly<F, P, ProvingCSConfig>
    where
        P: PrimeFieldLikeVectorized<Base = F>,
        CR: CircuitResolver<
            F,
            crate::boojum::config::Resolver<crate::boojum::config::DontPerformRuntimeAsserts>,
        >,
        usize: Into<<CR as CircuitResolver<F, <ProvingCSConfig as CSConfig>::ResolverConfig>>::Arg>,
    {
        match &self {
            ZkSyncBaseLayerCircuit::MainVM(inner) => Self::synthesis_inner::<_, CR>(inner, hint),
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => {
                Self::synthesis_inner::<_, CR>(inner, hint)
            }
            ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => {
                Self::synthesis_inner::<_, CR>(inner, hint)
            }
            ZkSyncBaseLayerCircuit::LogDemuxer(inner) => {
                Self::synthesis_inner::<_, CR>(inner, hint)
            }
            ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => {
                Self::synthesis_inner::<_, CR>(inner, hint)
            }
            ZkSyncBaseLayerCircuit::Sha256RoundFunction(inner) => {
                Self::synthesis_inner::<_, CR>(inner, hint)
            }
            ZkSyncBaseLayerCircuit::ECRecover(inner) => Self::synthesis_inner::<_, CR>(inner, hint),
            ZkSyncBaseLayerCircuit::RAMPermutation(inner) => {
                Self::synthesis_inner::<_, CR>(inner, hint)
            }
            ZkSyncBaseLayerCircuit::StorageSorter(inner) => {
                Self::synthesis_inner::<_, CR>(inner, hint)
            }
            ZkSyncBaseLayerCircuit::StorageApplication(inner) => {
                Self::synthesis_inner::<_, CR>(inner, hint)
            }
            ZkSyncBaseLayerCircuit::EventsSorter(inner) => {
                Self::synthesis_inner::<_, CR>(inner, hint)
            }
            ZkSyncBaseLayerCircuit::L1MessagesSorter(inner) => {
                Self::synthesis_inner::<_, CR>(inner, hint)
            }
            ZkSyncBaseLayerCircuit::L1MessagesHasher(inner) => {
                Self::synthesis_inner::<_, CR>(inner, hint)
            }
            ZkSyncBaseLayerCircuit::TransientStorageSorter(inner) => {
                Self::synthesis_inner::<_, CR>(inner, hint)
            }
            ZkSyncBaseLayerCircuit::Secp256r1Verify(inner) => {
                Self::synthesis_inner::<_, CR>(inner, hint)
            }
            ZkSyncBaseLayerCircuit::EIP4844Repack(inner) => {
                Self::synthesis_inner::<_, CR>(inner, hint)
            }
            ZkSyncBaseLayerCircuit::Modexp(inner) => Self::synthesis_inner::<_, CR>(inner, hint),
            ZkSyncBaseLayerCircuit::ECAdd(inner) => Self::synthesis_inner::<_, CR>(inner, hint),
            ZkSyncBaseLayerCircuit::ECMul(inner) => Self::synthesis_inner::<_, CR>(inner, hint),
            ZkSyncBaseLayerCircuit::ECPairing(inner) => Self::synthesis_inner::<_, CR>(inner, hint),
        }
    }

    pub fn geometry(&self) -> CSGeometry {
        match &self {
            ZkSyncBaseLayerCircuit::MainVM(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::LogDemuxer(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::Sha256RoundFunction(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::ECRecover(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::RAMPermutation(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::StorageSorter(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::StorageApplication(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::EventsSorter(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::L1MessagesSorter(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::L1MessagesHasher(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::TransientStorageSorter(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::Secp256r1Verify(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::EIP4844Repack(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::Modexp(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::ECAdd(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::ECMul(inner) => inner.geometry_proxy(),
            ZkSyncBaseLayerCircuit::ECPairing(inner) => inner.geometry_proxy(),
        }
    }

    pub fn debug_witness(&self) {
        match &self {
            ZkSyncBaseLayerCircuit::MainVM(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::CodeDecommitter(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::LogDemuxer(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::KeccakRoundFunction(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::Sha256RoundFunction(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::ECRecover(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::RAMPermutation(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::StorageSorter(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::StorageApplication(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::EventsSorter(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::L1MessagesSorter(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::L1MessagesHasher(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::TransientStorageSorter(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::Secp256r1Verify(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::EIP4844Repack(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::Modexp(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::ECAdd(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::ECMul(inner) => {
                inner.debug_witness();
            }
            ZkSyncBaseLayerCircuit::ECPairing(inner) => {
                inner.debug_witness();
            }
        };

        ()
    }

    pub fn numeric_circuit_type(&self) -> u8 {
        use crate::zkevm_circuits::scheduler::aux::BaseLayerCircuitType;

        match &self {
            ZkSyncBaseLayerCircuit::MainVM(..) => BaseLayerCircuitType::VM as u8,
            ZkSyncBaseLayerCircuit::CodeDecommittmentsSorter(..) => {
                BaseLayerCircuitType::DecommitmentsFilter as u8
            }
            ZkSyncBaseLayerCircuit::CodeDecommitter(..) => BaseLayerCircuitType::Decommiter as u8,
            ZkSyncBaseLayerCircuit::LogDemuxer(..) => BaseLayerCircuitType::LogDemultiplexer as u8,
            ZkSyncBaseLayerCircuit::KeccakRoundFunction(..) => {
                BaseLayerCircuitType::KeccakPrecompile as u8
            }
            ZkSyncBaseLayerCircuit::Sha256RoundFunction(..) => {
                BaseLayerCircuitType::Sha256Precompile as u8
            }
            ZkSyncBaseLayerCircuit::ECRecover(..) => {
                BaseLayerCircuitType::EcrecoverPrecompile as u8
            }
            ZkSyncBaseLayerCircuit::RAMPermutation(..) => BaseLayerCircuitType::RamValidation as u8,
            ZkSyncBaseLayerCircuit::StorageSorter(..) => BaseLayerCircuitType::StorageFilter as u8,
            ZkSyncBaseLayerCircuit::StorageApplication(..) => {
                BaseLayerCircuitType::StorageApplicator as u8
            }
            ZkSyncBaseLayerCircuit::EventsSorter(..) => {
                BaseLayerCircuitType::EventsRevertsFilter as u8
            }
            ZkSyncBaseLayerCircuit::L1MessagesSorter(..) => {
                BaseLayerCircuitType::L1MessagesRevertsFilter as u8
            }
            ZkSyncBaseLayerCircuit::L1MessagesHasher(..) => {
                BaseLayerCircuitType::L1MessagesHasher as u8
            }
            ZkSyncBaseLayerCircuit::TransientStorageSorter(..) => {
                BaseLayerCircuitType::TransientStorageChecker as u8
            }
            ZkSyncBaseLayerCircuit::Secp256r1Verify(..) => {
                BaseLayerCircuitType::Secp256r1Verify as u8
            }
            ZkSyncBaseLayerCircuit::EIP4844Repack(..) => BaseLayerCircuitType::EIP4844Repack as u8,
            ZkSyncBaseLayerCircuit::Modexp(..) => BaseLayerCircuitType::ModexpPrecompile as u8,
            ZkSyncBaseLayerCircuit::ECAdd(..) => BaseLayerCircuitType::ECAddPrecompile as u8,
            ZkSyncBaseLayerCircuit::ECMul(..) => BaseLayerCircuitType::ECMulPrecompile as u8,
            ZkSyncBaseLayerCircuit::ECPairing(..) => {
                BaseLayerCircuitType::ECPairingPrecompile as u8
            }
        }
    }
}

pub type ZkSyncBaseLayerCircuitInput<F> =
    ZkSyncBaseLayerStorage<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>;

use crate::zkevm_circuits::fsm_input_output::ClosedFormInputCompactFormWitness;

pub type ZkSyncBaseLayerClosedFormInput<F> =
    ZkSyncBaseLayerStorage<ClosedFormInputCompactFormWitness<F>>;

use crate::boojum::algebraic_props::round_function::AbsorptionModeOverwrite;
use crate::boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;
use crate::boojum::config::ProvingCSConfig;
use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
use crate::boojum::cs::implementations::reference_cs::CSReferenceAssembly;

pub type BaseProofsTreeHasher = GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>;
pub type ZkSyncBaseProof = Proof<GoldilocksField, BaseProofsTreeHasher, GoldilocksExt2>;

pub type ZkSyncBaseLayerProof = ZkSyncBaseLayerStorage<ZkSyncBaseProof>;

pub type ZkSyncBaseLayerFinalizationHint = ZkSyncBaseLayerStorage<FinalizationHintsForProver>;

use crate::boojum::cs::implementations::verifier::VerificationKey;
use crate::boojum::field::traits::field_like::PrimeFieldLikeVectorized;
pub type ZkSyncBaseVerificationKey = VerificationKey<GoldilocksField, BaseProofsTreeHasher>;

pub type ZkSyncBaseLayerVerificationKey = ZkSyncBaseLayerStorage<ZkSyncBaseVerificationKey>;
