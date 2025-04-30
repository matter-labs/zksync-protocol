use std::{marker::PhantomData, mem};

use circuit_encodings::boojum::sha2;
use zkevm_assembly::zkevm_opcode_defs::{
    BlobSha256, VersionedHashGeneric, ADDRESS_CONTRACT_DEPLOYER, ADDRESS_KNOWN_CODES_STORAGE,
};

use crate::zk_evm::{reference_impls::memory::SimpleMemory, tracing::Tracer};
use crate::{
    read_fatpointer_from_simple_memory,
    zk_evm::{
        aux_structures::Timestamp,
        tracing::{AfterExecutionData, VmLocalStateData},
        zkevm_opcode_defs::{
            FarCallOpcode, FatPointer, Opcode, CALL_IMPLICIT_CALLDATA_FAT_PTR_REGISTER,
        },
    },
};

use crate::ethereum_types::{Address, H160, U256};

pub fn evm_bytecode_into_words(bytecode: Vec<u8>) -> Vec<[u8; 32]> {
    let mut result = Vec::new();

    for chunk in bytecode.chunks(32) {
        let mut arr = [0u8; 32];
        arr[..chunk.len()].copy_from_slice(chunk);
        result.push(arr);
    }

    result
}

pub fn hash_evm_bytecode(unpadded_len: usize, bytecode_words: &Vec<[u8; 32]>) -> U256 {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for w in bytecode_words.iter() {
        hasher.update(&w);
    }

    let result = hasher.finalize();

    let mut digest = [0u8; 32];
    digest[..].copy_from_slice(&result.as_slice());

    let versioned_hash = VersionedHashGeneric::<BlobSha256>::from_digest_and_preimage_length(
        digest,
        unpadded_len.try_into().unwrap(),
    );

    U256::from_big_endian(&versioned_hash.serialize().unwrap())
}

/// Tracer responsible for collecting information about EVM deploys and providing those
/// to the code decommitter.
#[derive(Debug)]
pub(crate) struct EvmDeployTracer {
    pub tracked_signature: [u8; 4],
    pub pending_bytecodes: Vec<(usize, Vec<u8>)>,
}

impl EvmDeployTracer {
    pub(crate) fn new() -> Self {
        let tracked_signature = ethabi::short_signature(
            "publishEVMBytecode",
            &[ethabi::ParamType::Uint(256), ethabi::ParamType::Bytes],
        );

        Self {
            tracked_signature,
            pending_bytecodes: vec![],
        }
    }

    pub(crate) fn flush_bytecodes(self: &mut Self) -> Vec<(U256, Vec<U256>)> {
        let raw_bytecodes = mem::take(&mut self.pending_bytecodes);

        raw_bytecodes
            .into_iter()
            .map(|(unpadded_len, raw_bytecode)| {
                let bytecode_in_words = evm_bytecode_into_words(raw_bytecode);

                (
                    hash_evm_bytecode(unpadded_len, &bytecode_in_words),
                    bytecode_in_words
                        .into_iter()
                        .map(|el| U256::from_big_endian(&el))
                        .collect(),
                )
            })
            .collect()
    }
}

impl Tracer for EvmDeployTracer {
    const CALL_BEFORE_DECODING: bool = false;
    const CALL_AFTER_DECODING: bool = false;
    const CALL_BEFORE_EXECUTION: bool = false;
    const CALL_AFTER_EXECUTION: bool = true;
    type SupportedMemory = SimpleMemory;

    fn before_decoding(
        &mut self,
        _state: VmLocalStateData<
            '_,
            8,
            zkevm_assembly::zkevm_opcode_defs::decoding::EncodingModeProduction,
        >,
        _memory: &Self::SupportedMemory,
    ) {
        todo!()
    }

    fn after_decoding(
        &mut self,
        _state: VmLocalStateData<
            '_,
            8,
            zkevm_assembly::zkevm_opcode_defs::decoding::EncodingModeProduction,
        >,
        _data: circuit_encodings::zk_evm::tracing::AfterDecodingData<
            8,
            zkevm_assembly::zkevm_opcode_defs::decoding::EncodingModeProduction,
        >,
        _memory: &Self::SupportedMemory,
    ) {
        todo!()
    }

    fn before_execution(
        &mut self,
        _state: VmLocalStateData<
            '_,
            8,
            zkevm_assembly::zkevm_opcode_defs::decoding::EncodingModeProduction,
        >,
        _data: circuit_encodings::zk_evm::tracing::BeforeExecutionData<
            8,
            zkevm_assembly::zkevm_opcode_defs::decoding::EncodingModeProduction,
        >,
        _memory: &Self::SupportedMemory,
    ) {
        todo!()
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
        if !matches!(
            data.opcode.variant.opcode,
            Opcode::FarCall(FarCallOpcode::Normal)
        ) {
            return;
        };

        let current = state.vm_local_state.callstack.current;
        let from = current.msg_sender;
        let to = current.this_address;
        if from != H160::from_low_u64_be(ADDRESS_CONTRACT_DEPLOYER.into())
            || to != H160::from_low_u64_be(ADDRESS_KNOWN_CODES_STORAGE.into())
        {
            return;
        }

        let calldata_ptr =
            state.vm_local_state.registers[usize::from(CALL_IMPLICIT_CALLDATA_FAT_PTR_REGISTER)];
        let data =
            read_fatpointer_from_simple_memory(memory, FatPointer::from_u256(calldata_ptr.value));
        if data.len() < 4 {
            return;
        }
        let (signature, data) = data.split_at(4);
        if signature != self.tracked_signature {
            return;
        }

        match ethabi::decode(
            &[ethabi::ParamType::Uint(256), ethabi::ParamType::Bytes],
            data,
        ) {
            Ok(decoded) => {
                let mut decoded_iter = decoded.into_iter();
                let raw_bytecode_len = decoded_iter.next().unwrap().into_uint().unwrap().try_into();
                match raw_bytecode_len {
                    Ok(raw_bytecode_len) => {
                        let published_bytecode = decoded_iter.next().unwrap().into_bytes().unwrap();
                        self.pending_bytecodes
                            .push((raw_bytecode_len, published_bytecode));
                    }
                    Err(err) => {
                        tracing::error!("Invalid bytecode len in `publishEVMBytecode` call: {err}")
                    }
                }
            }
            Err(err) => tracing::error!("Unable to decode `publishEVMBytecode` call: {err}"),
        }
    }
}
