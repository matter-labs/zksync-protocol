use zkevm_opcode_defs::{
    blake2,
    ethereum_types::{Address, U256},
    VersionedHashHeader, VersionedHashNormalizedPreimage,
};

use crate::aux::{MemoryLocation, MemoryPage, Timestamp};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MemoryQuery {
    pub timestamp: Timestamp,
    pub location: MemoryLocation,
    pub value: U256,
    pub rw_flag: bool,
    pub value_is_pointer: bool,
}

impl MemoryQuery {
    pub const fn empty() -> Self {
        Self {
            timestamp: Timestamp::empty(),
            location: MemoryLocation::empty(),
            rw_flag: false,
            value_is_pointer: false,
            value: U256::zero(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct LogQuery {
    pub timestamp: Timestamp,
    pub tx_number_in_block: u16,
    pub aux_byte: u8,
    pub shard_id: u8,
    pub address: Address,
    pub key: U256,
    pub read_value: U256,
    pub written_value: U256,
    pub rw_flag: bool,
    pub rollback: bool,
    pub is_service: bool,
}

impl LogQuery {
    pub fn derive_final_address_for_params(address: &Address, key: &U256) -> [u8; 32] {
        let mut buffer = [0u8; 64];
        buffer[12..32].copy_from_slice(&address.0);
        key.to_big_endian(&mut buffer[32..64]);

        use blake2::*;
        let mut result = [0u8; 32];
        result.copy_from_slice(Blake2s256::digest(&buffer).as_slice());

        result
    }

    pub fn key_derivation_bytes(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[12..32].copy_from_slice(&self.address.0);
        self.key.to_big_endian(&mut result[32..64]);

        result
    }

    pub fn derive_final_address(&self) -> [u8; 32] {
        Self::derive_final_address_for_params(&self.address, &self.key)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct DecommittmentQuery {
    pub header: VersionedHashHeader,
    pub normalized_preimage: VersionedHashNormalizedPreimage,
    pub timestamp: Timestamp,
    pub memory_page: MemoryPage,
    pub decommitted_length: u16,
    pub is_fresh: bool,
}
