use std::{convert::TryInto, fmt};

use serde::{de, ser::SerializeTuple, Deserialize, Deserializer, Serialize, Serializer};
use zksync_basic_types::{Address, U256};

pub(crate) use self::compression::{compress_with_best_strategy, COMPRESSION_VERSION_NUMBER};
use crate::H256;

pub mod compression;

/// The number of bytes being used for state diff enumeration indices. Applicable to repeated writes.
pub const BYTES_PER_ENUMERATION_INDEX: u8 = 4;
/// The number of bytes being used for state diff derived keys. Applicable to initial writes.
pub const BYTES_PER_DERIVED_KEY: u8 = 32;

/// Total byte size of all fields in StateDiffRecord struct
/// 20 + 32 + 32 + 8 + 32 + 32
const STATE_DIFF_RECORD_SIZE: usize = 156;

// 2 * 136 - the size that allows for two keccak rounds.
pub const PADDED_ENCODED_STORAGE_DIFF_LEN_BYTES: usize = 272;

/// In VM there are two types of storage writes: Initial and Repeated.
///
/// After the first write to the key, we assign an index to it and in the future we should use
/// index instead of full key. It allows us to compress the data, as the full key would use 32 bytes,
/// and the index can be represented only as BYTES_PER_ENUMERATION_INDEX bytes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(test, derive(Serialize, Deserialize))]
pub struct InitialStorageWrite {
    pub index: u64,
    pub key: U256,
    pub value: H256,
}

/// For repeated writes, we can substitute the 32 byte key for a BYTES_PER_ENUMERATION_INDEX byte index
/// representing its leaf index in the tree.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(test, derive(Serialize, Deserialize))]
pub struct RepeatedStorageWrite {
    pub index: u64,
    pub value: H256,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default, Eq, PartialEq)]
pub struct StateDiffRecord {
    /// address state diff occurred at
    pub address: Address,
    /// storage slot key updated
    pub key: U256,
    /// derived_key == Blake2s(bytes32(address), key)
    pub derived_key: [u8; 32],
    /// index in tree of state diff
    pub enumeration_index: u64,
    /// previous value
    pub initial_value: U256,
    /// updated value
    pub final_value: U256,
}

impl StateDiffRecord {
    // Serialize into byte representation.
    fn encode(&self) -> [u8; STATE_DIFF_RECORD_SIZE] {
        let mut encoding = [0u8; STATE_DIFF_RECORD_SIZE];
        let mut offset = 0;
        let mut end = 0;

        end += 20;
        encoding[offset..end].copy_from_slice(self.address.as_fixed_bytes());
        offset = end;

        end += 32;
        self.key.to_big_endian(&mut encoding[offset..end]);
        offset = end;

        end += 32;
        encoding[offset..end].copy_from_slice(&self.derived_key);
        offset = end;

        end += 8;
        encoding[offset..end].copy_from_slice(&self.enumeration_index.to_be_bytes());
        offset = end;

        end += 32;
        self.initial_value.to_big_endian(&mut encoding[offset..end]);
        offset = end;

        end += 32;
        self.final_value.to_big_endian(&mut encoding[offset..end]);
        offset = end;

        debug_assert_eq!(offset, encoding.len());

        encoding
    }

    pub fn encode_padded(&self) -> [u8; PADDED_ENCODED_STORAGE_DIFF_LEN_BYTES] {
        let mut extended_state_diff_encoding = [0u8; PADDED_ENCODED_STORAGE_DIFF_LEN_BYTES];
        let packed_encoding = self.encode();
        extended_state_diff_encoding[0..packed_encoding.len()].copy_from_slice(&packed_encoding);

        extended_state_diff_encoding
    }

    /// Decode bytes into StateDiffRecord
    pub fn try_from_slice(data: &[u8]) -> Option<Self> {
        if data.len() == 156 {
            Some(Self {
                address: Address::from_slice(&data[0..20]),
                key: U256::from(&data[20..52]),
                derived_key: data[52..84].try_into().unwrap(),
                enumeration_index: u64::from_be_bytes(data[84..92].try_into().unwrap()),
                initial_value: U256::from(&data[92..124]),
                final_value: U256::from(&data[124..156]),
            })
        } else {
            None
        }
    }

    /// compression follows the following algorithm:
    /// 1. if repeated write:
    ///    entry <- enumeration_index || compressed value
    /// 2. if initial write:
    ///    entry <- blake2(bytes32(address), key) || compressed value
    ///
    /// size:
    /// - initial:  max of 65 bytes
    /// - repeated: max of 38 bytes
    /// - before:  156 bytes for each
    pub fn compress(&self) -> Vec<u8> {
        let mut comp_state_diff = match self.enumeration_index {
            0 => self.derived_key.to_vec(),
            enumeration_index if enumeration_index <= (u32::MAX as u64) => {
                (self.enumeration_index as u32).to_be_bytes().to_vec()
            }
            enumeration_index => panic!("enumeration_index is too large: {}", enumeration_index),
        };

        comp_state_diff.extend(compress_with_best_strategy(
            self.initial_value,
            self.final_value,
        ));

        comp_state_diff
    }

    pub fn is_write_initial(&self) -> bool {
        self.enumeration_index == 0
    }
}

/// Compresses a vector of state diff records according to the following:
/// num_initial writes (u16) || compressed initial writes || compressed repeated writes
pub fn compress_state_diffs(mut state_diffs: Vec<StateDiffRecord>) -> Vec<u8> {
    let mut res = vec![];

    // IMPORTANT: Sorting here is determined by the order expected in the circuits.
    state_diffs.sort_by_key(|rec| (rec.address, rec.key));

    let (initial_writes, repeated_writes): (Vec<_>, Vec<_>) = state_diffs
        .iter()
        .partition(|rec| rec.enumeration_index == 0);

    // The pubdata format encodes the initial-writes count as a u16. A bare
    // `as u16` would silently truncate above 65_535 and produce malformed
    // pubdata; fail loudly instead. Unreachable under current blob size limits,
    // but reachable with larger-blob DA.
    let num_initial_writes = u16::try_from(initial_writes.len())
        .expect("number of initial writes exceeds u16::MAX and cannot be encoded in pubdata");
    res.extend(num_initial_writes.to_be_bytes());
    for state_diff in initial_writes {
        res.extend(state_diff.compress());
    }

    for state_diff in repeated_writes {
        res.extend(state_diff.compress());
    }

    prepend_header(res)
}

/// Adds the header to the beginning of the compressed state diffs so it can be used as part of the overall
/// pubdata. Need to prepend: compression version || number of compressed state diffs || number of bytes used for
/// enumeration index.
fn prepend_header(compressed_state_diffs: Vec<u8>) -> Vec<u8> {
    let mut res = vec![0u8; 5];
    res[0] = COMPRESSION_VERSION_NUMBER;

    // The compressed length is packed into a 3-byte (u24) field. A bare `as u32`
    // truncated to `[1..4]` would silently drop the high byte above 2^24 bytes and
    // produce malformed pubdata; fail loudly instead. Unreachable under current
    // blob size limits.
    let compressed_len = u32::try_from(compressed_state_diffs.len())
        .ok()
        .filter(|&len| len <= 0x00FF_FFFF)
        .expect("compressed state diffs length exceeds the 3-byte pubdata length field");
    res[1..4].copy_from_slice(&compressed_len.to_be_bytes()[1..4]);

    res[4] = BYTES_PER_ENUMERATION_INDEX;

    res.extend(compressed_state_diffs);

    res.to_vec()
}

/// Struct for storing tree writes in DB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TreeWrite {
    /// `address` part of storage key.
    pub address: Address,
    /// `key` part of storage key.
    pub key: H256,
    /// Value written.
    pub value: H256,
    /// Leaf index of the slot.
    pub leaf_index: u64,
}

impl Serialize for TreeWrite {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut tup = serializer.serialize_tuple(4)?;
        tup.serialize_element(&self.address.0)?;
        tup.serialize_element(&self.key.0)?;
        tup.serialize_element(&self.value.0)?;
        tup.serialize_element(&self.leaf_index)?;
        tup.end()
    }
}

impl<'de> Deserialize<'de> for TreeWrite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TreeWriteVisitor;

        impl<'de> de::Visitor<'de> for TreeWriteVisitor {
            type Value = TreeWrite;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a tuple of 4 elements")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<TreeWrite, V::Error>
            where
                V: de::SeqAccess<'de>,
            {
                let address: [u8; 20] = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let key: [u8; 32] = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let value: [u8; 32] = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let leaf_index = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(3, &self))?;

                Ok(TreeWrite {
                    address: Address::from_slice(&address),
                    key: H256::from_slice(&key),
                    value: H256::from_slice(&value),
                    leaf_index,
                })
            }
        }

        deserializer.deserialize_tuple(4, TreeWriteVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compresses_small_initial_write_set() {
        let out = compress_state_diffs(vec![StateDiffRecord::default(); 3]);
        assert!(!out.is_empty());
        assert_eq!(out[0], COMPRESSION_VERSION_NUMBER);
    }

    #[test]
    #[should_panic(expected = "exceeds u16::MAX")]
    fn rejects_more_than_u16_initial_writes() {
        // > u16::MAX initial writes (enumeration_index == 0) cannot be encoded in
        // the pubdata format; must fail loudly rather than silently truncate.
        let diffs = vec![StateDiffRecord::default(); u16::MAX as usize + 1];
        let _ = compress_state_diffs(diffs);
    }
}
