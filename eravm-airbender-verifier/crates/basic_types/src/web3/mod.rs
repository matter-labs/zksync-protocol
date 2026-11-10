//! Selected Web3 types copied from the `web3` crate.
//!
//! The majority of the code is copied verbatim from the `web3` crate 0.19.0,
//! https://github.com/tomusdrw/rust-web3, licensed under the MIT open-source license.
//!
//! TODO(eravm-airbender-verifier): Reintroduce additional web3 types only when
//! a concrete in-tree consumer requires them.

use std::fmt;

use ethabi::ethereum_types::Address;
use serde::{
    de::{Error, Unexpected, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

use crate::{H160, H256, U256, U64};

pub mod contract;

pub type Index = U64;

// `Signature`, `keccak256`: from `web3::signing`

/// A struct that represents the components of a secp256k1 signature.
#[derive(Debug)]
pub struct Signature {
    /// V component in Electrum format with chain-id replay protection.
    pub v: u64,
    /// R component of the signature.
    pub r: H256,
    /// S component of the signature.
    pub s: H256,
}

/// Compute the Keccak-256 hash of input bytes.
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    <airbender_crypto::sha3::Keccak256 as airbender_crypto::MiniDigest>::digest(bytes)
}

/// Hashes concatenation of the two provided hashes using `keccak256`.
pub fn keccak256_concat(hash1: H256, hash2: H256) -> H256 {
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(hash1.as_bytes());
    bytes[32..].copy_from_slice(hash2.as_bytes());

    H256(keccak256(&bytes))
}

// `Bytes`: from `web3::types::bytes`

/// Raw bytes wrapper.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct Bytes(pub Vec<u8>);

impl<T: Into<Vec<u8>>> From<T> for Bytes {
    fn from(data: T) -> Self {
        Bytes(data.into())
    }
}

impl Serialize for Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            let mut serialized = "0x".to_owned();
            serialized.push_str(&hex::encode(&self.0));
            serializer.serialize_str(serialized.as_ref())
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'a> Deserialize<'a> for Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'a>,
    {
        if deserializer.is_human_readable() {
            deserializer.deserialize_identifier(BytesVisitor)
        } else {
            Vec::<u8>::deserialize(deserializer).map(Bytes)
        }
    }
}

impl fmt::Debug for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let serialized = format!("0x{}", hex::encode(&self.0));
        f.debug_tuple("Bytes").field(&serialized).finish()
    }
}

struct BytesVisitor;

impl<'a> Visitor<'a> for BytesVisitor {
    type Value = Bytes;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a 0x-prefixed hex-encoded vector of bytes")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        if let Some(value) = value.strip_prefix("0x") {
            let bytes =
                hex::decode(value).map_err(|e| Error::custom(format!("Invalid hex: {e}")))?;
            Ok(Bytes(bytes))
        } else {
            Err(Error::invalid_value(Unexpected::Str(value), &"0x prefix"))
        }
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: Error,
    {
        self.visit_str(value.as_ref())
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(Bytes(value.to_vec()))
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: Error,
    {
        Ok(Bytes(value))
    }
}

// `AccessList`, `AccessListItem`: from `web3::types::transaction`

/// Access list.
pub type AccessList = Vec<AccessListItem>;

/// Access list item.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessListItem {
    /// Accessed address.
    pub address: Address,
    /// Accessed storage keys.
    pub storage_keys: Vec<H256>,
}

// `Log`: from `web3::types::log`

/// A log produced by a transaction.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Log {
    /// H160.
    pub address: H160,
    /// Topics.
    pub topics: Vec<H256>,
    /// Data.
    pub data: Bytes,
    /// Block Hash.
    #[serde(rename = "blockHash")]
    pub block_hash: Option<H256>,
    /// Block Number.
    #[serde(rename = "blockNumber")]
    pub block_number: Option<U64>,
    /// Transaction Hash.
    #[serde(rename = "transactionHash")]
    pub transaction_hash: Option<H256>,
    /// Transaction Index.
    #[serde(rename = "transactionIndex")]
    pub transaction_index: Option<Index>,
    /// Log Index in Block.
    #[serde(rename = "logIndex")]
    pub log_index: Option<U256>,
    /// Log Index in Transaction.
    #[serde(rename = "transactionLogIndex")]
    pub transaction_log_index: Option<U256>,
    /// Log Type.
    #[serde(rename = "logType")]
    pub log_type: Option<String>,
    /// Removed.
    pub removed: Option<bool>,
    /// L2 block timestamp.
    #[serde(rename = "blockTimestamp")]
    pub block_timestamp: Option<U64>,
}

impl Log {
    /// Returns true if the log has been removed.
    pub fn is_removed(&self) -> bool {
        if let Some(val_removed) = self.removed {
            return val_removed;
        }
        if let Some(val_log_type) = &self.log_type {
            if val_log_type == "removed" {
                return true;
            }
        }
        false
    }
}

impl From<Log> for ethabi::RawLog {
    fn from(log: Log) -> Self {
        ethabi::RawLog {
            topics: log.topics,
            data: log.data.0,
        }
    }
}
