//! Minimal contract models used by the verifier-focused extraction.
//!
//! TODO(eravm-airbender-verifier): Restore artifact-backed contract-loading helpers if the
//! extraction needs filesystem ABI / bytecode resolution again.

use serde::{Deserialize, Serialize};
use zksync_basic_types::{bytecode::BytecodeHash, H256};

mod serde_bytecode;

/// Hash of code and code which consists of 32-byte words.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemContractCode {
    #[serde(with = "serde_bytecode")]
    pub code: Vec<u8>,
    pub hash: H256,
}

impl SystemContractCode {
    /// Constructs system-contract code and computes its canonical bytecode hash.
    pub fn from_code(code: Vec<u8>) -> Self {
        let hash = BytecodeHash::for_bytecode(&code).value();
        Self { code, hash }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseSystemContracts {
    pub bootloader: SystemContractCode,
    pub default_aa: SystemContractCode,
    pub evm_emulator: Option<SystemContractCode>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BaseSystemContractsHashes {
    pub bootloader: H256,
    pub default_aa: H256,
    /// Optional for backward compatibility reasons. Having a hash present does not imply
    /// that EVM emulation is enabled for the network.
    pub evm_emulator: Option<H256>,
}

impl PartialEq for BaseSystemContracts {
    fn eq(&self, other: &Self) -> bool {
        self.bootloader.hash == other.bootloader.hash
            && self.default_aa.hash == other.default_aa.hash
            && self.evm_emulator.as_ref().map(|contract| contract.hash)
                == other.evm_emulator.as_ref().map(|contract| contract.hash)
    }
}

impl Eq for BaseSystemContracts {}

impl BaseSystemContracts {
    pub fn hashes(&self) -> BaseSystemContractsHashes {
        BaseSystemContractsHashes {
            bootloader: self.bootloader.hash,
            default_aa: self.default_aa.hash,
            evm_emulator: self.evm_emulator.as_ref().map(|contract| contract.hash),
        }
    }
}
