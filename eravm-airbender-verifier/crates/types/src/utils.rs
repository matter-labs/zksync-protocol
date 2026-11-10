use std::fmt;

use chrono::{DateTime, TimeZone, Utc};
use zksync_basic_types::{ethabi, Address, H256};
use zksync_system_constants::L2_NATIVE_TOKEN_VAULT_ADDRESS;

use crate::{
    address_to_h256, u256_to_h256, web3::keccak256, AccountTreeId, StorageKey,
    L2_BASE_TOKEN_ADDRESS, U256,
};

// Nonces are composed as `2^128 * deployment_nonce + tx_nonce`.
// Keeping increments local avoids pulling in contract-loader code.
pub const TX_NONCE_INCREMENT: U256 = U256([1, 0, 0, 0]);
pub const DEPLOYMENT_NONCE_INCREMENT: U256 = U256([0, 0, 1, 0]);

/// Displays a Unix timestamp (seconds since epoch) in human-readable form. Useful for logging.
pub fn display_timestamp(timestamp: u64) -> impl fmt::Display {
    enum DisplayedTimestamp {
        Parsed(DateTime<Utc>),
        Raw(u64),
    }

    impl fmt::Display for DisplayedTimestamp {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Parsed(timestamp) => fmt::Display::fmt(timestamp, formatter),
                Self::Raw(raw) => write!(formatter, "(raw: {raw})"),
            }
        }
    }

    let parsed = i64::try_from(timestamp).ok();
    let parsed = parsed.and_then(|ts| Utc.timestamp_opt(ts, 0).single());
    parsed.map_or(
        DisplayedTimestamp::Raw(timestamp),
        DisplayedTimestamp::Parsed,
    )
}

/// Transforms the *full* account nonce into an *account* nonce.
///
/// Full nonce is a composite one: it includes both account nonce (number of transactions
/// initiated by the account) and deployer nonce (number of smart contracts deployed by the
/// account).
/// For most public things, we need the account nonce.
pub fn decompose_full_nonce(full_nonce: U256) -> (U256, U256) {
    (
        full_nonce % DEPLOYMENT_NONCE_INCREMENT,
        full_nonce / DEPLOYMENT_NONCE_INCREMENT,
    )
}

/// Converts tx nonce + deploy nonce into a full nonce.
pub fn nonces_to_full_nonce(tx_nonce: U256, deploy_nonce: U256) -> U256 {
    DEPLOYMENT_NONCE_INCREMENT * deploy_nonce + tx_nonce
}

pub fn key_for_eth_balance(address: &Address) -> H256 {
    let address_h256 = address_to_h256(address);

    let bytes = [address_h256.as_bytes(), &[0; 32]].concat();
    keccak256(&bytes).into()
}

/// Create a `key` part of `StorageKey` to access the balance from ERC20 contract balances
fn key_for_erc20_balance(address: &Address) -> H256 {
    let address_h256 = address_to_h256(address);

    // 20 bytes address first gets aligned to 32 bytes with index of `balanceOf` storage slot
    // of default ERC20 contract and to then to 64 bytes.
    let slot_index = H256::from_low_u64_be(51);
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(address_h256.as_bytes());
    bytes[32..].copy_from_slice(slot_index.as_bytes());
    H256(keccak256(&bytes))
}

/// Create a storage key to access the balance from supported token contract balances
pub fn storage_key_for_standard_token_balance(
    token_contract: AccountTreeId,
    address: &Address,
) -> StorageKey {
    // We have different implementation of the standard ERC20 contract and native
    // eth contract. The key for the balance is different for each.
    let key = if token_contract.address() == &L2_BASE_TOKEN_ADDRESS {
        key_for_eth_balance(address)
    } else {
        key_for_erc20_balance(address)
    };

    StorageKey::new(token_contract, key)
}

pub fn storage_key_for_eth_balance(address: &Address) -> StorageKey {
    storage_key_for_standard_token_balance(AccountTreeId::new(L2_BASE_TOKEN_ADDRESS), address)
}

/// Pre-calculates the address of the to-be-deployed EraVM contract (via CREATE, not CREATE2).
pub fn deployed_address_create(sender: Address, deploy_nonce: U256) -> Address {
    let prefix_bytes = keccak256("zksyncCreate".as_bytes());
    let address_bytes = address_to_h256(&sender);
    let nonce_bytes = u256_to_h256(deploy_nonce);

    let mut bytes = [0u8; 96];
    bytes[..32].copy_from_slice(&prefix_bytes);
    bytes[32..64].copy_from_slice(address_bytes.as_bytes());
    bytes[64..].copy_from_slice(nonce_bytes.as_bytes());

    Address::from_slice(&keccak256(&bytes)[12..])
}

/// Pre-calculates the address of the EVM contract created using a deployment transaction.
pub fn deployed_address_evm_create(sender: Address, tx_nonce: U256) -> Address {
    let mut stream = rlp::RlpStream::new();
    stream
        .begin_unbounded_list()
        .append(&sender)
        .append(&tx_nonce)
        .finalize_unbounded_list();
    Address::from_slice(&keccak256(&stream.out())[12..])
}

pub fn encode_ntv_asset_id(l1_chain_id: U256, addr: Address) -> H256 {
    let encoded_data = ethabi::encode(&[
        ethabi::Token::Uint(l1_chain_id),
        ethabi::Token::Address(L2_NATIVE_TOKEN_VAULT_ADDRESS),
        ethabi::Token::Address(addr),
    ]);

    H256(keccak256(&encoded_data))
}
