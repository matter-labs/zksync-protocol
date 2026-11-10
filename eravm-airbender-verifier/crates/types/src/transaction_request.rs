use std::convert::{TryFrom, TryInto};

use rlp::{DecoderError, Rlp, RlpStream};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zksync_system_constants::{DEFAULT_L2_TX_GAS_PER_PUBDATA_BYTE, MAX_ENCODED_TX_SIZE};

use super::{EIP_1559_TX_TYPE, EIP_2930_TX_TYPE, EIP_712_TX_TYPE};
use crate::{
    bytecode::{validate_bytecode, BytecodeHash, InvalidBytecodeError},
    fee::Fee,
    l1::L1Tx,
    l2::{L2Tx, TransactionType},
    u256_to_h256,
    web3::{keccak256, keccak256_concat, AccessList, Bytes},
    Address, EIP712TypedStructure, Eip712Domain, L1TxCommonData, L2ChainId, Nonce,
    PackedEthSignature, StructBuilder, H256, LEGACY_TX_TYPE, U256, U64,
};

/// Call contract request (eth_call / eth_estimateGas)
///
/// When using this for `eth_estimateGas`, all the fields
/// are optional. However, for usage in `eth_call` the
/// `to` field must be provided.
#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallRequest {
    /// Sender address (None for arbitrary address)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Address>,
    /// To address (None allowed for eth_estimateGas)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<Address>,
    /// Supplied gas (None for sensible default)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas: Option<U256>,
    /// Gas price (None for sensible default)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_price: Option<U256>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<U256>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<U256>,
    /// Transferred value (None for no transfer)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<U256>,
    /// Data (None for empty data)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Bytes>,
    /// Input (None for empty)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Bytes>,
    /// Nonce
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<U256>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub transaction_type: Option<U64>,
    /// Access list
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_list: Option<AccessList>,
    /// EIP712 meta
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eip712_meta: Option<Eip712Meta>,
}

/// While some default parameters are usually provided for the `eth_call` methods,
/// sometimes users may want to override those.
pub struct CallOverrides {
    pub enforced_base_fee: Option<u64>,
}

impl CallRequest {
    /// Function to return a builder for a Call Request
    pub fn builder() -> CallRequestBuilder {
        CallRequestBuilder::default()
    }

    pub fn get_call_overrides(&self) -> Result<CallOverrides, SerializationTransactionError> {
        let provided_gas_price = self.max_fee_per_gas.or(self.gas_price);
        let enforced_base_fee = if let Some(provided_gas_price) = provided_gas_price {
            Some(
                provided_gas_price
                    .try_into()
                    .map_err(|_| SerializationTransactionError::MaxFeePerGasNotU64)?,
            )
        } else {
            None
        };

        Ok(CallOverrides { enforced_base_fee })
    }
}

/// Call Request Builder
#[derive(Clone, Debug, Default)]
pub struct CallRequestBuilder {
    call_request: CallRequest,
}

impl CallRequestBuilder {
    /// Set sender address (None for arbitrary address)
    pub fn from(mut self, from: Address) -> Self {
        self.call_request.from = Some(from);
        self
    }

    /// Set to address (None allowed for eth_estimateGas)
    pub fn to(mut self, to: Option<Address>) -> Self {
        self.call_request.to = to;
        self
    }

    /// Set supplied gas (None for sensible default)
    pub fn gas(mut self, gas: U256) -> Self {
        self.call_request.gas = Some(gas);
        self
    }

    /// Set transferred, value (None for no transfer)
    pub fn gas_price(mut self, gas_price: U256) -> Self {
        self.call_request.gas_price = Some(gas_price);
        self
    }

    pub fn max_fee_per_gas(mut self, max_fee_per_gas: U256) -> Self {
        self.call_request.max_fee_per_gas = Some(max_fee_per_gas);
        self
    }

    pub fn max_priority_fee_per_gas(mut self, max_priority_fee_per_gas: U256) -> Self {
        self.call_request.max_priority_fee_per_gas = Some(max_priority_fee_per_gas);
        self
    }

    /// Set transferred, value (None for no transfer)
    pub fn value(mut self, value: U256) -> Self {
        self.call_request.value = Some(value);
        self
    }

    /// Set data (None for empty data)
    pub fn data(mut self, data: Bytes) -> Self {
        self.call_request.data = Some(data);
        self
    }

    pub fn input(mut self, input: Bytes) -> Self {
        self.call_request.input = Some(input);
        self
    }

    /// Set transaction type, Some(1) for AccessList transaction, None for Legacy
    pub fn transaction_type(mut self, transaction_type: U64) -> Self {
        self.call_request.transaction_type = Some(transaction_type);
        self
    }

    /// Set access list
    pub fn access_list(mut self, access_list: AccessList) -> Self {
        self.call_request.access_list = Some(access_list);
        self
    }

    /// Set meta
    pub fn eip712_meta(mut self, eip712_meta: Eip712Meta) -> Self {
        self.call_request.eip712_meta = Some(eip712_meta);
        self
    }

    /// build the Call Request
    pub fn build(&self) -> CallRequest {
        self.call_request.clone()
    }
}

#[derive(Debug, Error)]
pub enum SerializationTransactionError {
    #[error("transaction type is not supported")]
    UnknownTransactionFormat,
    #[error("toAddressIsNull")]
    ToAddressIsNull,
    #[error("incompleteSignature")]
    IncompleteSignature,
    #[error("fromAddressIsNull")]
    FromAddressIsNull,
    #[error("priceLimitToLow")]
    PriceLimitToLow,
    #[error("wrongToken")]
    WrongToken,
    #[error("decodeRlpError {0}")]
    DecodeRlpError(#[from] DecoderError),
    #[error("invalid signature")]
    MalformedSignature,
    #[error("wrong chain id {}", .0.unwrap_or_default())]
    WrongChainId(Option<u64>),
    #[error("malformed paymaster params")]
    MalforedPaymasterParams,
    #[error("factory dependency #{0} is invalid: {1}")]
    InvalidFactoryDependencies(usize, InvalidBytecodeError),
    #[error("access lists are not supported")]
    AccessListsNotSupported,
    #[error("nonce has max value")]
    TooBigNonce,

    /// Sanity checks to avoid extremely big numbers specified
    /// to gas and pubdata price.
    #[error("max fee per gas higher than 2^64-1")]
    MaxFeePerGasNotU64,
    #[error("max fee per pubdata byte higher than 2^64-1")]
    MaxFeePerPubdataByteNotU64,
    #[error("max priority fee per gas higher than 2^64-1")]
    MaxPriorityFeePerGasNotU64,

    /// OversizedData is returned if the raw tx size is greater
    /// than some meaningful limit a user might use. This is not a consensus error
    /// making the transaction invalid, rather a DOS protection.
    #[error("oversized data. max: {0}; actual: {1}")]
    OversizedData(usize, usize),
    #[error("gas per pub data limit is zero")]
    GasPerPubDataLimitZero,
}

#[derive(Clone, Debug, PartialEq, Default)]
/// Description of a Transaction, pending or in the chain.
pub struct TransactionRequest {
    /// Nonce
    pub nonce: U256,
    pub from: Option<Address>,
    /// Recipient (None when contract creation)
    pub to: Option<Address>,
    /// Transferred value
    pub value: U256,
    /// Gas Price
    pub gas_price: U256,
    /// Gas amount
    pub gas: U256,
    /// EIP-1559 part of gas price that goes to miners
    pub max_priority_fee_per_gas: Option<U256>,
    /// Input data
    pub input: Bytes,
    /// ECDSA recovery id
    pub v: Option<U64>,
    /// ECDSA signature r, 32 bytes
    pub r: Option<U256>,
    /// ECDSA signature s, 32 bytes
    pub s: Option<U256>,
    /// Raw transaction data
    pub raw: Option<Bytes>,
    /// Transaction type, Some(1) for AccessList transaction, None for Legacy
    pub transaction_type: Option<U64>,
    /// Access list
    pub access_list: Option<AccessList>,
    pub eip712_meta: Option<Eip712Meta>,
    /// Chain ID
    pub chain_id: Option<u64>,
}

#[derive(Default, Serialize, Deserialize, Clone, PartialEq, Debug, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PaymasterParams {
    pub paymaster: Address,
    pub paymaster_input: Vec<u8>,
}

impl PaymasterParams {
    fn from_vector(value: Vec<Vec<u8>>) -> Result<Option<Self>, SerializationTransactionError> {
        if value.is_empty() {
            return Ok(None);
        }
        if value.len() != 2 || value[0].len() != 20 {
            return Err(SerializationTransactionError::MalforedPaymasterParams);
        }

        let result = Some(Self {
            paymaster: Address::from_slice(&value[0]),
            paymaster_input: value[1].clone(),
        });

        Ok(result)
    }
}

#[derive(Default, Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Eip712Meta {
    pub gas_per_pubdata: U256,
    #[serde(default)]
    pub factory_deps: Vec<Vec<u8>>,
    pub custom_signature: Option<Vec<u8>>,
    pub paymaster_params: Option<PaymasterParams>,
}

impl Eip712Meta {
    pub fn rlp_append(&self, rlp: &mut RlpStream) {
        rlp.append(&self.gas_per_pubdata);
        rlp.begin_list(self.factory_deps.len());
        for dep in &self.factory_deps {
            rlp.append(&dep.as_slice());
        }

        rlp_opt(rlp, &self.custom_signature);

        if let Some(paymaster_params) = &self.paymaster_params {
            rlp.begin_list(2);
            rlp.append(&paymaster_params.paymaster.as_bytes());
            rlp.append(&paymaster_params.paymaster_input);
        } else {
            rlp.begin_list(0);
        }
    }
}

fn build_transaction_request_structure<BUILDER: StructBuilder>(
    tx: &TransactionRequest,
    builder: &mut BUILDER,
    factory_dep_hashes: &[H256],
) {
    let meta = tx
        .eip712_meta
        .as_ref()
        .expect("We can sign transaction only with meta");
    builder.add_member(
        "txType",
        &tx.transaction_type
            .map(|x| U256::from(x.as_u64()))
            .unwrap_or_else(|| U256::from(EIP_712_TX_TYPE)),
    );
    builder.add_member(
        "from",
        &U256::from(
            tx.from
                .expect("We can only sign transactions with known sender")
                .as_bytes(),
        ),
    );
    builder.add_member("to", &U256::from(tx.to.unwrap_or_default().as_bytes()));
    builder.add_member("gasLimit", &tx.gas);
    builder.add_member("gasPerPubdataByteLimit", &meta.gas_per_pubdata);
    builder.add_member("maxFeePerGas", &tx.gas_price);
    builder.add_member(
        "maxPriorityFeePerGas",
        &tx.max_priority_fee_per_gas.unwrap_or(tx.gas_price),
    );
    builder.add_member(
        "paymaster",
        &U256::from(tx.get_paymaster().unwrap_or_default().as_bytes()),
    );
    builder.add_member("nonce", &tx.nonce);
    builder.add_member("value", &tx.value);
    builder.add_member("data", &tx.input.0.as_slice());
    builder.add_member("factoryDeps", &factory_dep_hashes);
    builder.add_member(
        "paymasterInput",
        &tx.get_paymaster_input().unwrap_or_default().as_slice(),
    );
}

impl EIP712TypedStructure for TransactionRequest {
    const TYPE_NAME: &'static str = "Transaction";

    fn build_structure<BUILDER: StructBuilder>(&self, builder: &mut BUILDER) {
        let factory_dep_hashes: Vec<_> = self
            .get_factory_deps()
            .into_iter()
            .map(|dep| BytecodeHash::for_bytecode(&dep).value())
            .collect();
        build_transaction_request_structure(self, builder, &factory_dep_hashes);
    }
}

struct TransactionRequestWithPrecomputedFactoryDeps<'a> {
    tx: &'a TransactionRequest,
    factory_dep_hashes: &'a [H256],
}

impl EIP712TypedStructure for TransactionRequestWithPrecomputedFactoryDeps<'_> {
    const TYPE_NAME: &'static str = "Transaction";

    fn build_structure<BUILDER: StructBuilder>(&self, builder: &mut BUILDER) {
        build_transaction_request_structure(self.tx, builder, self.factory_dep_hashes);
    }
}

impl TransactionRequest {
    pub fn get_custom_signature(&self) -> Option<Vec<u8>> {
        self.eip712_meta.as_ref()?.custom_signature.clone()
    }

    pub fn get_paymaster(&self) -> Option<Address> {
        Some(
            self.eip712_meta
                .as_ref()?
                .paymaster_params
                .as_ref()?
                .paymaster,
        )
    }

    pub fn get_paymaster_input(&self) -> Option<Vec<u8>> {
        Some(
            self.eip712_meta
                .as_ref()?
                .paymaster_params
                .as_ref()?
                .paymaster_input
                .clone(),
        )
    }

    pub fn get_factory_deps(&self) -> Vec<Vec<u8>> {
        self.eip712_meta
            .as_ref()
            .map(|meta| meta.factory_deps.clone())
            .unwrap_or_default()
    }

    // returns packed eth signature if it is present
    pub fn get_packed_signature(
        &self,
    ) -> Result<PackedEthSignature, SerializationTransactionError> {
        let packed_v = self
            .v
            .ok_or(SerializationTransactionError::IncompleteSignature)?
            .as_u64();
        let v = if !self.is_legacy_tx() {
            packed_v
                .try_into()
                .map_err(|_| SerializationTransactionError::MalformedSignature)?
        } else {
            let (v, _) = PackedEthSignature::unpack_v(packed_v)
                .map_err(|_| SerializationTransactionError::MalformedSignature)?;
            v
        };

        let packed_eth_signature = PackedEthSignature::from_rsv(
            &u256_to_h256(
                self.r
                    .ok_or(SerializationTransactionError::IncompleteSignature)?,
            ),
            &u256_to_h256(
                self.s
                    .ok_or(SerializationTransactionError::IncompleteSignature)?,
            ),
            v,
        );

        Ok(packed_eth_signature)
    }

    pub fn get_signature(&self) -> Result<Vec<u8>, SerializationTransactionError> {
        let custom_signature = self.get_custom_signature();
        if let Some(custom_sig) = custom_signature {
            // TODO (SMA-1584): Support empty signatures for accounts.
            if !custom_sig.is_empty() {
                // There was a custom signature supplied, it overrides
                // the v/r/s signature
                return Ok(custom_sig);
            }
        }

        let packed_eth_signature = self.get_packed_signature()?;

        Ok(packed_eth_signature.serialize_packed().to_vec())
    }

    pub fn get_signed_bytes(
        &self,
        signature: &PackedEthSignature,
    ) -> Result<Vec<u8>, SerializationTransactionError> {
        let mut rlp = RlpStream::new();
        self.rlp(&mut rlp, Some(signature))?;
        let mut data = rlp.out().to_vec();
        if let Some(tx_type) = self.transaction_type {
            data.insert(0, tx_type.as_u64() as u8);
        }
        Ok(data)
    }

    pub fn is_legacy_tx(&self) -> bool {
        self.transaction_type.is_none() || self.transaction_type == Some(LEGACY_TX_TYPE.into())
    }

    /// Encodes `TransactionRequest` to RLP.
    /// It may fail if `chain_id` is `None` while required.
    pub fn get_rlp(&self) -> Result<Vec<u8>, SerializationTransactionError> {
        let mut rlp_stream = RlpStream::new();
        self.rlp(&mut rlp_stream, None)?;
        Ok(rlp_stream.as_raw().into())
    }

    /// Encodes `TransactionRequest` to RLP.
    /// It may fail if `chain_id` is `None` while required.
    pub fn rlp(
        &self,
        rlp: &mut RlpStream,
        signature: Option<&PackedEthSignature>,
    ) -> Result<(), SerializationTransactionError> {
        rlp.begin_unbounded_list();

        match self.transaction_type {
            // EIP-2930 (0x01)
            Some(x) if x == EIP_2930_TX_TYPE.into() => {
                rlp.append(
                    &self
                        .chain_id
                        .ok_or(SerializationTransactionError::WrongChainId(None))?,
                );
                rlp.append(&self.nonce);
                rlp.append(&self.gas_price);
                rlp.append(&self.gas);
                rlp_opt(rlp, &self.to);
                rlp.append(&self.value);
                rlp.append(&self.input.0);
                access_list_rlp(rlp, &self.access_list);
            }
            // EIP-1559 (0x02)
            Some(x) if x == EIP_1559_TX_TYPE.into() => {
                rlp.append(
                    &self
                        .chain_id
                        .ok_or(SerializationTransactionError::WrongChainId(None))?,
                );
                rlp.append(&self.nonce);
                rlp_opt(rlp, &self.max_priority_fee_per_gas);
                rlp.append(&self.gas_price);
                rlp.append(&self.gas);
                rlp_opt(rlp, &self.to);
                rlp.append(&self.value);
                rlp.append(&self.input.0);
                access_list_rlp(rlp, &self.access_list);
            }
            // EIP-712
            Some(x) if x == EIP_712_TX_TYPE.into() => {
                rlp.append(&self.nonce);
                rlp_opt(rlp, &self.max_priority_fee_per_gas);
                rlp.append(&self.gas_price);
                rlp.append(&self.gas);
                rlp_opt(rlp, &self.to);
                rlp.append(&self.value);
                rlp.append(&self.input.0);
            }
            Some(x) if x == LEGACY_TX_TYPE.into() => {
                rlp.append(&self.nonce);
                rlp.append(&self.gas_price);
                rlp.append(&self.gas);
                rlp_opt(rlp, &self.to);
                rlp.append(&self.value);
                rlp.append(&self.input.0);
            }
            // Legacy (None)
            None => {
                rlp.append(&self.nonce);
                rlp.append(&self.gas_price);
                rlp.append(&self.gas);
                rlp_opt(rlp, &self.to);
                rlp.append(&self.value);
                rlp.append(&self.input.0);
            }
            Some(_) => unreachable!("Unknown tx type"),
        }

        match (signature, self.chain_id, self.is_legacy_tx()) {
            (Some(sig), Some(chain_id), true) => {
                rlp.append(&sig.v_with_chain_id(chain_id));
                rlp.append(&U256::from_big_endian(sig.r()));
                rlp.append(&U256::from_big_endian(sig.s()));
            }
            (None, Some(chain_id), true) => {
                rlp.append(&chain_id);
                rlp.append(&0u8);
                rlp.append(&0u8);
            }
            (Some(sig), _, _) => {
                rlp.append(&sig.v());
                rlp.append(&U256::from_big_endian(sig.r()));
                rlp.append(&U256::from_big_endian(sig.s()));
            }
            (None, _, _) => {}
        }

        if self.is_eip712_tx() {
            rlp.append(
                &self
                    .chain_id
                    .ok_or(SerializationTransactionError::WrongChainId(None))?,
            );
            rlp_opt(rlp, &self.from);
            if let Some(meta) = &self.eip712_meta {
                meta.rlp_append(rlp);
            }
        }

        rlp.finalize_unbounded_list();
        Ok(())
    }

    pub fn set_signature(&mut self, signature: &PackedEthSignature) {
        self.r = Some(U256::from_big_endian(signature.r()));
        self.s = Some(U256::from_big_endian(signature.s()));
        self.v = Some(signature.v().into())
    }

    fn decode_standard_fields(rlp: &Rlp, offset: usize) -> Result<Self, DecoderError> {
        Ok(Self {
            nonce: rlp.val_at(offset)?,
            gas_price: rlp.val_at(offset + 1)?,
            gas: rlp.val_at(offset + 2)?,
            to: rlp.val_at(offset + 3).ok(),
            value: rlp.val_at(offset + 4)?,
            input: Bytes(rlp.val_at(offset + 5)?),
            ..Default::default()
        })
    }

    fn decode_eip1559_fields(rlp: &Rlp, offset: usize) -> Result<Self, DecoderError> {
        Ok(Self {
            nonce: rlp.val_at(offset)?,
            max_priority_fee_per_gas: rlp.val_at(offset + 1).ok(),
            gas_price: rlp.val_at(offset + 2)?,
            gas: rlp.val_at(offset + 3)?,
            to: rlp.val_at(offset + 4).ok(),
            value: rlp.val_at(offset + 5)?,
            input: Bytes(rlp.val_at(offset + 6)?),
            ..Default::default()
        })
    }

    pub fn is_eip712_tx(&self) -> bool {
        Some(EIP_712_TX_TYPE.into()) == self.transaction_type
    }

    pub fn from_bytes_unverified(
        bytes: &[u8],
    ) -> Result<(Self, H256), SerializationTransactionError> {
        let rlp;
        let mut tx = match bytes.first() {
            Some(x) if *x >= 0x80 => {
                rlp = Rlp::new(bytes);
                if rlp.item_count()? != 9 {
                    return Err(DecoderError::RlpIncorrectListLen.into());
                }
                let v = rlp.val_at(6)?;
                Self {
                    // For legacy transactions `chain_id` is optional.
                    chain_id: PackedEthSignature::unpack_v(v)
                        .map_err(|_| SerializationTransactionError::MalformedSignature)?
                        .1,
                    v: Some(rlp.val_at(6)?),
                    r: Some(rlp.val_at(7)?),
                    s: Some(rlp.val_at(8)?),
                    ..Self::decode_standard_fields(&rlp, 0)?
                }
            }
            Some(&EIP_1559_TX_TYPE) => {
                rlp = Rlp::new(&bytes[1..]);
                if rlp.item_count()? != 12 {
                    return Err(DecoderError::RlpIncorrectListLen.into());
                }
                if let Ok(access_list_rlp) = rlp.at(8) {
                    if access_list_rlp.item_count()? > 0 {
                        return Err(SerializationTransactionError::AccessListsNotSupported);
                    }
                }
                Self {
                    chain_id: Some(rlp.val_at(0)?),
                    v: Some(rlp.val_at(9)?),
                    r: Some(rlp.val_at(10)?),
                    s: Some(rlp.val_at(11)?),
                    raw: Some(Bytes(rlp.as_raw().to_vec())),
                    transaction_type: Some(EIP_1559_TX_TYPE.into()),
                    ..Self::decode_eip1559_fields(&rlp, 1)?
                }
            }
            Some(&EIP_712_TX_TYPE) => {
                rlp = Rlp::new(&bytes[1..]);
                if rlp.item_count()? != 16 {
                    return Err(DecoderError::RlpIncorrectListLen.into());
                }
                Self {
                    v: Some(rlp.val_at(7)?),
                    r: Some(rlp.val_at(8)?),
                    s: Some(rlp.val_at(9)?),
                    eip712_meta: Some(Eip712Meta {
                        gas_per_pubdata: rlp.val_at(12)?,
                        factory_deps: rlp.list_at(13)?,
                        custom_signature: rlp.val_at(14).ok(),
                        paymaster_params: if let Ok(params) = rlp.list_at(15) {
                            PaymasterParams::from_vector(params)?
                        } else {
                            None
                        },
                    }),
                    chain_id: Some(rlp.val_at(10)?),
                    transaction_type: Some(EIP_712_TX_TYPE.into()),
                    from: Some(rlp.val_at(11)?),
                    ..Self::decode_eip1559_fields(&rlp, 0)?
                }
            }
            Some(&EIP_2930_TX_TYPE) => {
                return Err(SerializationTransactionError::AccessListsNotSupported)
            }
            _ => return Err(SerializationTransactionError::UnknownTransactionFormat),
        };
        if let Some(meta) = &tx.eip712_meta {
            validate_factory_deps(&meta.factory_deps)?;
        }
        tx.raw = Some(Bytes(bytes.to_vec()));

        let default_signed_message = tx.get_default_signed_message()?;

        if tx.from.is_none() {
            tx.from = tx.recover_default_signer(default_signed_message).ok();
        }

        // `tx.raw` is set, so unwrap is safe here.
        let hash = tx
            .get_tx_hash_with_signed_message(default_signed_message)?
            .unwrap();
        Ok((tx, hash))
    }

    pub fn from_bytes(
        bytes: &[u8],
        chain_id: L2ChainId,
    ) -> Result<(Self, H256), SerializationTransactionError> {
        let (tx, hash) = Self::from_bytes_unverified(bytes)?;
        if tx.chain_id.is_some() && tx.chain_id != Some(chain_id.as_u64()) {
            return Err(SerializationTransactionError::WrongChainId(tx.chain_id));
        }
        Ok((tx, hash))
    }

    pub fn get_default_signed_message(&self) -> Result<H256, SerializationTransactionError> {
        if self.is_eip712_tx() {
            let chain_id = self
                .chain_id
                .ok_or(SerializationTransactionError::WrongChainId(None))?;
            Ok(PackedEthSignature::typed_data_to_signed_bytes(
                &Eip712Domain::new(L2ChainId::try_from(chain_id).unwrap()),
                self,
            ))
        } else {
            let mut data = self.get_rlp()?;
            if let Some(tx_type) = self.transaction_type {
                data.insert(0, tx_type.as_u64() as u8);
            }
            Ok(PackedEthSignature::message_to_signed_bytes(&data))
        }
    }

    pub fn get_default_signed_message_with_factory_dep_hashes(
        &self,
        factory_dep_hashes: &[H256],
    ) -> Result<H256, SerializationTransactionError> {
        if !self.is_eip712_tx() {
            return self.get_default_signed_message();
        }

        let meta = self
            .eip712_meta
            .as_ref()
            .expect("We can sign transaction only with meta");
        if meta.factory_deps.len() != factory_dep_hashes.len() {
            return self.get_default_signed_message();
        }

        let chain_id = self
            .chain_id
            .ok_or(SerializationTransactionError::WrongChainId(None))?;
        let typed_request = TransactionRequestWithPrecomputedFactoryDeps {
            tx: self,
            factory_dep_hashes,
        };
        Ok(PackedEthSignature::typed_data_to_signed_bytes(
            &Eip712Domain::new(L2ChainId::try_from(chain_id).unwrap()),
            &typed_request,
        ))
    }

    fn get_tx_hash_with_signed_message(
        &self,
        signed_message: H256,
    ) -> Result<Option<H256>, SerializationTransactionError> {
        if self.is_eip712_tx() {
            return Ok(Some(keccak256_concat(
                signed_message,
                H256(keccak256(&self.get_signature()?)),
            )));
        }
        Ok(self.raw.as_ref().map(|bytes| H256(keccak256(&bytes.0))))
    }

    pub fn get_tx_hash(&self) -> Result<H256, SerializationTransactionError> {
        Ok(self.get_signed_and_tx_hashes()?.1)
    }

    pub fn get_signed_and_tx_hashes(&self) -> Result<(H256, H256), SerializationTransactionError> {
        let signed_message = self.get_default_signed_message()?;
        if let Some(tx_hash) = self.get_tx_hash_with_signed_message(signed_message)? {
            return Ok((signed_message, tx_hash));
        }
        let signature = self.get_packed_signature()?;
        let tx_hash = H256(keccak256(&self.get_signed_bytes(&signature)?));
        Ok((signed_message, tx_hash))
    }

    pub fn get_signed_and_tx_hashes_with_factory_dep_hashes(
        &self,
        factory_dep_hashes: &[H256],
    ) -> Result<(H256, H256), SerializationTransactionError> {
        let signed_message =
            self.get_default_signed_message_with_factory_dep_hashes(factory_dep_hashes)?;
        if let Some(tx_hash) = self.get_tx_hash_with_signed_message(signed_message)? {
            return Ok((signed_message, tx_hash));
        }
        let signature = self.get_packed_signature()?;
        let tx_hash = H256(keccak256(&self.get_signed_bytes(&signature)?));
        Ok((signed_message, tx_hash))
    }

    fn recover_default_signer(
        &self,
        default_signed_message: H256,
    ) -> Result<Address, SerializationTransactionError> {
        let signature = self.get_signature()?;
        PackedEthSignature::deserialize_packed(&signature)
            .map_err(|_| SerializationTransactionError::MalformedSignature)?
            .signature_recover_signer(&default_signed_message)
            .map_err(|_| SerializationTransactionError::MalformedSignature)?;

        let address = PackedEthSignature::deserialize_packed(&signature)
            .map_err(|_| SerializationTransactionError::MalformedSignature)?
            .signature_recover_signer(&default_signed_message)
            .map_err(|_| SerializationTransactionError::MalformedSignature)?;

        Ok(address)
    }

    fn get_fee_data_checked(&self) -> Result<Fee, SerializationTransactionError> {
        if self.gas_price > u64::MAX.into() {
            return Err(SerializationTransactionError::MaxFeePerGasNotU64);
        }

        let gas_per_pubdata_limit = if let Some(meta) = &self.eip712_meta {
            if meta.gas_per_pubdata > u64::MAX.into() {
                return Err(SerializationTransactionError::MaxFeePerPubdataByteNotU64);
            } else if meta.gas_per_pubdata == U256::zero() {
                return Err(SerializationTransactionError::GasPerPubDataLimitZero);
            }
            meta.gas_per_pubdata
        } else {
            // For transactions that don't support corresponding field, a maximal default value is chosen.
            DEFAULT_L2_TX_GAS_PER_PUBDATA_BYTE.into()
        };

        let max_priority_fee_per_gas = self.max_priority_fee_per_gas.unwrap_or(self.gas_price);
        if max_priority_fee_per_gas > u64::MAX.into() {
            return Err(SerializationTransactionError::MaxPriorityFeePerGasNotU64);
        }

        Ok(Fee {
            gas_limit: self.gas,
            max_fee_per_gas: self.gas_price,
            max_priority_fee_per_gas,
            gas_per_pubdata_limit,
        })
    }

    fn get_nonce_checked(&self) -> Result<Nonce, SerializationTransactionError> {
        if self.nonce <= U256::from(u32::MAX) {
            Ok(Nonce(self.nonce.as_u32()))
        } else {
            Err(SerializationTransactionError::TooBigNonce)
        }
    }
}

impl L2Tx {
    pub(crate) fn from_request_unverified(
        mut value: TransactionRequest,
        allow_no_target: bool,
    ) -> Result<Self, SerializationTransactionError> {
        let fee = value.get_fee_data_checked()?;
        let nonce = value.get_nonce_checked()?;

        let raw_signature = value.get_signature().unwrap_or_default();
        let meta = value.eip712_meta.take().unwrap_or_default();
        validate_factory_deps(&meta.factory_deps)?;

        if value.to.is_none() && (!allow_no_target || value.is_eip712_tx()) {
            return Err(SerializationTransactionError::ToAddressIsNull);
        }

        let mut tx = L2Tx::new(
            value.to,
            value.input.0.clone(),
            nonce,
            fee,
            value.from.unwrap_or_default(),
            value.value,
            meta.factory_deps,
            meta.paymaster_params.unwrap_or_default(),
        );

        tx.common_data.transaction_type = match value.transaction_type.map(|t| t.as_u64() as u8) {
            Some(EIP_712_TX_TYPE) => TransactionType::EIP712Transaction,
            Some(EIP_1559_TX_TYPE) => TransactionType::EIP1559Transaction,
            Some(EIP_2930_TX_TYPE) => TransactionType::EIP2930Transaction,
            _ => TransactionType::LegacyTransaction,
        };
        // For fee calculation we use the same structure, as a result, signature may not be provided
        tx.set_raw_signature(raw_signature);

        if let Some(raw_bytes) = value.raw {
            tx.set_raw_bytes(raw_bytes);
        }
        Ok(tx)
    }

    /// Converts a request into a transaction.
    ///
    /// # Arguments
    ///
    /// - `allow_no_target` enables / disables transactions without target (i.e., `to` field).
    ///   This field can only be absent for EVM deployment transactions.
    pub fn from_request(
        request: TransactionRequest,
        max_tx_size: usize,
        allow_no_target: bool,
    ) -> Result<Self, SerializationTransactionError> {
        let tx = Self::from_request_unverified(request, allow_no_target)?;
        tx.check_encoded_size(max_tx_size)?;
        Ok(tx)
    }

    /// Ensures that encoded transaction size is not greater than `max_tx_size`.
    fn check_encoded_size(&self, max_tx_size: usize) -> Result<(), SerializationTransactionError> {
        // since `abi_encoding_len` returns 32-byte words multiplication on 32 is needed
        let tx_size = self.abi_encoding_len() * 32;
        if tx_size > max_tx_size {
            return Err(SerializationTransactionError::OversizedData(
                max_tx_size,
                tx_size,
            ));
        };
        Ok(())
    }
}

impl From<L2Tx> for CallRequest {
    fn from(tx: L2Tx) -> Self {
        let mut meta = Eip712Meta {
            gas_per_pubdata: tx.common_data.fee.gas_per_pubdata_limit,
            factory_deps: vec![],
            custom_signature: Some(tx.common_data.signature.clone()),
            paymaster_params: Some(tx.common_data.paymaster_params.clone()),
        };
        meta.factory_deps.clone_from(&tx.execute.factory_deps);
        let mut request = CallRequestBuilder::default()
            .from(tx.initiator_account())
            .gas(tx.common_data.fee.gas_limit)
            .max_fee_per_gas(tx.common_data.fee.max_fee_per_gas)
            .max_priority_fee_per_gas(tx.common_data.fee.max_priority_fee_per_gas)
            .transaction_type(U64::from(tx.common_data.transaction_type as u32))
            .to(tx.execute.contract_address)
            .data(Bytes(tx.execute.calldata.clone()))
            .eip712_meta(meta)
            .build();

        if tx.common_data.transaction_type == TransactionType::LegacyTransaction {
            request.transaction_type = None;
        }
        request
    }
}

impl From<CallRequest> for TransactionRequest {
    fn from(call_request: CallRequest) -> Self {
        TransactionRequest {
            nonce: call_request.nonce.unwrap_or_default(),
            from: call_request.from,
            to: call_request.to,
            value: call_request.value.unwrap_or_default(),
            gas_price: call_request.gas_price.unwrap_or_default(),
            gas: call_request.gas.unwrap_or_default(),
            input: call_request.input.or(call_request.data).unwrap_or_default(),
            transaction_type: call_request.transaction_type,
            access_list: call_request.access_list,
            eip712_meta: call_request.eip712_meta,
            ..Default::default()
        }
    }
}

impl L1Tx {
    /// Converts a request into a transaction.
    ///
    /// # Arguments
    ///
    /// - `allow_no_target` enables / disables transactions without target (i.e., `to` field).
    ///   This field can only be absent for EVM deployment transactions.
    pub fn from_request(
        request: CallRequest,
        allow_no_target: bool,
    ) -> Result<Self, SerializationTransactionError> {
        // L1 transactions have no limitations on the transaction size.
        let tx: L2Tx = L2Tx::from_request(request.into(), MAX_ENCODED_TX_SIZE, allow_no_target)?;

        // Note, that while the user has theoretically provided the fee for ETH on L1,
        // the payment to the operator as well as refunds happen on L2 and so all the ETH
        // that the transaction requires to pay the operator needs to be minted on L2.
        let total_needed_eth =
            tx.execute.value + tx.common_data.fee.max_fee_per_gas * tx.common_data.fee.gas_limit;

        // Note, that we do not set `refund_recipient` here, to keep it explicitly 0,
        // so that during fee estimation it is taken into account that the refund recipient may be a different address
        let common_data = L1TxCommonData {
            sender: tx.common_data.initiator_address,
            max_fee_per_gas: tx.common_data.fee.max_fee_per_gas,
            gas_limit: tx.common_data.fee.gas_limit,
            gas_per_pubdata_limit: tx.common_data.fee.gas_per_pubdata_limit,
            to_mint: total_needed_eth,
            ..Default::default()
        };

        let tx = L1Tx {
            execute: tx.execute,
            common_data,
            received_timestamp_ms: 0u64,
        };

        Ok(tx)
    }
}

fn rlp_opt<T: rlp::Encodable>(rlp: &mut RlpStream, opt: &Option<T>) {
    if let Some(inner) = opt {
        rlp.append(inner);
    } else {
        rlp.append(&"");
    }
}

fn access_list_rlp(rlp: &mut RlpStream, access_list: &Option<AccessList>) {
    if let Some(access_list) = access_list {
        rlp.begin_list(access_list.len());
        for item in access_list {
            rlp.begin_list(2);
            rlp.append(&item.address);
            rlp.append_list(&item.storage_keys);
        }
    } else {
        rlp.begin_list(0);
    }
}

pub fn validate_factory_deps(
    factory_deps: &[Vec<u8>],
) -> Result<(), SerializationTransactionError> {
    for (i, dep) in factory_deps.iter().enumerate() {
        validate_bytecode(dep)
            .map_err(|err| SerializationTransactionError::InvalidFactoryDependencies(i, err))?;
    }

    Ok(())
}
