use std::str::FromStr;

use serde::{Deserialize, Serialize};
use strum::{Display, EnumIter};

use crate::{
    ethabi,
    web3::contract::{Detokenize, Error as ContractError},
    Address, U256,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, EnumIter, Display)]
pub enum L1BatchCommitmentMode {
    #[default]
    Rollup,
    Validium,
}

impl From<PubdataType> for L1BatchCommitmentMode {
    fn from(value: PubdataType) -> Self {
        match value {
            PubdataType::Rollup => L1BatchCommitmentMode::Rollup,
            PubdataType::NoDA
            | PubdataType::Avail
            | PubdataType::Celestia
            | PubdataType::Eigen
            | PubdataType::ObjectStore => L1BatchCommitmentMode::Validium,
        }
    }
}

// The cases are extracted from the `PubdataPricingMode` enum in the L1 contracts,
// And knowing that, in Ethereum, the response is the index of the enum case.
// 0 corresponds to Rollup case,
// 1 corresponds to Validium case,
// Other values are incorrect.
impl Detokenize for L1BatchCommitmentMode {
    fn from_tokens(tokens: Vec<ethabi::Token>) -> Result<Self, ContractError> {
        fn error(tokens: &[ethabi::Token]) -> ContractError {
            ContractError::InvalidOutputType(format!(
                "L1BatchCommitDataGeneratorMode::from_tokens: {tokens:?}"
            ))
        }

        match tokens.as_slice() {
            [ethabi::Token::Uint(enum_value)] => {
                if enum_value == &U256::zero() {
                    Ok(L1BatchCommitmentMode::Rollup)
                } else if enum_value == &U256::one() {
                    Ok(L1BatchCommitmentMode::Validium)
                } else {
                    Err(error(&tokens))
                }
            }
            _ => Err(error(&tokens)),
        }
    }
}

impl FromStr for L1BatchCommitmentMode {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Rollup" => Ok(Self::Rollup),
            "Validium" => Ok(Self::Validium),
            _ => {
                Err("Incorrect l1 batch commitment mode type; expected one of `Rollup`, `Validium`")
            }
        }
    }
}

#[derive(Default, Copy, Debug, Clone, PartialEq, Serialize, Deserialize, Display)]
pub enum PubdataType {
    #[default]
    Rollup,
    NoDA,
    Avail,
    Celestia,
    Eigen,
    ObjectStore,
}

impl FromStr for PubdataType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Rollup" => Ok(Self::Rollup),
            "NoDA" => Ok(Self::NoDA),
            "Avail" => Ok(Self::Avail),
            "Celestia" => Ok(Self::Celestia),
            "Eigen" => Ok(Self::Eigen),
            "ObjectStore" => Ok(Self::ObjectStore),
            _ => Err("Incorrect DA client type; expected one of `Rollup`, `NoDA`, `Avail`, `Celestia`, `Eigen`, `ObjectStore`"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Display)]
#[repr(u8)]
pub enum L2DACommitmentScheme {
    None = 0,
    EmptyNoDA = 1,
    PubdataKeccak256 = 2,
    BlobsAndPubdataKeccak256 = 3,
    BlobsZksyncOS = 4,
}

impl L2DACommitmentScheme {
    pub fn is_none(&self) -> bool {
        *self == L2DACommitmentScheme::None
    }
}

// `BlobsZksyncOS = 4` is zksync-os-only, so `TryFrom<u8>` and `FromStr` reject
// it. The derived `serde::Deserialize` still reads the tag directly, so wire
// payloads are gated at the `PubdataParams::new` invariant instead.
impl TryFrom<u8> for L2DACommitmentScheme {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(L2DACommitmentScheme::None),
            1 => Ok(L2DACommitmentScheme::EmptyNoDA),
            2 => Ok(L2DACommitmentScheme::PubdataKeccak256),
            3 => Ok(L2DACommitmentScheme::BlobsAndPubdataKeccak256),
            _ => Err("Invalid L2DACommitmentScheme value"),
        }
    }
}

impl FromStr for L2DACommitmentScheme {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "None" => Ok(Self::None),
            "EmptyNoDA" => Ok(Self::EmptyNoDA),
            "PubdataKeccak256" => Ok(Self::PubdataKeccak256),
            "BlobsAndPubdataKeccak256" => Ok(Self::BlobsAndPubdataKeccak256),
            _ => Err("Incorrect L2 DA commitment scheme; expected one of `None`, `EmptyNoDA`, `PubdataKeccak256`, `BlobsAndPubdataKeccak256`"),
        }
    }
}

#[derive(Copy, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum L2PubdataValidator {
    Address(Address),
    CommitmentScheme(L2DACommitmentScheme),
}

impl TryFrom<(Option<Address>, Option<L2DACommitmentScheme>)> for L2PubdataValidator {
    type Error = anyhow::Error;

    fn try_from(
        value: (Option<Address>, Option<L2DACommitmentScheme>),
    ) -> Result<Self, Self::Error> {
        match value {
            (None, Some(scheme)) => Ok(L2PubdataValidator::CommitmentScheme(scheme)),
            (Some(address), None) => Ok(L2PubdataValidator::Address(address)),
            (Some(_), Some(_)) => anyhow::bail!(
                "Address and L2DACommitmentScheme are specified, should be chosen only one"
            ),
            (None, None) => anyhow::bail!(
                "Address and L2DACommitmentScheme are not specified, should be chosen at least one"
            ),
        }
    }
}

impl L2PubdataValidator {
    pub fn l2_da_validator(&self) -> Option<Address> {
        match self {
            L2PubdataValidator::Address(addr) => Some(*addr),
            L2PubdataValidator::CommitmentScheme(_) => None,
        }
    }

    pub fn l2_da_commitment_scheme(&self) -> Option<L2DACommitmentScheme> {
        match self {
            L2PubdataValidator::Address(_) => None,
            L2PubdataValidator::CommitmentScheme(scheme) => Some(*scheme),
        }
    }
}

// `Serialize` is derived; `Deserialize` is hand-rolled below to route through
// `PubdataParams::new`, so the wire layer also enforces its invalid-scheme
// invariant. Field names and order must stay in lockstep with the `Repr` helper
// below — a reorder here will break wire compatibility without breaking the
// bincode round-trip test.
#[derive(Copy, Debug, Clone, PartialEq, Serialize)]
pub struct PubdataParams {
    pubdata_validator: L2PubdataValidator,
    pubdata_type: PubdataType,
}

impl<'de> Deserialize<'de> for PubdataParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // On human-readable wires (JSON), accept both the current
        // `pubdata_validator` field and the pre-v31 `l2_da_validator_address`
        // field so a mixed-version sender (an EN that hasn't picked up the
        // new field yet) can still be decoded; `pubdata_validator` wins when
        // both are present. The derived `Serialize` only emits the two
        // canonical fields, and bincode is positional, so the binary wire
        // never carries the legacy slot and uses the simpler shape.
        let (pubdata_validator, pubdata_type) = if deserializer.is_human_readable() {
            #[derive(Deserialize)]
            struct JsonRepr {
                pubdata_validator: Option<L2PubdataValidator>,
                l2_da_validator_address: Option<Address>,
                pubdata_type: PubdataType,
            }
            let r = JsonRepr::deserialize(deserializer)?;
            let validator = match (r.pubdata_validator, r.l2_da_validator_address) {
                (Some(v), _) => v,
                (None, Some(addr)) => L2PubdataValidator::Address(addr),
                (None, None) => return Err(serde::de::Error::missing_field("pubdata_validator")),
            };
            (validator, r.pubdata_type)
        } else {
            #[derive(Deserialize)]
            struct BinaryRepr {
                pubdata_validator: L2PubdataValidator,
                pubdata_type: PubdataType,
            }
            let r = BinaryRepr::deserialize(deserializer)?;
            (r.pubdata_validator, r.pubdata_type)
        };
        Self::new(pubdata_validator, pubdata_type).map_err(serde::de::Error::custom)
    }
}

impl PubdataParams {
    pub fn new(
        pubdata_validator: L2PubdataValidator,
        pubdata_type: PubdataType,
    ) -> anyhow::Result<Self> {
        // Reject commitment schemes invalid for an Era batch. The scheme is written
        // straight into bootloader memory, and the derived `Deserialize` can read
        // the `None` (0) and zksync-os-only `BlobsZksyncOS` (4) tags that
        // `TryFrom`/`FromStr` refuse — so every `PubdataParams` is gated here.
        if let L2PubdataValidator::CommitmentScheme(scheme) = pubdata_validator {
            match scheme {
                L2DACommitmentScheme::None | L2DACommitmentScheme::BlobsZksyncOS => {
                    anyhow::bail!(
                        "L2DACommitmentScheme::{scheme} is not a valid pubdata parameter for an Era batch"
                    );
                }
                L2DACommitmentScheme::EmptyNoDA
                | L2DACommitmentScheme::PubdataKeccak256
                | L2DACommitmentScheme::BlobsAndPubdataKeccak256 => {}
            }
        }

        Ok(PubdataParams {
            pubdata_validator,
            pubdata_type,
        })
    }

    pub fn pubdata_validator(&self) -> L2PubdataValidator {
        self.pubdata_validator
    }

    pub fn pubdata_type(&self) -> PubdataType {
        self.pubdata_type
    }

    pub fn genesis() -> Self {
        PubdataParams {
            pubdata_validator: L2PubdataValidator::CommitmentScheme(
                L2DACommitmentScheme::BlobsAndPubdataKeccak256,
            ),
            pubdata_type: PubdataType::Rollup,
        }
    }

    pub fn pre_gateway() -> Self {
        PubdataParams {
            pubdata_validator: L2PubdataValidator::Address(Address::zero()),
            pubdata_type: PubdataType::Rollup,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `Deserialize` must route through `PubdataParams::new` so untrusted wire
    /// payloads cannot construct the `CommitmentScheme(None)` shape that
    /// `new()` itself rejects.
    #[test]
    fn pubdata_params_deserialize_rejects_commitment_scheme_none() {
        let invalid = serde_json::json!({
            "pubdata_validator": { "CommitmentScheme": "None" },
            "pubdata_type": "Rollup",
        });
        let err = serde_json::from_value::<PubdataParams>(invalid).unwrap_err();
        assert!(
            err.to_string().contains("None"),
            "expected None-rejection error, got: {err}"
        );
    }

    /// The derived `Deserialize` on `L2DACommitmentScheme` can read the `BlobsZksyncOS`
    /// (4) tag even though it's zksync-os-only and rejected by `TryFrom`/`FromStr`;
    /// `PubdataParams::new` must reject it so it never reaches bootloader memory.
    #[test]
    fn pubdata_params_deserialize_rejects_zksync_os_scheme() {
        let invalid = serde_json::json!({
            "pubdata_validator": { "CommitmentScheme": "BlobsZksyncOS" },
            "pubdata_type": "Rollup",
        });
        let err = serde_json::from_value::<PubdataParams>(invalid).unwrap_err();
        assert!(
            err.to_string().contains("BlobsZksyncOS"),
            "expected BlobsZksyncOS-rejection error, got: {err}"
        );
    }

    #[test]
    fn pubdata_params_serde_roundtrip_json() {
        let params = PubdataParams::genesis();
        let json = serde_json::to_string(&params).unwrap();
        let back: PubdataParams = serde_json::from_str(&json).unwrap();
        assert_eq!(back, params);
    }

    #[test]
    fn pubdata_params_serde_roundtrip_bincode() {
        let params = PubdataParams::pre_gateway();
        let bytes = bincode::serde::encode_to_vec(params, bincode::config::standard()).unwrap();
        let (back, _): (PubdataParams, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(back, params);
    }

    /// Pre-v31 ENs (before upstream PR #4730) only emit the legacy
    /// `l2_da_validator_address` field. Mirror upstream's `Deserialize` and
    /// wrap such payloads into the `Address` variant.
    #[test]
    fn pubdata_params_deserialize_accepts_legacy_only_field() {
        let addr = Address::repeat_byte(0xab);
        let legacy = serde_json::json!({
            "l2_da_validator_address": addr,
            "pubdata_type": "Rollup",
        });
        let parsed: PubdataParams = serde_json::from_value(legacy).unwrap();
        assert_eq!(
            parsed.pubdata_validator(),
            L2PubdataValidator::Address(addr)
        );
    }

    /// Upstream emits both fields during the migration window. The new
    /// `pubdata_validator` field wins; the legacy address is ignored.
    #[test]
    fn pubdata_params_deserialize_prefers_new_field_when_both_present() {
        let legacy_addr = Address::repeat_byte(0xab);
        let new_addr = Address::repeat_byte(0xcd);
        let mixed = serde_json::json!({
            "pubdata_validator": { "Address": new_addr },
            "l2_da_validator_address": legacy_addr,
            "pubdata_type": "Rollup",
        });
        let parsed: PubdataParams = serde_json::from_value(mixed).unwrap();
        assert_eq!(
            parsed.pubdata_validator(),
            L2PubdataValidator::Address(new_addr)
        );
    }

    /// A payload with neither field is rejected with a missing-field error.
    #[test]
    fn pubdata_params_deserialize_rejects_missing_both_fields() {
        let invalid = serde_json::json!({
            "pubdata_type": "Rollup",
        });
        let err = serde_json::from_value::<PubdataParams>(invalid).unwrap_err();
        assert!(
            err.to_string().contains("pubdata_validator"),
            "expected missing-field error, got: {err}"
        );
    }
}
