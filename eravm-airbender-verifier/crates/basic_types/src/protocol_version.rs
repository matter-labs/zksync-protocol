use std::{
    convert::{TryFrom, TryInto},
    fmt,
    num::ParseIntError,
    ops::{Add, Deref, DerefMut, Sub},
    str::FromStr,
};

use num_enum::TryFromPrimitive;
use serde::{de, Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

use crate::{
    ethabi::Token,
    vm::VmVersion,
    web3::contract::{Detokenize, Error},
    H256, U256,
};

pub const PACKED_SEMVER_MINOR_OFFSET: u32 = 32;
pub const PACKED_SEMVER_MINOR_MASK: u32 = 0xFFFF;

/// `ProtocolVersionId` is a unique identifier of the protocol version.
///
/// Note, that it is an identifier of the `minor` semver version of the protocol, with
/// the `major` version being `0`. Also, the protocol version on the contracts may contain
/// potential minor versions, that may have different contract behavior (e.g. Verifier), but it should not
/// impact the users.
#[repr(u16)]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    TryFromPrimitive,
    Serialize,
    Deserialize,
)]
pub enum ProtocolVersionId {
    Version0 = 0,
    Version1,
    Version2,
    Version3,
    Version4,
    Version5,
    Version6,
    Version7,
    Version8,
    Version9,
    Version10,
    Version11,
    Version12,
    Version13,
    Version14,
    Version15,
    Version16,
    Version17,
    Version18,
    Version19,
    Version20,
    Version21,
    Version22,
    // Version `23` is only present on the internal staging networks.
    // All the user-facing environments were switched from 22 to 24 right away.
    Version23,
    Version24,
    Version25,
    Version26,
    Version27,
    Version28,
    Version29,
    // Version `30` was skipped as an Era upgrade due to version clash with ZKsync OS.
    Version30,
    Version31,
    Version32,
    Version33,
    Version34,
    // Speculative next protocol version for the upgrade integration tests etc.
    Version35,
}

impl ProtocolVersionId {
    pub const fn latest() -> Self {
        Self::Version34
    }

    pub const fn next() -> Self {
        Self::Version35
    }

    pub fn try_from_packed_semver(packed_semver: U256) -> Result<Self, String> {
        ProtocolSemanticVersion::try_from_packed(packed_semver).map(|p| p.minor)
    }

    pub fn into_packed_semver_with_patch(self, patch: usize) -> U256 {
        let minor = U256::from(self as u16);
        let patch = U256::from(patch as u32);

        (minor << U256::from(PACKED_SEMVER_MINOR_OFFSET)) | patch
    }

    /// Returns VM version to be used by API for this protocol version.
    /// We temporary support only two latest VM versions for API.
    pub fn into_api_vm_version(self) -> VmVersion {
        match self {
            ProtocolVersionId::Version0 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version1 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version2 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version3 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version4 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version5 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version6 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version7 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version8 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version9 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version10 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version11 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version12 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version13 => VmVersion::VmVirtualBlocks,
            ProtocolVersionId::Version14 => VmVersion::VmVirtualBlocks,
            ProtocolVersionId::Version15 => VmVersion::VmVirtualBlocks,
            ProtocolVersionId::Version16 => VmVersion::VmVirtualBlocksRefundsEnhancement,
            ProtocolVersionId::Version17 => VmVersion::VmVirtualBlocksRefundsEnhancement,
            ProtocolVersionId::Version18 => VmVersion::VmBoojumIntegration,
            ProtocolVersionId::Version19 => VmVersion::VmBoojumIntegration,
            ProtocolVersionId::Version20 => VmVersion::Vm1_4_1,
            ProtocolVersionId::Version21 => VmVersion::Vm1_4_2,
            ProtocolVersionId::Version22 => VmVersion::Vm1_4_2,
            ProtocolVersionId::Version23 => VmVersion::Vm1_5_0SmallBootloaderMemory,
            ProtocolVersionId::Version24 => VmVersion::Vm1_5_0IncreasedBootloaderMemory,
            ProtocolVersionId::Version25 => VmVersion::Vm1_5_0IncreasedBootloaderMemory,
            ProtocolVersionId::Version26 => VmVersion::VmGateway,
            ProtocolVersionId::Version27 => VmVersion::VmEvmEmulator,
            ProtocolVersionId::Version28 => VmVersion::VmEcPrecompiles,
            ProtocolVersionId::Version29 => VmVersion::VmInterop,
            // Note V30 is only present on zksync os
            ProtocolVersionId::Version30 => VmVersion::VmInterop,
            ProtocolVersionId::Version31 => VmVersion::VmMediumInterop,
            ProtocolVersionId::Version32 => VmVersion::VmMediumInterop,
            ProtocolVersionId::Version33 => VmVersion::VmMediumInterop,
            ProtocolVersionId::Version34 => VmVersion::VmMediumInteropForceFail,
            ProtocolVersionId::Version35 => VmVersion::VmMediumInteropForceFail,
        }
    }

    // It is possible that some external nodes do not store protocol versions for versions below 9.
    // That's why we assume that whenever a protocol version is not present, version 9 is to be used.
    pub fn last_potentially_undefined() -> Self {
        Self::Version9
    }

    pub fn is_pre_boojum(&self) -> bool {
        self <= &Self::Version17
    }

    pub fn is_pre_shared_bridge(&self) -> bool {
        self <= &Self::Version22
    }

    pub fn is_pre_gateway(&self) -> bool {
        self < &Self::gateway_upgrade()
    }

    pub fn is_post_gateway(&self) -> bool {
        self >= &Self::gateway_upgrade()
    }

    pub fn is_pre_fflonk(&self) -> bool {
        self < &Self::Version27
    }

    pub fn is_post_fflonk(&self) -> bool {
        self >= &Self::Version27
    }

    pub fn is_pre_interop_fast_blocks(&self) -> bool {
        self < &Self::Version29
    }

    pub fn is_pre_medium_interop(&self) -> bool {
        self < &Self::Version31
    }

    pub fn is_1_4_0(&self) -> bool {
        self >= &ProtocolVersionId::Version18 && self < &ProtocolVersionId::Version20
    }

    pub fn is_1_4_1(&self) -> bool {
        self == &ProtocolVersionId::Version20
    }

    pub fn is_pre_1_4_1(&self) -> bool {
        self < &ProtocolVersionId::Version20
    }

    pub fn is_post_1_4_1(&self) -> bool {
        self >= &ProtocolVersionId::Version20
    }

    pub fn is_post_1_4_2(&self) -> bool {
        self >= &ProtocolVersionId::Version21
    }

    pub fn is_pre_1_4_2(&self) -> bool {
        self < &ProtocolVersionId::Version21
    }

    pub fn is_1_4_2(&self) -> bool {
        self == &ProtocolVersionId::Version21 || self == &ProtocolVersionId::Version22
    }

    pub fn is_pre_1_5_0(&self) -> bool {
        self < &ProtocolVersionId::Version23
    }

    pub fn is_post_1_5_0(&self) -> bool {
        self >= &ProtocolVersionId::Version23
    }

    pub const fn gateway_upgrade() -> Self {
        ProtocolVersionId::Version26
    }
}

impl Default for ProtocolVersionId {
    fn default() -> Self {
        Self::latest()
    }
}

impl fmt::Display for ProtocolVersionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", *self as u16)
    }
}

impl TryFrom<U256> for ProtocolVersionId {
    type Error = String;

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value > U256::from(u16::MAX) {
            Err(format!("unknown protocol version ID: {}", value))
        } else {
            (value.as_u32() as u16)
                .try_into()
                .map_err(|_| format!("unknown protocol version ID: {}", value))
        }
    }
}

/// Highest protocol minor this build can name.
///
/// Tests use it to construct minors this build *cannot* name (the interesting
/// case for [`ProtocolUpgradeId`]). Pinned by `max_known_is_last_variant`: a
/// dependency bump that appends a variant to [`ProtocolVersionId`] must move
/// this constant in the same commit.
pub const MAX_KNOWN_PROTOCOL_VERSION: ProtocolVersionId = ProtocolVersionId::Version35;

/// Reads a raw protocol-minor number from either wire form: the derived
/// `"VersionNN"` string (JSON) or a bare integer (bincode, plus JSON
/// defensively). See [`ProtocolUpgradeId`].
struct WireProtocolVersionVisitor;

impl<'de> de::Visitor<'de> for WireProtocolVersionVisitor {
    type Value = u16;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a protocol minor version as `\"VersionNN\"` or a number")
    }

    /// Accepts exactly the form the derived `Serialize` writes. `u16::from_str`
    /// alone would also take `"Version+31"` and `"Version031"`, which nothing
    /// produces and the derived codec rejects.
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        value
            .strip_prefix("Version")
            .filter(|digits| {
                !digits.is_empty()
                    && digits.bytes().all(|b| b.is_ascii_digit())
                    && (digits.len() == 1 || !digits.starts_with('0'))
            })
            .and_then(|digits| digits.parse::<u16>().ok())
            .ok_or_else(|| E::invalid_value(de::Unexpected::Str(value), &self))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
        u16::try_from(value).map_err(|_| E::invalid_value(de::Unexpected::Unsigned(value), &self))
    }
}

/// The protocol minor named by a protocol-upgrade transaction, as the raw wire
/// number.
///
/// [`ProtocolVersionId`] is a closed enum, so its derived codec *rejects* a
/// minor this build cannot name — and on a non-self-describing wire that
/// rejection kills the whole payload decode. The first batch of a new minor
/// carries a protocol-upgrade transaction naming that minor, so with the strict
/// codec that batch could not even be decoded until a new build shipped.
///
/// This newtype carries the value losslessly instead. It is not clamped or
/// validated against the variant list: the value becomes the upgrade tx's nonce
/// and so feeds its canonical hash — mangling it would corrupt the transaction
/// rather than fail cleanly. Wire form is byte-identical to the derived
/// [`ProtocolVersionId`] codec in both directions; it can additionally carry,
/// and re-emit unchanged, a minor this build cannot name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolUpgradeId(u16);

impl ProtocolUpgradeId {
    /// The raw minor as it appeared on the wire; the upgrade tx's nonce.
    pub const fn raw(self) -> u16 {
        self.0
    }
}

impl Default for ProtocolUpgradeId {
    fn default() -> Self {
        Self::from(ProtocolVersionId::default())
    }
}

impl From<ProtocolVersionId> for ProtocolUpgradeId {
    fn from(value: ProtocolVersionId) -> Self {
        Self(value as u16)
    }
}

impl From<u16> for ProtocolUpgradeId {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

/// Fails for a minor this build cannot name; use [`ProtocolUpgradeId::raw`] for
/// the nonce.
impl TryFrom<ProtocolUpgradeId> for ProtocolVersionId {
    type Error = String;

    fn try_from(value: ProtocolUpgradeId) -> Result<Self, Self::Error> {
        Self::try_from(value.0).map_err(|_| format!("unknown protocol version ID: {}", value.0))
    }
}

impl TryFrom<U256> for ProtocolUpgradeId {
    type Error = String;

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        if value > U256::from(u16::MAX) {
            Err(format!("protocol upgrade ID out of range: {value}"))
        } else {
            Ok(Self(value.as_u32() as u16))
        }
    }
}

impl Serialize for ProtocolUpgradeId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // Mirror the derived codec: variant name when self-describing, index
        // otherwise. The host re-encodes for the guest, so this side matters too.
        if s.is_human_readable() {
            s.serialize_str(&format!("Version{}", self.0))
        } else {
            s.serialize_u16(self.0)
        }
    }
}

impl<'de> Deserialize<'de> for ProtocolUpgradeId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // bincode cannot `deserialize_any`, so pick the form by wire kind.
        let raw = if d.is_human_readable() {
            d.deserialize_any(WireProtocolVersionVisitor)?
        } else {
            d.deserialize_u16(WireProtocolVersionVisitor)?
        };
        Ok(Self(raw))
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifierParams {
    pub recursion_node_level_vk_hash: H256,
    pub recursion_leaf_level_vk_hash: H256,
    pub recursion_circuits_set_vks_hash: H256,
}

impl Detokenize for VerifierParams {
    fn from_tokens(tokens: Vec<Token>) -> Result<Self, Error> {
        if tokens.len() != 1 {
            return Err(Error::InvalidOutputType(format!(
                "expected single token, got {tokens:?}"
            )));
        }

        let tokens = match tokens[0].clone() {
            Token::Tuple(tokens) => tokens,
            other => {
                return Err(Error::InvalidOutputType(format!(
                    "expected a tuple, got {other:?}"
                )));
            }
        };

        let vks_vec: Vec<H256> = tokens
            .into_iter()
            .map(|token| H256::from_slice(&token.into_fixed_bytes().unwrap()))
            .collect();
        Ok(VerifierParams {
            recursion_node_level_vk_hash: vks_vec[0],
            recursion_leaf_level_vk_hash: vks_vec[1],
            recursion_circuits_set_vks_hash: vks_vec[2],
        })
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct L1VerifierConfig {
    // Rename is required to not introduce breaking changes in the API for existing clients.
    #[serde(
        alias = "recursion_scheduler_level_vk_hash",
        rename(serialize = "recursion_scheduler_level_vk_hash")
    )]
    pub snark_wrapper_vk_hash: H256,
    pub fflonk_snark_wrapper_vk_hash: Option<H256>,
}

impl From<ProtocolVersionId> for VmVersion {
    fn from(value: ProtocolVersionId) -> Self {
        match value {
            ProtocolVersionId::Version0 => VmVersion::M5WithoutRefunds,
            ProtocolVersionId::Version1 => VmVersion::M5WithoutRefunds,
            ProtocolVersionId::Version2 => VmVersion::M5WithRefunds,
            ProtocolVersionId::Version3 => VmVersion::M5WithRefunds,
            ProtocolVersionId::Version4 => VmVersion::M6Initial,
            ProtocolVersionId::Version5 => VmVersion::M6BugWithCompressionFixed,
            ProtocolVersionId::Version6 => VmVersion::M6BugWithCompressionFixed,
            ProtocolVersionId::Version7 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version8 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version9 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version10 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version11 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version12 => VmVersion::Vm1_3_2,
            ProtocolVersionId::Version13 => VmVersion::VmVirtualBlocks,
            ProtocolVersionId::Version14 => VmVersion::VmVirtualBlocks,
            ProtocolVersionId::Version15 => VmVersion::VmVirtualBlocks,
            ProtocolVersionId::Version16 => VmVersion::VmVirtualBlocksRefundsEnhancement,
            ProtocolVersionId::Version17 => VmVersion::VmVirtualBlocksRefundsEnhancement,
            ProtocolVersionId::Version18 => VmVersion::VmBoojumIntegration,
            ProtocolVersionId::Version19 => VmVersion::VmBoojumIntegration,
            ProtocolVersionId::Version20 => VmVersion::Vm1_4_1,
            ProtocolVersionId::Version21 => VmVersion::Vm1_4_2,
            ProtocolVersionId::Version22 => VmVersion::Vm1_4_2,
            ProtocolVersionId::Version23 => VmVersion::Vm1_5_0SmallBootloaderMemory,
            ProtocolVersionId::Version24 => VmVersion::Vm1_5_0IncreasedBootloaderMemory,
            ProtocolVersionId::Version25 => VmVersion::Vm1_5_0IncreasedBootloaderMemory,
            ProtocolVersionId::Version26 => VmVersion::VmGateway,
            ProtocolVersionId::Version27 => VmVersion::VmEvmEmulator,
            ProtocolVersionId::Version28 => VmVersion::VmEcPrecompiles,
            ProtocolVersionId::Version29 => VmVersion::VmInterop,
            ProtocolVersionId::Version30 => VmVersion::VmInterop,
            ProtocolVersionId::Version31 => VmVersion::VmMediumInterop,
            ProtocolVersionId::Version32 => VmVersion::VmMediumInterop,
            // v33 is v32's VM; only the bootloader changes.
            ProtocolVersionId::Version33 => VmVersion::VmMediumInterop,
            ProtocolVersionId::Version34 => VmVersion::VmMediumInteropForceFail,
            // Speculative next protocol version for the upgrade integration tests etc.
            ProtocolVersionId::Version35 => VmVersion::VmMediumInteropForceFail,
        }
    }
}

basic_type!(
    /// Patch part of semantic protocol version.
    VersionPatch,
    u32
);

/// Semantic protocol version.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, SerializeDisplay, DeserializeFromStr, Hash, PartialOrd, Ord,
)]
pub struct ProtocolSemanticVersion {
    pub minor: ProtocolVersionId,
    pub patch: VersionPatch,
}

impl ProtocolSemanticVersion {
    const MAJOR_VERSION: u8 = 0;

    pub fn new(minor: ProtocolVersionId, patch: VersionPatch) -> Self {
        Self { minor, patch }
    }

    pub fn try_from_packed(packed: U256) -> Result<Self, String> {
        let minor = ((packed >> U256::from(PACKED_SEMVER_MINOR_OFFSET))
            & U256::from(PACKED_SEMVER_MINOR_MASK))
        .try_into()?;
        let patch = packed.0[0] as u32;

        Ok(Self {
            minor,
            patch: VersionPatch(patch),
        })
    }

    pub fn pack(&self) -> U256 {
        (U256::from(self.minor as u16) << U256::from(PACKED_SEMVER_MINOR_OFFSET))
            | U256::from(self.patch.0)
    }
}

impl fmt::Display for ProtocolSemanticVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}",
            Self::MAJOR_VERSION,
            self.minor as u16,
            self.patch
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseProtocolSemanticVersionError {
    #[error("invalid format")]
    InvalidFormat,
    #[error("non zero major version")]
    NonZeroMajorVersion,
    #[error("{0}")]
    ParseIntError(ParseIntError),
}

impl FromStr for ProtocolSemanticVersion {
    type Err = ParseProtocolSemanticVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 3 {
            return Err(ParseProtocolSemanticVersionError::InvalidFormat);
        }

        let major = parts[0]
            .parse::<u16>()
            .map_err(ParseProtocolSemanticVersionError::ParseIntError)?;
        if major != 0 {
            return Err(ParseProtocolSemanticVersionError::NonZeroMajorVersion);
        }

        let minor = parts[1]
            .parse::<u16>()
            .map_err(ParseProtocolSemanticVersionError::ParseIntError)?;
        let minor = ProtocolVersionId::try_from(minor)
            .map_err(|_| ParseProtocolSemanticVersionError::InvalidFormat)?;

        let patch = parts[2]
            .parse::<u32>()
            .map_err(ParseProtocolSemanticVersionError::ParseIntError)?;

        Ok(ProtocolSemanticVersion {
            minor,
            patch: patch.into(),
        })
    }
}

impl Default for ProtocolSemanticVersion {
    fn default() -> Self {
        Self {
            minor: Default::default(),
            patch: 0.into(),
        }
    }
}

#[cfg(test)]
mod protocol_upgrade_id_tests {
    use super::*;

    fn nameable() -> impl Iterator<Item = ProtocolVersionId> {
        (0..=MAX_KNOWN_PROTOCOL_VERSION as u16)
            .map(|raw| ProtocolVersionId::try_from(raw).expect("the variant list is contiguous"))
    }

    /// Change detector: a bump that appends a variant must move
    /// [`MAX_KNOWN_PROTOCOL_VERSION`] in the same commit, or the tests here
    /// would pick a nameable minor when they need an unnameable one.
    #[test]
    fn max_known_is_last_variant() {
        let max = MAX_KNOWN_PROTOCOL_VERSION as u16;
        assert!(ProtocolVersionId::try_from(max).is_ok());
        assert!(
            ProtocolVersionId::try_from(max + 1).is_err(),
            "ProtocolVersionId gained a variant above {MAX_KNOWN_PROTOCOL_VERSION:?}; \
             update MAX_KNOWN_PROTOCOL_VERSION"
        );
    }

    /// Byte-identical to the codec it replaces, both directions — the host
    /// re-encodes the input for the guest.
    #[test]
    fn upgrade_id_bincode_matches_protocol_version_id() {
        let cfg = bincode::config::standard();
        for version in nameable() {
            let from_enum = bincode::serde::encode_to_vec(version, cfg).expect("encode enum");
            let from_new = bincode::serde::encode_to_vec(ProtocolUpgradeId::from(version), cfg)
                .expect("encode newtype");
            assert_eq!(from_new, from_enum, "byte layout differs for {version:?}");

            let (decoded, read) =
                bincode::serde::decode_from_slice::<ProtocolUpgradeId, _>(&from_enum, cfg)
                    .expect("decode newtype");
            assert_eq!(decoded.raw(), version as u16, "{version:?}");
            assert_eq!(read, from_enum.len(), "trailing bytes for {version:?}");
        }
    }

    /// [`WireProtocolVersionVisitor::visit_str`] is hand-rolled and strict on
    /// purpose, and this is the only coverage of that. It is now
    /// [`ProtocolUpgradeId`]'s sole JSON deserializer — it parses era's
    /// `proof_inputs_*.json` and the `upgrade_id` that becomes an upgrade tx's
    /// nonce, so a loosened parser would corrupt that tx's canonical hash.
    #[test]
    fn upgrade_id_json_rejects_malformed_labels() {
        for bad in [
            "\"Version+31\"",
            "\"Version031\"",
            "\"Version 31\"",
            "\"Version\"",
            "\"Version-1\"",
            "\"31\"",
            "\"v31\"",
            "\"VersionNaN\"",
        ] {
            assert!(
                serde_json::from_str::<ProtocolUpgradeId>(bad).is_err(),
                "{bad} must be rejected, not coerced"
            );
        }
        // The one string form that IS accepted, for contrast.
        assert_eq!(
            serde_json::from_str::<ProtocolUpgradeId>("\"Version31\"")
                .expect("the canonical form must parse")
                .raw(),
            31
        );
    }

    /// Same on the JSON wire.
    #[test]
    fn upgrade_id_json_matches_protocol_version_id() {
        for version in nameable() {
            let from_enum = serde_json::to_string(&version).expect("serialize enum");
            let from_new = serde_json::to_string(&ProtocolUpgradeId::from(version))
                .expect("serialize newtype");
            assert_eq!(from_new, from_enum, "JSON form differs for {version:?}");

            let decoded: ProtocolUpgradeId =
                serde_json::from_str(&from_enum).expect("decode newtype");
            assert_eq!(decoded.raw(), version as u16);
        }
    }

    /// Why this type exists: the value is the tx nonce, so an unnameable minor
    /// must decode *and re-encode to the same bytes*. Clamping must not happen.
    #[test]
    fn unnameable_minor_round_trips_losslessly() {
        let cfg = bincode::config::standard();
        for raw in [MAX_KNOWN_PROTOCOL_VERSION as u16 + 1, 45, 60_000, u16::MAX] {
            assert!(
                ProtocolVersionId::try_from(raw).is_err(),
                "raw {raw} is nameable; pick a value this build cannot name"
            );

            let bytes = bincode::serde::encode_to_vec(raw, cfg).expect("encode raw u16");

            // The strict enum rejects exactly these bytes — the original abort.
            assert!(
                bincode::serde::decode_from_slice::<ProtocolVersionId, _>(&bytes, cfg).is_err(),
                "raw {raw} should be undecodable as the closed enum; the comparison below is \
                 meaningless otherwise"
            );

            let (decoded, read) =
                bincode::serde::decode_from_slice::<ProtocolUpgradeId, _>(&bytes, cfg)
                    .unwrap_or_else(|e| panic!("decode of raw {raw}: {e}"));

            assert_eq!(decoded.raw(), raw, "value must survive decode unchanged");
            assert_ne!(
                decoded.raw(),
                MAX_KNOWN_PROTOCOL_VERSION as u16,
                "raw {raw} was saturated — that would corrupt the upgrade tx nonce"
            );
            assert_eq!(read, bytes.len(), "trailing bytes for raw {raw}");

            let re_encoded = bincode::serde::encode_to_vec(decoded, cfg).expect("re-encode");
            assert_eq!(re_encoded, bytes, "re-encode differs for raw {raw}");

            // The same value on the JSON wire, and back.
            let json = serde_json::to_string(&decoded).expect("serialize");
            assert_eq!(json, format!("\"Version{raw}\""));
            let back: ProtocolUpgradeId = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back.raw(), raw);
        }
    }

    /// Naming stays fallible; the newtype only widens what can be carried.
    #[test]
    fn naming_an_unnameable_minor_fails() {
        assert_eq!(
            ProtocolVersionId::try_from(ProtocolUpgradeId::from(ProtocolVersionId::latest()))
                .unwrap(),
            ProtocolVersionId::latest()
        );
        assert!(ProtocolVersionId::try_from(ProtocolUpgradeId::from(
            MAX_KNOWN_PROTOCOL_VERSION as u16 + 1
        ))
        .is_err());
    }
}
