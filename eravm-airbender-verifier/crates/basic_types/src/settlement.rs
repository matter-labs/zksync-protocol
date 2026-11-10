use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::SLChainId;

/// Whether the network settles to L1 directly or via a Gateway L2.
///
/// The JSON wire form is the adjacent-tagged shape upstream zksync-era emits
/// (`{"type":"L1","chain_id":1}`); the binary (bincode) wire form is
/// externally-tagged. The split exists because bincode cannot drive
/// `#[serde(tag, content)]` — its `Deserializer::deserialize_identifier` is
/// unimplemented — and the prover server consumes both wire formats.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SettlementLayer {
    L1(SLChainId),
    Gateway(SLChainId),
}

impl Serialize for SettlementLayer {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        // The two `Repr` enums below are identical except for the
        // `#[serde(tag, content)]` attribute on the human-readable branch.
        // Serde attributes aren't conditional, so the duplication is the
        // cost of keeping a single `SettlementLayer` type across both wires.
        if ser.is_human_readable() {
            #[derive(Serialize)]
            #[serde(tag = "type", content = "chain_id")]
            enum Repr<'a> {
                L1(&'a SLChainId),
                Gateway(&'a SLChainId),
            }
            match self {
                Self::L1(id) => Repr::L1(id).serialize(ser),
                Self::Gateway(id) => Repr::Gateway(id).serialize(ser),
            }
        } else {
            #[derive(Serialize)]
            enum Repr<'a> {
                L1(&'a SLChainId),
                Gateway(&'a SLChainId),
            }
            match self {
                Self::L1(id) => Repr::L1(id).serialize(ser),
                Self::Gateway(id) => Repr::Gateway(id).serialize(ser),
            }
        }
    }
}

impl<'de> Deserialize<'de> for SettlementLayer {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        if de.is_human_readable() {
            #[derive(Deserialize)]
            #[serde(tag = "type", content = "chain_id")]
            enum Repr {
                L1(SLChainId),
                Gateway(SLChainId),
            }
            Ok(match Repr::deserialize(de)? {
                Repr::L1(id) => Self::L1(id),
                Repr::Gateway(id) => Self::Gateway(id),
            })
        } else {
            #[derive(Deserialize)]
            enum Repr {
                L1(SLChainId),
                Gateway(SLChainId),
            }
            Ok(match Repr::deserialize(de)? {
                Repr::L1(id) => Self::L1(id),
                Repr::Gateway(id) => Self::Gateway(id),
            })
        }
    }
}

impl Default for SettlementLayer {
    fn default() -> Self {
        Self::L1(SLChainId(1))
    }
}

impl SettlementLayer {
    pub fn is_gateway(self) -> bool {
        matches!(self, Self::Gateway(_))
    }
    pub fn chain_id(&self) -> SLChainId {
        match self {
            Self::L1(chain_id) | Self::Gateway(chain_id) => *chain_id,
        }
    }
    pub fn for_tests() -> Self {
        // 9 is a common chain id for localhost
        Self::L1(SLChainId(9))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Locks the JSON wire format to upstream's adjacent-tagged form. If this
    /// breaks, the prover server's `reqwest::Response::json()` path fails on
    /// real payloads.
    #[test]
    fn json_wire_matches_upstream_adjacent_tagged_form() {
        let json = serde_json::to_string(&SettlementLayer::L1(SLChainId(42))).unwrap();
        assert_eq!(json, r#"{"type":"L1","chain_id":42}"#);

        let gw = serde_json::to_string(&SettlementLayer::Gateway(SLChainId(7))).unwrap();
        assert_eq!(gw, r#"{"type":"Gateway","chain_id":7}"#);

        let parsed: SettlementLayer =
            serde_json::from_str(r#"{"type":"L1","chain_id":42}"#).unwrap();
        assert_eq!(parsed, SettlementLayer::L1(SLChainId(42)));
    }

    /// Bincode can't drive adjacent-tagged enums (`deserialize_identifier` is
    /// unimplemented). The `is_human_readable=false` branch must round-trip.
    #[test]
    fn bincode_roundtrip() {
        let original = SettlementLayer::Gateway(SLChainId(123));
        let bytes = bincode::serde::encode_to_vec(original, bincode::config::standard()).unwrap();
        let (decoded, _): (SettlementLayer, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).unwrap();
        assert_eq!(decoded, original);
    }
}
