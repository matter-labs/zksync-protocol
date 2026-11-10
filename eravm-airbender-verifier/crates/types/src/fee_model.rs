use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};
use zksync_system_constants::L1_GAS_PER_PUBDATA_BYTE;

use crate::ProtocolVersionId;

/// Fee input to be provided into the VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatchFeeInput {
    L1Pegged(L1PeggedBatchFeeModelInput),
    PubdataIndependent(PubdataIndependentBatchFeeModelInput),
}

impl BatchFeeInput {
    pub fn sensible_l1_pegged_default() -> Self {
        Self::L1Pegged(L1PeggedBatchFeeModelInput {
            l1_gas_price: 1_000_000_000,
            fair_l2_gas_price: 100_000_000,
        })
    }

    pub fn l1_pegged(l1_gas_price: u64, fair_l2_gas_price: u64) -> Self {
        Self::L1Pegged(L1PeggedBatchFeeModelInput {
            l1_gas_price,
            fair_l2_gas_price,
        })
    }

    pub fn pubdata_independent(
        l1_gas_price: u64,
        fair_l2_gas_price: u64,
        fair_pubdata_price: u64,
    ) -> Self {
        Self::PubdataIndependent(PubdataIndependentBatchFeeModelInput {
            l1_gas_price,
            fair_l2_gas_price,
            fair_pubdata_price,
        })
    }

    pub fn from_protocol_version(
        protocol_version: Option<ProtocolVersionId>,
        l1_gas_price: u64,
        fair_l2_gas_price: u64,
        fair_pubdata_price: Option<u64>,
    ) -> Self {
        protocol_version
            .filter(|version: &ProtocolVersionId| version.is_post_1_4_1())
            .map(|_| {
                Self::PubdataIndependent(PubdataIndependentBatchFeeModelInput {
                    fair_pubdata_price: fair_pubdata_price
                        .expect("No fair pubdata price for 1.4.1"),
                    fair_l2_gas_price,
                    l1_gas_price,
                })
            })
            .unwrap_or_else(|| {
                Self::L1Pegged(L1PeggedBatchFeeModelInput {
                    fair_l2_gas_price,
                    l1_gas_price,
                })
            })
    }

    pub fn into_l1_pegged(self) -> L1PeggedBatchFeeModelInput {
        match self {
            BatchFeeInput::L1Pegged(input) => input,
            _ => panic!(
                "Can not convert PubdataIndependentBatchFeeModelInput into L1PeggedBatchFeeModelInput"
            ),
        }
    }

    pub fn fair_pubdata_price(&self) -> u64 {
        match self {
            BatchFeeInput::L1Pegged(input) => input.l1_gas_price * L1_GAS_PER_PUBDATA_BYTE as u64,
            BatchFeeInput::PubdataIndependent(input) => input.fair_pubdata_price,
        }
    }

    pub fn fair_l2_gas_price(&self) -> u64 {
        match self {
            BatchFeeInput::L1Pegged(input) => input.fair_l2_gas_price,
            BatchFeeInput::PubdataIndependent(input) => input.fair_l2_gas_price,
        }
    }

    pub fn l1_gas_price(&self) -> u64 {
        match self {
            BatchFeeInput::L1Pegged(input) => input.l1_gas_price,
            BatchFeeInput::PubdataIndependent(input) => input.l1_gas_price,
        }
    }

    pub fn into_pubdata_independent(self) -> PubdataIndependentBatchFeeModelInput {
        match self {
            BatchFeeInput::PubdataIndependent(input) => input,
            BatchFeeInput::L1Pegged(input) => PubdataIndependentBatchFeeModelInput {
                fair_l2_gas_price: input.fair_l2_gas_price,
                fair_pubdata_price: input.l1_gas_price * L1_GAS_PER_PUBDATA_BYTE as u64,
                l1_gas_price: input.l1_gas_price,
            },
        }
    }

    pub fn for_protocol_version(
        protocol_version: ProtocolVersionId,
        fair_l2_gas_price: u64,
        fair_pubdata_price: Option<u64>,
        l1_gas_price: u64,
    ) -> Self {
        if protocol_version.is_post_1_4_1() {
            Self::PubdataIndependent(PubdataIndependentBatchFeeModelInput {
                fair_l2_gas_price,
                fair_pubdata_price: fair_pubdata_price
                    .expect("Pubdata price must be provided for protocol version 1.4.1"),
                l1_gas_price,
            })
        } else {
            Self::L1Pegged(L1PeggedBatchFeeModelInput {
                fair_l2_gas_price,
                l1_gas_price,
            })
        }
    }

    pub fn stricter(self, other: BatchFeeInput) -> Self {
        match (self, other) {
            (BatchFeeInput::L1Pegged(first), BatchFeeInput::L1Pegged(second)) => Self::l1_pegged(
                first.l1_gas_price.max(second.l1_gas_price),
                first.fair_l2_gas_price.max(second.fair_l2_gas_price),
            ),
            input @ (_, _) => {
                let (first, second) = (
                    input.0.into_pubdata_independent(),
                    input.1.into_pubdata_independent(),
                );

                Self::pubdata_independent(
                    first.l1_gas_price.max(second.l1_gas_price),
                    first.fair_l2_gas_price.max(second.fair_l2_gas_price),
                    first.fair_pubdata_price.max(second.fair_pubdata_price),
                )
            }
        }
    }
}

impl Default for BatchFeeInput {
    fn default() -> Self {
        Self::L1Pegged(L1PeggedBatchFeeModelInput {
            l1_gas_price: 0,
            fair_l2_gas_price: 0,
        })
    }
}

/// Pubdata is only published via calldata and so its price is pegged to the L1 gas price.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct L1PeggedBatchFeeModelInput {
    pub fair_l2_gas_price: u64,
    pub l1_gas_price: u64,
}

/// Pubdata price may be independent from L1 gas price.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PubdataIndependentBatchFeeModelInput {
    pub fair_l2_gas_price: u64,
    pub fair_pubdata_price: u64,
    pub l1_gas_price: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct ConversionRatio {
    pub numerator: NonZeroU64,
    pub denominator: NonZeroU64,
}

impl ConversionRatio {
    pub fn reciprocal(&self) -> Self {
        Self {
            numerator: self.denominator,
            denominator: self.numerator,
        }
    }
}

impl Default for ConversionRatio {
    fn default() -> Self {
        Self {
            numerator: NonZeroU64::new(1).unwrap(),
            denominator: NonZeroU64::new(1).unwrap(),
        }
    }
}

/// BaseToken<->ETH conversion ratio.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BaseTokenConversionRatio {
    l1: Option<ConversionRatio>,
    sl: Option<ConversionRatio>,
    #[deprecated(note = "backwards compatibility for API")]
    numerator: NonZeroU64,
    #[deprecated(note = "backwards compatibility for API")]
    denominator: NonZeroU64,
}

#[allow(deprecated)]
impl BaseTokenConversionRatio {
    pub fn new_simple(l1_sl: ConversionRatio) -> Self {
        Self::new(l1_sl, l1_sl)
    }

    pub fn new(l1: ConversionRatio, sl: ConversionRatio) -> Self {
        Self {
            l1: Some(l1),
            sl: Some(sl),
            numerator: l1.numerator,
            denominator: l1.denominator,
        }
    }

    pub fn l1_conversion_ratio(&self) -> ConversionRatio {
        self.l1.unwrap_or(ConversionRatio {
            numerator: self.numerator,
            denominator: self.denominator,
        })
    }

    pub fn sl_conversion_ratio(&self) -> ConversionRatio {
        self.sl.unwrap_or_default()
    }
}

impl Default for BaseTokenConversionRatio {
    fn default() -> Self {
        Self::new_simple(ConversionRatio::default())
    }
}
