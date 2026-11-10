//! Basic VM types that shared widely enough to not put them in the `multivm` crate.

#[derive(Debug, Clone, Copy)]
pub enum VmVersion {
    M5WithoutRefunds,
    M5WithRefunds,
    M6Initial,
    M6BugWithCompressionFixed,
    Vm1_3_2,
    VmVirtualBlocks,
    VmVirtualBlocksRefundsEnhancement,
    VmBoojumIntegration,
    Vm1_4_1,
    Vm1_4_2,
    Vm1_5_0SmallBootloaderMemory,
    Vm1_5_0IncreasedBootloaderMemory,
    VmGateway,
    VmEvmEmulator,
    VmEcPrecompiles,
    VmInterop,
    VmMediumInterop,
    /// Protocol v34 and above. [`Self::VmMediumInterop`]'s bootloader and memory model plus the
    /// force-fail `txMeta` bit.
    VmMediumInteropForceFail,
}

impl VmVersion {
    /// Returns the latest supported VM version.
    pub const fn latest() -> VmVersion {
        Self::VmMediumInteropForceFail
    }
}
