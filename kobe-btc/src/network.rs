//! Bitcoin network types.

/// Bitcoin network type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Network {
    /// Bitcoin mainnet
    Mainnet,
    /// Bitcoin testnet
    Testnet,
}

impl Network {
    /// Get the P2PKH address prefix (version byte)
    pub const fn p2pkh_prefix(&self) -> u8 {
        match self {
            Self::Mainnet => 0x00,
            Self::Testnet => 0x6f,
        }
    }
    
    /// Get the P2SH address prefix (version byte)
    pub const fn p2sh_prefix(&self) -> u8 {
        match self {
            Self::Mainnet => 0x05,
            Self::Testnet => 0xc4,
        }
    }
    
    /// Get the WIF prefix (version byte)
    pub const fn wif_prefix(&self) -> u8 {
        match self {
            Self::Mainnet => 0x80,
            Self::Testnet => 0xef,
        }
    }
    
    /// Get the Bech32 human-readable part
    pub const fn bech32_hrp(&self) -> &'static str {
        match self {
            Self::Mainnet => "bc",
            Self::Testnet => "tb",
        }
    }
}

impl Default for Network {
    fn default() -> Self {
        Self::Mainnet
    }
}
