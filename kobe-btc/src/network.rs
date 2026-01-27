//! Bitcoin network types.

use bitcoin::Network as BtcNetwork;
use core::fmt;

/// Supported Bitcoin networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Network {
    /// Bitcoin mainnet.
    #[default]
    Mainnet,
    /// Bitcoin testnet.
    Testnet,
}

impl Network {
    /// Convert to bitcoin crate's Network type.
    #[inline]
    #[must_use]
    pub const fn to_bitcoin_network(self) -> BtcNetwork {
        match self {
            Self::Mainnet => BtcNetwork::Bitcoin,
            Self::Testnet => BtcNetwork::Testnet,
        }
    }

    /// Get the BIP44 coin type for this network.
    #[inline]
    #[must_use]
    pub const fn coin_type(self) -> u32 {
        match self {
            Self::Mainnet => 0,
            Self::Testnet => 1,
        }
    }

    /// Get network name as string.
    #[inline]
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}
