//! Ethereum network definitions.
//!
//! Provides type-safe network selection for transactions and key derivation.
//!
//! # Example
//!
//! ```rust,ignore
//! use kobe_eth::{Network, EthTransaction};
//!
//! // Create a mainnet transaction
//! let tx = EthTransaction::transfer(
//!     Network::Mainnet,
//!     recipient,
//!     value,
//!     nonce,
//!     gas_price,
//! );
//!
//! // Or use a custom network
//! let arbitrum = Network::custom("Arbitrum One", 42161);
//! ```

use core::fmt;

#[cfg(feature = "alloc")]
use alloc::string::String;

/// Ethereum network identifier.
///
/// Provides type-safe network selection with common networks pre-defined.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum Network {
    /// Ethereum Mainnet (Chain ID: 1)
    #[default]
    Mainnet,
    /// Sepolia Testnet (Chain ID: 11155111)
    Sepolia,
    /// Goerli Testnet (Chain ID: 5) - Deprecated
    Goerli,
    /// Binance Smart Chain (Chain ID: 56)
    BinanceSmartChain,
    /// Polygon/Matic (Chain ID: 137)
    Polygon,
    /// Arbitrum One (Chain ID: 42161)
    Arbitrum,
    /// Optimism (Chain ID: 10)
    Optimism,
    /// Avalanche C-Chain (Chain ID: 43114)
    Avalanche,
    /// Base (Chain ID: 8453)
    Base,
    /// Custom network with name and chain ID
    #[cfg(feature = "alloc")]
    Custom {
        /// Network name
        name: String,
        /// Chain ID
        chain_id: u64,
    },
}

impl Network {
    /// Get the chain ID for this network.
    pub const fn chain_id(&self) -> u64 {
        match self {
            Self::Mainnet => 1,
            Self::Sepolia => 11155111,
            Self::Goerli => 5,
            Self::BinanceSmartChain => 56,
            Self::Polygon => 137,
            Self::Arbitrum => 42161,
            Self::Optimism => 10,
            Self::Avalanche => 43114,
            Self::Base => 8453,
            #[cfg(feature = "alloc")]
            Self::Custom { chain_id, .. } => *chain_id,
        }
    }

    /// Get the network name.
    pub fn name(&self) -> &str {
        match self {
            Self::Mainnet => "Ethereum Mainnet",
            Self::Sepolia => "Sepolia Testnet",
            Self::Goerli => "Goerli Testnet",
            Self::BinanceSmartChain => "BNB Smart Chain",
            Self::Polygon => "Polygon",
            Self::Arbitrum => "Arbitrum One",
            Self::Optimism => "Optimism",
            Self::Avalanche => "Avalanche C-Chain",
            Self::Base => "Base",
            #[cfg(feature = "alloc")]
            Self::Custom { name, .. } => name,
        }
    }

    /// Get the HD wallet coin type (BIP-44).
    ///
    /// Returns 60 for mainnet networks, 1 for testnets.
    pub const fn coin_type(&self) -> u32 {
        match self {
            Self::Mainnet
            | Self::BinanceSmartChain
            | Self::Polygon
            | Self::Arbitrum
            | Self::Optimism
            | Self::Avalanche
            | Self::Base => 60,
            Self::Sepolia | Self::Goerli => 1,
            #[cfg(feature = "alloc")]
            Self::Custom { .. } => 60,
        }
    }

    /// Check if this is a testnet.
    pub const fn is_testnet(&self) -> bool {
        matches!(self, Self::Sepolia | Self::Goerli)
    }

    /// Check if this is Ethereum mainnet.
    pub const fn is_mainnet(&self) -> bool {
        matches!(self, Self::Mainnet)
    }

    /// Check if this network supports EIP-1559.
    pub const fn supports_eip1559(&self) -> bool {
        match self {
            Self::Mainnet
            | Self::Sepolia
            | Self::Goerli
            | Self::Polygon
            | Self::Arbitrum
            | Self::Optimism
            | Self::Base => true,
            Self::BinanceSmartChain | Self::Avalanche => false,
            #[cfg(feature = "alloc")]
            Self::Custom { .. } => true,
        }
    }

    /// Get the native currency symbol.
    pub const fn currency_symbol(&self) -> &str {
        match self {
            Self::Mainnet | Self::Sepolia | Self::Goerli => "ETH",
            Self::BinanceSmartChain => "BNB",
            Self::Polygon => "MATIC",
            Self::Arbitrum | Self::Optimism | Self::Base => "ETH",
            Self::Avalanche => "AVAX",
            #[cfg(feature = "alloc")]
            Self::Custom { .. } => "ETH",
        }
    }

    /// Get the block explorer URL (if available).
    #[cfg(feature = "alloc")]
    pub fn explorer_url(&self) -> Option<&str> {
        match self {
            Self::Mainnet => Some("https://etherscan.io"),
            Self::Sepolia => Some("https://sepolia.etherscan.io"),
            Self::Goerli => Some("https://goerli.etherscan.io"),
            Self::BinanceSmartChain => Some("https://bscscan.com"),
            Self::Polygon => Some("https://polygonscan.com"),
            Self::Arbitrum => Some("https://arbiscan.io"),
            Self::Optimism => Some("https://optimistic.etherscan.io"),
            Self::Avalanche => Some("https://snowtrace.io"),
            Self::Base => Some("https://basescan.org"),
            Self::Custom { .. } => None,
        }
    }

    /// Create a custom network.
    #[cfg(feature = "alloc")]
    pub fn custom(name: impl Into<String>, chain_id: u64) -> Self {
        Self::Custom {
            name: name.into(),
            chain_id,
        }
    }

    /// Get the standard derivation path for this network.
    #[cfg(feature = "alloc")]
    pub fn derivation_path(&self, account: u32, index: u32) -> String {
        alloc::format!("m/44'/{}'/{}'/0/{}", self.coin_type(), account, index)
    }

    /// Get all predefined networks.
    pub const fn all() -> &'static [Network] {
        &[
            Self::Mainnet,
            Self::Sepolia,
            Self::Goerli,
            Self::BinanceSmartChain,
            Self::Polygon,
            Self::Arbitrum,
            Self::Optimism,
            Self::Avalanche,
            Self::Base,
        ]
    }

    /// Create from chain ID.
    pub fn from_chain_id(chain_id: u64) -> Option<Self> {
        match chain_id {
            1 => Some(Self::Mainnet),
            5 => Some(Self::Goerli),
            10 => Some(Self::Optimism),
            56 => Some(Self::BinanceSmartChain),
            137 => Some(Self::Polygon),
            8453 => Some(Self::Base),
            42161 => Some(Self::Arbitrum),
            43114 => Some(Self::Avalanche),
            11155111 => Some(Self::Sepolia),
            _ => None,
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (Chain ID: {})", self.name(), self.chain_id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mainnet() {
        let net = Network::Mainnet;
        assert_eq!(net.chain_id(), 1);
        assert_eq!(net.name(), "Ethereum Mainnet");
        assert!(!net.is_testnet());
        assert!(net.is_mainnet());
        assert!(net.supports_eip1559());
    }

    #[test]
    fn test_sepolia() {
        let net = Network::Sepolia;
        assert_eq!(net.chain_id(), 11155111);
        assert!(net.is_testnet());
        assert_eq!(net.coin_type(), 1);
    }

    #[test]
    fn test_bsc() {
        let net = Network::BinanceSmartChain;
        assert_eq!(net.chain_id(), 56);
        assert_eq!(net.currency_symbol(), "BNB");
        assert!(!net.supports_eip1559());
    }

    #[test]
    fn test_polygon() {
        let net = Network::Polygon;
        assert_eq!(net.chain_id(), 137);
        assert_eq!(net.currency_symbol(), "MATIC");
    }

    #[test]
    fn test_from_chain_id() {
        assert_eq!(Network::from_chain_id(1), Some(Network::Mainnet));
        assert_eq!(Network::from_chain_id(137), Some(Network::Polygon));
        assert_eq!(Network::from_chain_id(999999), None);
    }

    #[test]
    fn test_derivation_path() {
        let net = Network::Mainnet;
        assert_eq!(net.derivation_path(0, 0), "m/44'/60'/0'/0/0");

        let testnet = Network::Sepolia;
        assert_eq!(testnet.derivation_path(0, 0), "m/44'/1'/0'/0/0");
    }

    #[test]
    fn test_display() {
        let net = Network::Mainnet;
        assert_eq!(net.to_string(), "Ethereum Mainnet (Chain ID: 1)");
    }

    #[test]
    fn test_all_networks() {
        let all = Network::all();
        assert!(all.len() >= 9);
    }
}
