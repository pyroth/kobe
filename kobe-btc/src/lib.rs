//! Bitcoin wallet utilities for Kobe CLI.
//!
//! Provides Bitcoin address derivation from a unified [`kobe_core::Wallet`].
//!
//! # Features
//!
//! - `std` (default): Enable standard library support
//! - `alloc`: Enable heap allocation without full std (for `no_std` environments)
//! - `rand`: Enable random key generation for `StandardWallet`
//!
//! # Usage
//!
//! ```ignore
//! use kobe_core::Wallet;
//! use kobe_btc::{Deriver, Network, AddressType};
//!
//! // Create a wallet from kobe-core
//! let wallet = Wallet::generate(12, None).unwrap();
//!
//! // Derive Bitcoin addresses from the wallet
//! let deriver = Deriver::new(&wallet, Network::Mainnet).unwrap();
//! let addr = deriver.derive(AddressType::P2wpkh, 0, false, 0).unwrap();
//! println!("Address: {}", addr.address);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod deriver;
mod error;
mod network;
mod standard_wallet;
mod types;

pub use deriver::{DerivedAddress, Deriver};
pub use error::Error;
pub use network::Network;
pub use standard_wallet::StandardWallet;
pub use types::{AddressType, DerivationPath};
