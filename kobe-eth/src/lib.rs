//! # Kobe-ETH - Ethereum Wallet Support
//!
//! Ethereum wallet implementation for the Kobe wallet library.
//! Provides private key, public key, address, HD wallets, and signing functionality.
//!
//! ## Features
//!
//! - **Private/Public Key Management**: secp256k1 key generation and manipulation
//! - **Address Generation**: EIP-55 checksummed addresses
//! - **BIP-32 HD Wallets**: Hierarchical deterministic key derivation
//! - **BIP-39 Mnemonics**: Mnemonic phrase generation and seed derivation
//! - **Message Signing**: EIP-191 and EIP-712 signing support

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod address;
mod extended_key;
mod extended_public_key;
mod mnemonic;
mod network;
mod private_key;
mod public_key;
mod transaction;

pub use address::EthAddress;
pub use extended_key::ExtendedPrivateKey;
pub use extended_public_key::ExtendedPublicKey;
pub use mnemonic::Mnemonic;
pub use kobe::wordlist::bip39::Language;
pub use network::Network;
pub use private_key::EthPrivateKey;
pub use public_key::EthPublicKey;
pub use transaction::{Eip1559Transaction, EthTransaction, EthTxId};

// Re-export kobe core types and traits
pub use kobe::{Error, Result, Signature};
pub use kobe::{
    Address, ExtendedPrivateKey as ExtendedPrivateKeyTrait,
    ExtendedPublicKey as ExtendedPublicKeyTrait, Mnemonic as MnemonicTrait, PrivateKey, PublicKey,
};
