//! # Kobe-ETH - Ethereum Wallet Support
//!
//! Ethereum wallet implementation for the Kobe wallet library.
//! Provides private key, public key, address, and signing functionality.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod address;
mod private_key;
mod public_key;

pub use address::EthAddress;
pub use private_key::EthPrivateKey;
pub use public_key::EthPublicKey;

pub use kobe::{Error, Result, Signature};
