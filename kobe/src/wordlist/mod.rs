//! BIP-39 wordlists for mnemonic phrase generation.
//!
//! This module provides wordlists in multiple languages for BIP-39 mnemonic phrases.

pub mod bip39;
pub mod traits;

pub use self::traits::{Wordlist, WordlistError};
