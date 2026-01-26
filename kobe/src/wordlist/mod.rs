//! BIP-39 wordlists for mnemonic phrase generation.
//!
//! This module provides wordlists in multiple languages for BIP-39 mnemonic phrases.
//!
//! # Supported Languages
//!
//! - Chinese (Simplified)
//! - Chinese (Traditional)
//! - English (default)
//! - French
//! - Italian
//! - Japanese
//! - Korean
//! - Spanish

pub mod bip39;
pub mod traits;

pub use self::bip39::Language;
pub use self::traits::{Wordlist, WordlistError};
