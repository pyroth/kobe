//! Core traits defining the wallet interface.

use crate::error::Result;
use core::fmt::{Debug, Display};
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "alloc")]
use alloc::string::String;

/// A private key that can sign messages and derive public keys.
pub trait PrivateKey: Clone + Debug + Sized + zeroize::Zeroize {
    /// The associated public key type
    type PublicKey: PublicKey;
    
    /// Generate a new random private key
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Self>;
    
    /// Create from raw bytes
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
    
    /// Serialize to raw bytes
    fn to_bytes(&self) -> [u8; 32];
    
    /// Derive the corresponding public key
    fn public_key(&self) -> Self::PublicKey;
    
    /// Sign a message hash (prehashed data)
    fn sign_prehash(&self, hash: &[u8; 32]) -> Result<Signature>;
}

/// A public key that can verify signatures and derive addresses.
pub trait PublicKey: Clone + Debug + PartialEq + Eq + Sized {
    /// The associated address type
    type Address: Address;
    
    /// Create from compressed bytes (33 bytes for secp256k1)
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
    
    /// Serialize to compressed bytes
    fn to_bytes(&self) -> [u8; 33];
    
    /// Serialize to uncompressed bytes (65 bytes with 0x04 prefix)
    fn to_uncompressed_bytes(&self) -> [u8; 65];
    
    /// Derive the address
    fn to_address(&self) -> Self::Address;
    
    /// Verify a signature
    fn verify(&self, hash: &[u8; 32], signature: &Signature) -> Result<()>;
}

/// A cryptocurrency address.
pub trait Address: Clone + Debug + Display + PartialEq + Eq + Sized {
    /// Parse from string representation
    #[cfg(feature = "alloc")]
    fn from_str(s: &str) -> Result<Self>;
    
    /// Convert to string representation
    #[cfg(feature = "alloc")]
    fn to_string(&self) -> String;
    
    /// Get the raw bytes of the address
    fn as_bytes(&self) -> &[u8];
}

/// An ECDSA signature with recovery ID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The r component (32 bytes)
    pub r: [u8; 32],
    /// The s component (32 bytes)
    pub s: [u8; 32],
    /// The recovery ID (0-3)
    pub v: u8,
}

impl Signature {
    /// Create a new signature from components
    pub const fn new(r: [u8; 32], s: [u8; 32], v: u8) -> Self {
        Self { r, s, v }
    }
    
    /// Create from 64-byte RS format plus recovery ID
    pub fn from_rs_v(rs: [u8; 64], v: u8) -> Self {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&rs[..32]);
        s.copy_from_slice(&rs[32..]);
        Self { r, s, v }
    }
    
    /// Serialize to 64-byte RS format
    pub fn to_rs(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        result[..32].copy_from_slice(&self.r);
        result[32..].copy_from_slice(&self.s);
        result
    }
    
    /// Serialize to 65-byte RSV format
    pub fn to_rsv(&self) -> [u8; 65] {
        let mut result = [0u8; 65];
        result[..32].copy_from_slice(&self.r);
        result[32..64].copy_from_slice(&self.s);
        result[64] = self.v;
        result
    }
    
    /// Serialize to 65-byte VRS format (used by some chains)
    pub fn to_vrs(&self) -> [u8; 65] {
        let mut result = [0u8; 65];
        result[0] = self.v;
        result[1..33].copy_from_slice(&self.r);
        result[33..].copy_from_slice(&self.s);
        result
    }
}

/// Extended key for hierarchical deterministic wallets (BIP-32).
pub trait ExtendedPrivateKey: Clone + Debug + Sized + zeroize::Zeroize {
    /// The associated private key type
    type PrivateKey: PrivateKey;
    
    /// Create master key from seed
    fn from_seed(seed: &[u8]) -> Result<Self>;
    
    /// Derive child key at given index (normal derivation)
    fn derive_child(&self, index: u32) -> Result<Self>;
    
    /// Derive child key at given index (hardened derivation)
    fn derive_child_hardened(&self, index: u32) -> Result<Self>;
    
    /// Derive from path string (e.g., "m/44'/60'/0'/0/0")
    #[cfg(feature = "alloc")]
    fn derive_path(&self, path: &str) -> Result<Self>;
    
    /// Get the underlying private key
    fn private_key(&self) -> Self::PrivateKey;
    
    /// Get the chain code
    fn chain_code(&self) -> [u8; 32];
    
    /// Get the depth in the derivation tree
    fn depth(&self) -> u8;
}

/// Mnemonic phrase for seed generation (BIP-39).
pub trait Mnemonic: Clone + Debug + Sized {
    /// Generate new mnemonic with specified word count (12, 15, 18, 21, 24)
    fn generate<R: RngCore + CryptoRng>(rng: &mut R, word_count: usize) -> Result<Self>;
    
    /// Create from existing phrase
    #[cfg(feature = "alloc")]
    fn from_phrase(phrase: &str) -> Result<Self>;
    
    /// Get the phrase as string
    #[cfg(feature = "alloc")]
    fn to_phrase(&self) -> String;
    
    /// Derive seed with optional passphrase
    fn to_seed(&self, passphrase: &str) -> [u8; 64];
    
    /// Get entropy bytes
    fn entropy(&self) -> &[u8];
}
