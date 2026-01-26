//! Cryptographic hash functions used in cryptocurrency operations.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// Compute SHA-256 hash
#[inline]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute double SHA-256 hash (used in Bitcoin)
#[inline]
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// Compute RIPEMD-160 hash
#[inline]
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute Hash160 (SHA-256 followed by RIPEMD-160, used in Bitcoin)
#[inline]
pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

/// Compute Keccak-256 hash (used in Ethereum)
#[inline]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = b"hello";
        let hash = sha256(data);
        assert_eq!(
            hex::encode(hash),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_keccak256() {
        let data = b"hello";
        let hash = keccak256(data);
        assert_eq!(
            hex::encode(hash),
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn test_hash160() {
        let data = b"hello";
        let hash = hash160(data);
        assert_eq!(
            hex::encode(hash),
            "b6a9c8c230722b7c748331a8b450f05566dc7d0f"
        );
    }
}
