//! Ethereum public key implementation.
//!
//! Implements `kobe::PublicKey` trait for unified wallet interface.

use crate::address::EthAddress;
use k256::ecdsa::{SigningKey, VerifyingKey, signature::hazmat::PrehashVerifier};
use kobe::{Error, Result, Signature};

/// Ethereum public key based on secp256k1.
///
/// Provides signature verification and address derivation for Ethereum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthPublicKey {
    inner: VerifyingKey,
}

impl EthPublicKey {
    /// Create from a signing key.
    pub(crate) fn from_signing_key(key: &SigningKey) -> Self {
        Self {
            inner: *key.verifying_key(),
        }
    }

    /// Get the raw 64-byte public key (without 0x04 prefix).
    #[inline]
    #[must_use]
    pub fn to_raw_bytes(&self) -> [u8; 64] {
        let uncompressed = kobe::PublicKey::to_uncompressed_bytes(self);
        let mut result = [0u8; 64];
        result.copy_from_slice(&uncompressed[1..]);
        result
    }
}

impl kobe::PublicKey for EthPublicKey {
    type Address = EthAddress;

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self { inner })
    }

    fn to_bytes(&self) -> [u8; 33] {
        let point = self.inner.to_encoded_point(true);
        let mut result = [0u8; 33];
        result.copy_from_slice(point.as_bytes());
        result
    }

    fn to_uncompressed_bytes(&self) -> [u8; 65] {
        let point = self.inner.to_encoded_point(false);
        let mut result = [0u8; 65];
        result.copy_from_slice(point.as_bytes());
        result
    }

    fn to_address(&self) -> Self::Address {
        EthAddress::from_public_key(self)
    }

    fn verify(&self, hash: &[u8; 32], signature: &Signature) -> Result<()> {
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&signature.r);
        sig_bytes[32..].copy_from_slice(&signature.s);

        let sig =
            k256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|_| Error::InvalidSignature)?;

        self.inner
            .verify_prehash(hash, &sig)
            .map_err(|_| Error::InvalidSignature)
    }
}

impl EthPublicKey {
    /// Recover public key from signature and message hash.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid or recovery fails.
    pub fn recover_from_prehash(hash: &[u8; 32], signature: &Signature) -> Result<Self> {
        use k256::ecdsa::RecoveryId;

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&signature.r);
        sig_bytes[32..].copy_from_slice(&signature.s);

        let sig =
            k256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|_| Error::InvalidSignature)?;
        let recid = RecoveryId::from_byte(signature.v).ok_or(Error::InvalidSignature)?;

        let recovered = VerifyingKey::recover_from_prehash(hash, &sig, recid)
            .map_err(|_| Error::InvalidSignature)?;

        Ok(Self { inner: recovered })
    }

    /// Recover public key from an EIP-191 personal signed message.
    ///
    /// This is the inverse of `EthPrivateKey::sign_message`.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid or recovery fails.
    pub fn recover_from_message(message: &[u8], signature: &Signature) -> Result<Self> {
        let hash = eip191_hash_message(message);
        Self::recover_from_prehash(&hash, signature)
    }
}

/// Compute EIP-191 message hash (same as in private_key.rs).
fn eip191_hash_message(message: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};

    let prefix_start = b"\x19Ethereum Signed Message:\n";
    let (len_buf, len_used) = format_usize(message.len());

    let mut hasher = Keccak256::new();
    hasher.update(prefix_start);
    hasher.update(&len_buf[..len_used]);
    hasher.update(message);
    hasher.finalize().into()
}

/// Format usize as string (no_std compatible).
fn format_usize(mut n: usize) -> ([u8; 20], usize) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();

    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }

    let len = buf.len() - i;
    buf.copy_within(i.., 0);
    (buf, len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EthPrivateKey;
    use kobe::{PrivateKey, PublicKey};

    #[test]
    fn test_public_key_derivation() {
        let private_key: EthPrivateKey =
            "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
                .parse()
                .unwrap();
        let public_key = private_key.public_key();
        let compressed = public_key.to_bytes();
        assert_eq!(compressed.len(), 33);

        let recovered = EthPublicKey::from_bytes(&compressed).unwrap();
        assert_eq!(public_key, recovered);
    }

    #[test]
    fn test_sign_and_verify() {
        let private_key: EthPrivateKey =
            "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
                .parse()
                .unwrap();
        let public_key = private_key.public_key();

        let hash = [0u8; 32];
        let signature = private_key.sign_prehash(&hash).unwrap();

        public_key.verify(&hash, &signature).unwrap();
    }

    #[test]
    fn test_recover() {
        let private_key: EthPrivateKey =
            "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
                .parse()
                .unwrap();
        let public_key = private_key.public_key();

        let hash = [1u8; 32];
        let signature = private_key.sign_prehash(&hash).unwrap();

        let recovered = EthPublicKey::recover_from_prehash(&hash, &signature).unwrap();
        assert_eq!(public_key, recovered);
    }

    #[test]
    fn test_recover_from_message() {
        let private_key: EthPrivateKey =
            "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
                .parse()
                .unwrap();
        let expected_address = private_key.address();

        let message = b"Hello, Ethereum!";
        let signature = private_key.sign_message(message).unwrap();

        // Recover public key from message signature
        let recovered = EthPublicKey::recover_from_message(message, &signature).unwrap();
        let recovered_address = recovered.to_address();

        assert_eq!(expected_address, recovered_address);
    }
}
