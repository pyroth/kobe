//! Ethereum public key implementation.

use crate::address::EthAddress;
use k256::ecdsa::{SigningKey, VerifyingKey, signature::hazmat::PrehashVerifier};
use kobe::{Error, Result, Signature};

/// Ethereum public key based on secp256k1.
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

    /// Create from raw compressed bytes (33 bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inner = VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self { inner })
    }

    /// Serialize to compressed bytes (33 bytes).
    pub fn to_bytes(&self) -> [u8; 33] {
        let point = self.inner.to_encoded_point(true);
        let mut result = [0u8; 33];
        result.copy_from_slice(point.as_bytes());
        result
    }

    /// Serialize to uncompressed bytes (65 bytes with 0x04 prefix).
    pub fn to_uncompressed_bytes(&self) -> [u8; 65] {
        let point = self.inner.to_encoded_point(false);
        let mut result = [0u8; 65];
        result.copy_from_slice(point.as_bytes());
        result
    }

    /// Get the raw 64-byte public key (without 0x04 prefix).
    pub fn to_raw_bytes(&self) -> [u8; 64] {
        let uncompressed = self.to_uncompressed_bytes();
        let mut result = [0u8; 64];
        result.copy_from_slice(&uncompressed[1..]);
        result
    }

    /// Derive the Ethereum address.
    pub fn to_address(&self) -> EthAddress {
        EthAddress::from_public_key(self)
    }

    /// Verify a signature against a message hash.
    pub fn verify(&self, hash: &[u8; 32], signature: &Signature) -> Result<()> {
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&signature.r);
        sig_bytes[32..].copy_from_slice(&signature.s);

        let sig =
            k256::ecdsa::Signature::from_slice(&sig_bytes).map_err(|_| Error::InvalidSignature)?;

        self.inner
            .verify_prehash(hash, &sig)
            .map_err(|_| Error::InvalidSignature)
    }

    /// Recover public key from signature and message hash.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EthPrivateKey;

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
}
