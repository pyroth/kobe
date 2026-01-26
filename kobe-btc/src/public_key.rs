//! Bitcoin public key implementation.

use crate::address::{BtcAddress, AddressFormat};
use crate::network::Network;
use kobe::{Error, Result, Signature};
use k256::ecdsa::{SigningKey, VerifyingKey, signature::hazmat::PrehashVerifier};

/// Bitcoin public key based on secp256k1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcPublicKey {
    inner: VerifyingKey,
    compressed: bool,
}

impl BtcPublicKey {
    /// Create from a signing key.
    pub(crate) fn from_signing_key(key: &SigningKey, compressed: bool) -> Self {
        Self {
            inner: *key.verifying_key(),
            compressed,
        }
    }
    
    /// Create from raw compressed bytes (33 bytes).
    pub fn from_compressed_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 33 {
            return Err(Error::InvalidLength {
                expected: 33,
                actual: bytes.len(),
            });
        }
        let inner = VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self {
            inner,
            compressed: true,
        })
    }
    
    /// Create from raw uncompressed bytes (65 bytes).
    pub fn from_uncompressed_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 65 {
            return Err(Error::InvalidLength {
                expected: 65,
                actual: bytes.len(),
            });
        }
        let inner = VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self {
            inner,
            compressed: false,
        })
    }
    
    /// Check if using compressed format.
    pub const fn is_compressed(&self) -> bool {
        self.compressed
    }
    
    /// Serialize to compressed bytes (33 bytes).
    pub fn to_compressed_bytes(&self) -> [u8; 33] {
        let point = self.inner.to_encoded_point(true);
        let mut result = [0u8; 33];
        result.copy_from_slice(point.as_bytes());
        result
    }
    
    /// Serialize to uncompressed bytes (65 bytes).
    pub fn to_uncompressed_bytes(&self) -> [u8; 65] {
        let point = self.inner.to_encoded_point(false);
        let mut result = [0u8; 65];
        result.copy_from_slice(point.as_bytes());
        result
    }
    
    /// Serialize to bytes (compressed or uncompressed based on setting).
    pub fn to_bytes(&self) -> [u8; 33] {
        self.to_compressed_bytes()
    }
    
    /// Get the hash160 of the public key (for P2PKH addresses).
    pub fn hash160(&self) -> [u8; 20] {
        let bytes = if self.compressed {
            self.to_compressed_bytes().to_vec()
        } else {
            self.to_uncompressed_bytes().to_vec()
        };
        kobe::hash::hash160(&bytes)
    }
    
    /// Derive a Bitcoin address.
    pub fn to_address(&self, network: Network, format: AddressFormat) -> Result<BtcAddress> {
        BtcAddress::from_public_key(self, network, format)
    }
    
    /// Verify a signature against a message hash.
    pub fn verify(&self, hash: &[u8; 32], signature: &Signature) -> Result<()> {
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&signature.r);
        sig_bytes[32..].copy_from_slice(&signature.s);
        
        let sig = k256::ecdsa::Signature::from_slice(&sig_bytes)
            .map_err(|_| Error::InvalidSignature)?;
        
        self.inner
            .verify_prehash(hash, &sig)
            .map_err(|_| Error::InvalidSignature)
    }
    
    /// Recover public key from signature and message hash.
    pub fn recover_from_prehash(hash: &[u8; 32], signature: &Signature, compressed: bool) -> Result<Self> {
        use k256::ecdsa::RecoveryId;
        
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&signature.r);
        sig_bytes[32..].copy_from_slice(&signature.s);
        
        let sig = k256::ecdsa::Signature::from_slice(&sig_bytes)
            .map_err(|_| Error::InvalidSignature)?;
        let recid = RecoveryId::from_byte(signature.v)
            .ok_or(Error::InvalidSignature)?;
        
        let recovered = VerifyingKey::recover_from_prehash(hash, &sig, recid)
            .map_err(|_| Error::InvalidSignature)?;
        
        Ok(Self {
            inner: recovered,
            compressed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BtcPrivateKey;
    
    #[test]
    fn test_public_key_derivation() {
        let bytes = hex_literal::hex!(
            "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
        );
        let private_key = BtcPrivateKey::from_bytes(&bytes).unwrap();
        let public_key = private_key.public_key();
        
        let compressed = public_key.to_compressed_bytes();
        assert_eq!(compressed.len(), 33);
        
        let recovered = BtcPublicKey::from_compressed_bytes(&compressed).unwrap();
        assert_eq!(public_key.to_compressed_bytes(), recovered.to_compressed_bytes());
    }
}
