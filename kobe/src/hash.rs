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

    mod sha256_tests {
        use super::*;

        #[test]
        fn test_sha256_hello() {
            let hash = sha256(b"hello");
            assert_eq!(
                hex::encode(hash),
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
            );
        }

        #[test]
        fn test_sha256_empty() {
            let hash = sha256(b"");
            assert_eq!(
                hex::encode(hash),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            );
        }

        #[test]
        fn test_sha256_abc() {
            let hash = sha256(b"abc");
            assert_eq!(
                hex::encode(hash),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
        }

        #[test]
        fn test_sha256_long_input() {
            let hash = sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
            assert_eq!(
                hex::encode(hash),
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
            );
        }

        #[test]
        fn test_sha256_deterministic() {
            let data = b"test determinism";
            assert_eq!(sha256(data), sha256(data));
        }

        #[test]
        fn test_sha256_output_length() {
            assert_eq!(sha256(b"any data").len(), 32);
        }
    }

    mod double_sha256_tests {
        use super::*;

        #[test]
        fn test_double_sha256_empty() {
            let hash = double_sha256(b"");
            assert_eq!(
                hex::encode(hash),
                "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
            );
        }

        #[test]
        fn test_double_sha256_hello() {
            let hash = double_sha256(b"hello");
            let expected = sha256(&sha256(b"hello"));
            assert_eq!(hash, expected);
        }

        #[test]
        fn test_double_sha256_bitcoin_block_header() {
            // Bitcoin genesis block header hash (reversed for display)
            let header = hex_literal::hex!(
                "0100000000000000000000000000000000000000000000000000000000000000"
                "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa"
                "4b1e5e4a29ab5f49ffff001d1dac2b7c"
            );
            let hash = double_sha256(&header);
            assert_eq!(hash.len(), 32);
        }

        #[test]
        fn test_double_sha256_deterministic() {
            let data = b"bitcoin transaction";
            assert_eq!(double_sha256(data), double_sha256(data));
        }
    }

    mod ripemd160_tests {
        use super::*;

        #[test]
        fn test_ripemd160_empty() {
            let hash = ripemd160(b"");
            assert_eq!(
                hex::encode(hash),
                "9c1185a5c5e9fc54612808977ee8f548b2258d31"
            );
        }

        #[test]
        fn test_ripemd160_hello() {
            let hash = ripemd160(b"hello");
            assert_eq!(
                hex::encode(hash),
                "108f07b8382412612c048d07d13f814118445acd"
            );
        }

        #[test]
        fn test_ripemd160_abc() {
            let hash = ripemd160(b"abc");
            assert_eq!(
                hex::encode(hash),
                "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"
            );
        }

        #[test]
        fn test_ripemd160_output_length() {
            assert_eq!(ripemd160(b"any data").len(), 20);
        }
    }

    mod hash160_tests {
        use super::*;

        #[test]
        fn test_hash160_hello() {
            let hash = hash160(b"hello");
            assert_eq!(
                hex::encode(hash),
                "b6a9c8c230722b7c748331a8b450f05566dc7d0f"
            );
        }

        #[test]
        fn test_hash160_empty() {
            let hash = hash160(b"");
            assert_eq!(
                hex::encode(hash),
                "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
            );
        }

        #[test]
        fn test_hash160_equals_ripemd160_of_sha256() {
            let data = b"test composition";
            let expected = ripemd160(&sha256(data));
            assert_eq!(hash160(data), expected);
        }

        #[test]
        fn test_hash160_bitcoin_pubkey() {
            // Compressed public key (33 bytes)
            let pubkey = hex_literal::hex!(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            );
            let hash = hash160(&pubkey);
            assert_eq!(
                hex::encode(hash),
                "751e76e8199196d454941c45d1b3a323f1433bd6"
            );
        }

        #[test]
        fn test_hash160_output_length() {
            assert_eq!(hash160(b"any data").len(), 20);
        }
    }

    mod keccak256_tests {
        use super::*;

        #[test]
        fn test_keccak256_hello() {
            let hash = keccak256(b"hello");
            assert_eq!(
                hex::encode(hash),
                "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
            );
        }

        #[test]
        fn test_keccak256_empty() {
            let hash = keccak256(b"");
            assert_eq!(
                hex::encode(hash),
                "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
            );
        }

        #[test]
        fn test_keccak256_ethereum_address() {
            // Ethereum uses keccak256 for address derivation
            let pubkey = hex_literal::hex!(
                "04"
                "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
            );
            let hash = keccak256(&pubkey[1..]); // Skip 0x04 prefix
            // Address is last 20 bytes
            assert_eq!(
                &hash[12..],
                hex_literal::hex!("7e5f4552091a69125d5dfcb7b8c2659029395bdf")
            );
        }

        #[test]
        fn test_keccak256_eip191_prefix() {
            // Ethereum signed message prefix
            let prefix = b"\x19Ethereum Signed Message:\n";
            let hash = keccak256(prefix);
            assert_eq!(hash.len(), 32);
        }

        #[test]
        fn test_keccak256_output_length() {
            assert_eq!(keccak256(b"any data").len(), 32);
        }

        #[test]
        fn test_keccak256_deterministic() {
            let data = b"ethereum transaction";
            assert_eq!(keccak256(data), keccak256(data));
        }
    }

    mod collision_resistance_tests {
        use super::*;

        #[test]
        fn test_sha256_different_inputs_different_outputs() {
            assert_ne!(sha256(b"hello"), sha256(b"hello!"));
            assert_ne!(sha256(b"a"), sha256(b"b"));
            assert_ne!(sha256(b""), sha256(b" "));
        }

        #[test]
        fn test_keccak256_different_inputs_different_outputs() {
            assert_ne!(keccak256(b"hello"), keccak256(b"hello!"));
            assert_ne!(keccak256(b"a"), keccak256(b"b"));
        }

        #[test]
        fn test_hash160_different_inputs_different_outputs() {
            assert_ne!(hash160(b"hello"), hash160(b"hello!"));
            assert_ne!(hash160(b"a"), hash160(b"b"));
        }
    }
}
