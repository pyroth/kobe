//! Encoding utilities for cryptocurrency addresses and keys.

#[cfg(feature = "alloc")]
use alloc::string::String;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::error::{Error, Result};
use crate::hash::double_sha256;

/// Encode bytes to hexadecimal string
#[cfg(feature = "alloc")]
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(HEX_CHARS[(byte >> 4) as usize] as char);
        result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    result
}

/// Decode hexadecimal string to bytes
#[cfg(feature = "alloc")]
pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return Err(Error::InvalidEncoding);
    }

    let mut result = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let high = hex_char_to_nibble(chunk[0])?;
        let low = hex_char_to_nibble(chunk[1])?;
        result.push((high << 4) | low);
    }
    Ok(result)
}

#[inline]
fn hex_char_to_nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::InvalidEncoding),
    }
}

/// Encode bytes to Base58Check (used in Bitcoin)
#[cfg(feature = "alloc")]
pub fn base58check_encode(version: &[u8], payload: &[u8]) -> String {
    let mut data = Vec::with_capacity(version.len() + payload.len() + 4);
    data.extend_from_slice(version);
    data.extend_from_slice(payload);

    let checksum = double_sha256(&data);
    data.extend_from_slice(&checksum[..4]);

    bs58::encode(data).into_string()
}

/// Decode Base58Check encoded string
#[cfg(feature = "alloc")]
pub fn base58check_decode(encoded: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let data = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| Error::InvalidEncoding)?;

    if data.len() < 5 {
        return Err(Error::InvalidLength {
            expected: 5,
            actual: data.len(),
        });
    }

    let (payload, checksum) = data.split_at(data.len() - 4);
    let computed_checksum = double_sha256(payload);

    if checksum != &computed_checksum[..4] {
        return Err(Error::InvalidChecksum);
    }

    // Assume first byte is version for Bitcoin-style addresses
    Ok((payload[..1].to_vec(), payload[1..].to_vec()))
}

/// Compute checksum for Ethereum address (EIP-55)
#[cfg(feature = "alloc")]
pub fn eth_checksum_address(address: &[u8; 20]) -> String {
    let hex_addr = to_hex(address);
    let hash = crate::hash::keccak256(hex_addr.as_bytes());

    let mut result = String::with_capacity(42);
    result.push_str("0x");

    for (i, c) in hex_addr.chars().enumerate() {
        if c.is_ascii_alphabetic() {
            let hash_nibble = if i % 2 == 0 {
                hash[i / 2] >> 4
            } else {
                hash[i / 2] & 0x0f
            };

            if hash_nibble >= 8 {
                result.push(c.to_ascii_uppercase());
            } else {
                result.push(c.to_ascii_lowercase());
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Encode using Bech32 (used in Bitcoin SegWit)
#[cfg(feature = "alloc")]
pub fn bech32_encode(hrp: &str, version: u8, data: &[u8]) -> Result<String> {
    use bech32::Hrp;

    let hrp = Hrp::parse(hrp).map_err(|_| Error::InvalidEncoding)?;
    let mut encoded_data = Vec::with_capacity(data.len() + 1);
    encoded_data.push(version);
    encoded_data.extend_from_slice(data);

    bech32::encode::<bech32::Bech32m>(hrp, &encoded_data).map_err(|_| Error::InvalidEncoding)
}

/// Decode Bech32 encoded string
#[cfg(feature = "alloc")]
pub fn bech32_decode(encoded: &str) -> Result<(String, u8, Vec<u8>)> {
    let (hrp, data) = bech32::decode(encoded).map_err(|_| Error::InvalidEncoding)?;

    if data.is_empty() {
        return Err(Error::InvalidLength {
            expected: 1,
            actual: 0,
        });
    }

    let version = data[0];
    let payload = data[1..].to_vec();

    Ok((hrp.to_string(), version, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_roundtrip() {
        let original = [0xde, 0xad, 0xbe, 0xef];
        let encoded = to_hex(&original);
        assert_eq!(encoded, "deadbeef");
        let decoded = from_hex(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_hex_with_prefix() {
        let decoded = from_hex("0xdeadbeef").unwrap();
        assert_eq!(decoded, [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_eth_checksum_address() {
        let addr: [u8; 20] = hex_literal::hex!("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
        let checksummed = eth_checksum_address(&addr);
        assert_eq!(checksummed, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }
}
