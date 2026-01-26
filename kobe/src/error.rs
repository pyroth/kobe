//! Error types for the Kobe wallet library.

#[cfg(feature = "alloc")]
use alloc::string::String;

use core::fmt;

/// A specialized Result type for Kobe operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors that can occur in the Kobe wallet library.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Invalid private key
    InvalidPrivateKey,
    /// Invalid public key
    InvalidPublicKey,
    /// Invalid signature
    InvalidSignature,
    /// Invalid address format
    InvalidAddress,
    /// Invalid checksum
    InvalidChecksum,
    /// Invalid length for the given operation
    InvalidLength {
        /// Expected length
        expected: usize,
        /// Actual length
        actual: usize,
    },
    /// Invalid encoding (hex, base58, etc.)
    InvalidEncoding,
    /// Invalid derivation path
    InvalidDerivationPath,
    /// Invalid mnemonic phrase
    InvalidMnemonic,
    /// Invalid word in mnemonic
    InvalidWord,
    /// Invalid entropy length
    InvalidEntropyLength,
    /// Cryptographic operation failed
    CryptoError,
    /// Message with description
    #[cfg(feature = "alloc")]
    Message(String),
    /// Static message without allocation
    StaticMessage(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrivateKey => write!(f, "invalid private key"),
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::InvalidAddress => write!(f, "invalid address"),
            Self::InvalidChecksum => write!(f, "invalid checksum"),
            Self::InvalidLength { expected, actual } => {
                write!(f, "invalid length: expected {}, got {}", expected, actual)
            }
            Self::InvalidEncoding => write!(f, "invalid encoding"),
            Self::InvalidDerivationPath => write!(f, "invalid derivation path"),
            Self::InvalidMnemonic => write!(f, "invalid mnemonic"),
            Self::InvalidWord => write!(f, "invalid word in mnemonic"),
            Self::InvalidEntropyLength => write!(f, "invalid entropy length"),
            Self::CryptoError => write!(f, "cryptographic error"),
            #[cfg(feature = "alloc")]
            Self::Message(msg) => write!(f, "{}", msg),
            Self::StaticMessage(msg) => write!(f, "{}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<k256::ecdsa::Error> for Error {
    fn from(_: k256::ecdsa::Error) -> Self {
        Self::CryptoError
    }
}

impl From<k256::elliptic_curve::Error> for Error {
    fn from(_: k256::elliptic_curve::Error) -> Self {
        Self::CryptoError
    }
}
