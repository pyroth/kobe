//! Wordlist trait and error types.

use core::fmt::{Debug, Display};

#[cfg(feature = "alloc")]
use alloc::string::String;

/// The interface for a generic wordlist.
pub trait Wordlist: Copy + Clone + Debug + Send + Sync + 'static + Eq + Sized {
    /// Get the word at the given index.
    fn get_word(index: usize) -> Option<&'static str>;
    
    /// Get the index of the given word.
    fn get_index(word: &str) -> Option<usize>;
    
    /// Get all words in the wordlist.
    fn get_all() -> &'static [&'static str];
}

/// Errors related to wordlist operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WordlistError {
    /// Invalid index in wordlist.
    InvalidIndex(usize),
    /// Invalid word not found in wordlist.
    #[cfg(feature = "alloc")]
    InvalidWord(String),
    /// Invalid word (static message for no_std).
    #[cfg(not(feature = "alloc"))]
    InvalidWord,
}

impl Display for WordlistError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidIndex(i) => write!(f, "invalid wordlist index: {}", i),
            #[cfg(feature = "alloc")]
            Self::InvalidWord(w) => write!(f, "invalid word: {}", w),
            #[cfg(not(feature = "alloc"))]
            Self::InvalidWord => write!(f, "invalid word"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for WordlistError {}
