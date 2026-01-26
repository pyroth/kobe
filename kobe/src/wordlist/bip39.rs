//! BIP-39 wordlists for various languages.
//!
//! Provides wordlists in 8 languages as defined by BIP-39.

/// Chinese Simplified BIP-39 wordlist (2048 words).
pub const CHINESE_SIMPLIFIED: &str = include_str!("./bip39/chinese_simplified.txt");
/// Chinese Traditional BIP-39 wordlist (2048 words).
pub const CHINESE_TRADITIONAL: &str = include_str!("./bip39/chinese_traditional.txt");
/// English BIP-39 wordlist (2048 words).
pub const ENGLISH: &str = include_str!("./bip39/english.txt");
/// French BIP-39 wordlist (2048 words).
pub const FRENCH: &str = include_str!("./bip39/french.txt");
/// Italian BIP-39 wordlist (2048 words).
pub const ITALIAN: &str = include_str!("./bip39/italian.txt");
/// Japanese BIP-39 wordlist (2048 words).
pub const JAPANESE: &str = include_str!("./bip39/japanese.txt");
/// Korean BIP-39 wordlist (2048 words).
pub const KOREAN: &str = include_str!("./bip39/korean.txt");
/// Spanish BIP-39 wordlist (2048 words).
pub const SPANISH: &str = include_str!("./bip39/spanish.txt");

/// BIP-39 supported languages.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Language {
    /// Chinese Simplified
    ChineseSimplified,
    /// Chinese Traditional
    ChineseTraditional,
    /// English (default)
    #[default]
    English,
    /// French
    French,
    /// Italian
    Italian,
    /// Japanese
    Japanese,
    /// Korean
    Korean,
    /// Spanish
    Spanish,
}

impl Language {
    /// Get the wordlist for this language as a raw string.
    pub const fn wordlist_str(&self) -> &'static str {
        match self {
            Self::ChineseSimplified => CHINESE_SIMPLIFIED,
            Self::ChineseTraditional => CHINESE_TRADITIONAL,
            Self::English => ENGLISH,
            Self::French => FRENCH,
            Self::Italian => ITALIAN,
            Self::Japanese => JAPANESE,
            Self::Korean => KOREAN,
            Self::Spanish => SPANISH,
        }
    }

    /// Get the word at the given index for this language.
    pub fn get_word(&self, index: usize) -> Option<&'static str> {
        if index >= 2048 {
            return None;
        }
        self.wordlist_str().lines().nth(index)
    }

    /// Get the index of the given word for this language.
    pub fn get_index(&self, word: &str) -> Option<usize> {
        self.wordlist_str().lines().position(|w| w == word)
    }

    /// Get all available languages.
    pub const fn all() -> &'static [Language] {
        &[
            Self::ChineseSimplified,
            Self::ChineseTraditional,
            Self::English,
            Self::French,
            Self::Italian,
            Self::Japanese,
            Self::Korean,
            Self::Spanish,
        ]
    }

    /// Get the language name as a string.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::ChineseSimplified => "Chinese (Simplified)",
            Self::ChineseTraditional => "Chinese (Traditional)",
            Self::English => "English",
            Self::French => "French",
            Self::Italian => "Italian",
            Self::Japanese => "Japanese",
            Self::Korean => "Korean",
            Self::Spanish => "Spanish",
        }
    }

    /// Get the ISO 639-1 language code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ChineseSimplified => "zh-Hans",
            Self::ChineseTraditional => "zh-Hant",
            Self::English => "en",
            Self::French => "fr",
            Self::Italian => "it",
            Self::Japanese => "ja",
            Self::Korean => "ko",
            Self::Spanish => "es",
        }
    }
}

impl core::fmt::Display for Language {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_english_wordlist_length() {
        assert_eq!(ENGLISH.lines().count(), 2048);
    }

    #[test]
    fn test_all_wordlists_length() {
        for lang in Language::all() {
            assert_eq!(
                lang.wordlist_str().lines().count(),
                2048,
                "Wordlist for {} should have 2048 words",
                lang.name()
            );
        }
    }

    #[test]
    fn test_english_first_word() {
        assert_eq!(Language::English.get_word(0), Some("abandon"));
    }

    #[test]
    fn test_english_last_word() {
        assert_eq!(Language::English.get_word(2047), Some("zoo"));
    }

    #[test]
    fn test_get_index() {
        assert_eq!(Language::English.get_index("abandon"), Some(0));
        assert_eq!(Language::English.get_index("zoo"), Some(2047));
        assert_eq!(Language::English.get_index("notaword"), None);
    }

    #[test]
    fn test_chinese_simplified_first_word() {
        assert_eq!(Language::ChineseSimplified.get_word(0), Some("的"));
    }

    #[test]
    fn test_japanese_first_word() {
        assert_eq!(Language::Japanese.get_word(0), Some("あいこくしん"));
    }

    #[test]
    fn test_language_default() {
        assert_eq!(Language::default(), Language::English);
    }

    #[test]
    fn test_language_all() {
        assert_eq!(Language::all().len(), 8);
    }

    #[test]
    fn test_language_codes() {
        assert_eq!(Language::English.code(), "en");
        assert_eq!(Language::ChineseSimplified.code(), "zh-Hans");
        assert_eq!(Language::Japanese.code(), "ja");
    }
}
