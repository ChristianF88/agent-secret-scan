//! Rule post-processors (`regex_rules[].postprocess`) that need more than a
//! string trim: shared by the regex analyzer and the catalogue example tests.

use std::sync::OnceLock;

use crate::filters::trim_trailing_punctuation;
use crate::model::PostProcess;

/// Outcome of a regex rule's post-processor on a cleaned candidate value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Processed<'a> {
    /// Keep this (possibly shortened) value.
    Keep(&'a str),
    /// The candidate is not what the rule looks for.
    Drop,
}

/// Apply a regex rule's post-processor. JWT claims are decoded separately
/// ([`jwt_claims`]); here the JWT check only decides keep or drop.
pub fn apply(pp: Option<PostProcess>, value: &str) -> Processed<'_> {
    match pp {
        None | Some(PostProcess::Base64DecodeUserpass | PostProcess::JwtDecodeCheckExp) => {
            Processed::Keep(value)
        }
        Some(PostProcess::TrimTrailingPunctuation) => {
            Processed::Keep(trim_trailing_punctuation(value))
        }
        Some(PostProcess::Bip39WordlistCheck) => {
            bip39_mnemonic(value).map_or(Processed::Drop, Processed::Keep)
        }
    }
}

/// The post-processor verifies the value's structure (a BIP-39 mnemonic, a
/// decodable JWT), so placeholder filters, which judge by shape, do not apply:
/// twelve lowercase words look like prose but are a wallet seed.
pub fn validates_shape(pp: Option<PostProcess>) -> bool {
    matches!(
        pp,
        Some(PostProcess::Bip39WordlistCheck | PostProcess::JwtDecodeCheckExp)
    )
}

// ---------------------------------------------------------------------------
// BIP-39
// ---------------------------------------------------------------------------

/// The BIP-39 English wordlist (2048 words, sorted, one per line), verbatim
/// from bitcoin/bips `bip-0039/english.txt`.
pub const BIP39_ENGLISH: &str = include_str!("../data/bip39-english.txt");

/// Mnemonic lengths BIP-39 defines.
const MNEMONIC_WORDS: [usize; 5] = [24, 21, 18, 15, 12];

fn bip39_words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| BIP39_ENGLISH.lines().collect())
}

/// `word` is in the BIP-39 English list (ASCII case-insensitive).
pub fn is_bip39_word(word: &str) -> bool {
    let mut buf = [0u8; 8]; // the longest BIP-39 word has 8 letters
    let Some(lower) = buf.get_mut(..word.len()) else {
        return false;
    };
    lower.copy_from_slice(word.as_bytes());
    lower.make_ascii_lowercase();
    bip39_words()
        .binary_search_by(|w| w.as_bytes().cmp(lower))
        .is_ok()
}

/// `bip39_wordlist_check`: the longest prefix of `value` that is a mnemonic
/// of a BIP-39 length (12, 15, 18, 21 or 24 words) made only of list words.
/// The rule's regex is greedy, so trailing prose words are cut off here.
/// The checksum bits are not verified.
pub fn bip39_mnemonic(value: &str) -> Option<&str> {
    let mut count = 0;
    let mut ends = [0usize; 24];
    for (start, word) in words_with_offsets(value) {
        if count == ends.len() || !is_bip39_word(word) {
            break;
        }
        ends[count] = start + word.len();
        count += 1;
    }
    let n = MNEMONIC_WORDS.into_iter().find(|&n| n <= count)?;
    Some(&value[..ends[n - 1]])
}

/// Whitespace-separated words with their byte offsets.
fn words_with_offsets(s: &str) -> impl Iterator<Item = (usize, &str)> {
    s.split(|c: char| c.is_ascii_whitespace())
        .filter(|w| !w.is_empty())
        .map(move |w| (w.as_ptr() as usize - s.as_ptr() as usize, w))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the embedded list. Its SHA-256 is the published
    /// 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda;
    /// the workspace has no SHA-256 crate, so BLAKE3 of the same bytes is
    /// pinned here.
    #[test]
    fn wordlist_is_the_bip39_english_list() {
        let words = bip39_words();
        assert_eq!(words.len(), 2048);
        assert!(words.windows(2).all(|w| w[0] < w[1]), "sorted and unique");
        assert!(
            words
                .iter()
                .all(|w| (3..=8).contains(&w.len()) && w.bytes().all(|b| b.is_ascii_lowercase()))
        );
        assert_eq!((words[0], words[2047]), ("abandon", "zoo"));
        assert_eq!(
            blake3::hash(BIP39_ENGLISH.as_bytes()).to_hex().as_str(),
            "43afe08c75f902534cfd2a694bef11db381f4804cd3ef76cd05a8ad0d7199122"
        );
    }

    #[test]
    fn words() {
        assert!(is_bip39_word("abandon"));
        assert!(is_bip39_word("Zoo"));
        assert!(!is_bip39_word("zebras"));
        assert!(!is_bip39_word("tokeniser"));
        assert!(!is_bip39_word(""));
    }

    #[test]
    fn mnemonics() {
        let twelve =
            "orbit lunar cactus velvet harbor ginger mammal ribbon pigeon throw quantum anchor";
        assert_eq!(bip39_mnemonic(twelve), Some(twelve));
        // Trailing prose is cut at the longest BIP-39 length.
        let with_tail = format!("{twelve} then restart the wallet");
        assert_eq!(bip39_mnemonic(&with_tail), Some(twelve));
        assert_eq!(
            bip39_mnemonic(&format!("{twelve} orbit lunar cactus")),
            Some(&*format!("{twelve} orbit lunar cactus"))
        );
        // A non-list word inside the first twelve.
        let bad = twelve.replace("ginger", "gingerly");
        assert_eq!(bip39_mnemonic(&bad), None);
        assert_eq!(bip39_mnemonic("orbit lunar cactus"), None);
        assert_eq!(bip39_mnemonic(""), None);
    }
}
