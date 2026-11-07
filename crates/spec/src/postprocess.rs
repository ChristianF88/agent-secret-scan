//! Rule post-processors (`regex_rules[].postprocess`) that need more than a
//! string trim: shared by the regex analyzer and the catalogue example tests.

use std::sync::OnceLock;

use agentleaks_core::JwtClaims;
use base64::Engine as _;
use base64::alphabet::URL_SAFE;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use serde_json::{Map, Value};

use crate::filters::trim_trailing_punctuation;
use crate::model::PostProcess;

/// Outcome of a regex rule's post-processor on a cleaned candidate value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Processed<'a> {
    /// Keep this (possibly shortened) value.
    Keep(&'a str),
    /// A decoded JWT and its non-secret claims.
    Jwt(&'a str, JwtClaims),
    /// The candidate is not what the rule looks for.
    Drop,
}

/// Apply a regex rule's post-processor.
pub fn apply(pp: Option<PostProcess>, value: &str) -> Processed<'_> {
    match pp {
        None | Some(PostProcess::Base64DecodeUserpass) => Processed::Keep(value),
        Some(PostProcess::TrimTrailingPunctuation) => {
            Processed::Keep(trim_trailing_punctuation(value))
        }
        Some(PostProcess::Bip39WordlistCheck) => {
            bip39_mnemonic(value).map_or(Processed::Drop, Processed::Keep)
        }
        Some(PostProcess::JwtDecodeCheckExp) => {
            jwt_claims(value).map_or(Processed::Drop, |c| Processed::Jwt(value, c))
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

// ---------------------------------------------------------------------------
// JWT
// ---------------------------------------------------------------------------

/// base64url, padding optional, lenient about trailing bits.
const B64URL: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Longest claim string kept in a report.
const MAX_CLAIM: usize = 256;

/// `jwt_decode_check_exp`: the claims of `header.payload.signature` when the
/// header is a JSON object with an `alg` string and the payload is a JSON
/// object; `None` if it is not a JWT. Only `iss`, `aud` and `exp` are read;
/// the signature is never decoded or kept.
pub fn jwt_claims(token: &str) -> Option<JwtClaims> {
    let mut parts = token.split('.');
    let (header, payload, sig) = (parts.next()?, parts.next()?, parts.next()?);
    if sig.is_empty() || parts.next().is_some() {
        return None;
    }
    decode_object(header)?.get("alg")?.as_str()?;
    let claims = decode_object(payload)?;
    let aud = match claims.get("aud") {
        Some(Value::String(s)) => Some(capped(s)),
        Some(Value::Array(a)) => {
            let all: Vec<&str> = a.iter().filter_map(Value::as_str).collect();
            (!all.is_empty()).then(|| capped(&all.join(",")))
        }
        _ => None,
    };
    Some(JwtClaims {
        iss: claims.get("iss").and_then(Value::as_str).map(capped),
        aud,
        exp: claims
            .get("exp")
            .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))),
    })
}

/// The token expired before `now` (seconds since the Unix epoch).
pub fn jwt_expired(claims: &JwtClaims, now: i64) -> bool {
    claims.exp.is_some_and(|exp| exp < now)
}

fn decode_object(part: &str) -> Option<Map<String, Value>> {
    let bytes = B64URL.decode(part).ok()?;
    match serde_json::from_slice(&bytes).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

fn capped(s: &str) -> String {
    let mut end = s.len().min(MAX_CLAIM);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
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

    /// `header.payload.sig` from JSON parts (test helper).
    fn jwt(header: &str, payload: &str) -> String {
        format!(
            "{}.{}.c2lnbmF0dXJlLW5vdC1jaGVja2Vk",
            B64URL.encode(header),
            B64URL.encode(payload)
        )
        .replace('=', "")
    }

    #[test]
    fn jwt_claims_are_decoded() {
        let t = jwt(
            r#"{"alg":"HS256","typ":"JWT"}"#,
            r#"{"iss":"https://auth.acme.test","aud":["acme-api","acme-web"],"exp":4102444800,"sub":"u1"}"#,
        );
        let c = jwt_claims(&t).expect("jwt");
        assert_eq!(c.iss.as_deref(), Some("https://auth.acme.test"));
        assert_eq!(c.aud.as_deref(), Some("acme-api,acme-web"));
        assert_eq!(c.exp, Some(4_102_444_800));
        assert!(!jwt_expired(&c, 1_700_000_000));
        assert!(jwt_expired(&c, 4_102_444_801));
        // No exp: never expired.
        let c = jwt_claims(&jwt(r#"{"alg":"none"}"#, r#"{"aud":"x"}"#)).unwrap();
        assert!(!jwt_expired(&c, i64::MAX));
        assert_eq!((c.iss, c.aud.as_deref(), c.exp), (None, Some("x"), None));
    }

    #[test]
    fn non_jwts_are_rejected() {
        // Header without alg, payload not an object, not JSON, not base64.
        assert_eq!(jwt_claims(&jwt(r#"{"typ":"JWT"}"#, "{}")), None);
        assert_eq!(jwt_claims(&jwt(r#"{"alg":"HS256"}"#, "[1]")), None);
        assert_eq!(jwt_claims(&jwt(r#"{"alg":"HS256"}"#, "{oops")), None);
        assert_eq!(jwt_claims("eyJhbGciOiJIUzI1NiJ9.eyJ!!!.c2ln"), None);
        assert_eq!(jwt_claims("eyJhbGciOiJIUzI1NiJ9.e30"), None);
        assert_eq!(
            apply(
                Some(PostProcess::JwtDecodeCheckExp),
                "eyJxxxxxxxxxxxx.eyJyyyyyyyyyy.zzzzzzzzzzzz"
            ),
            Processed::Drop
        );
    }

    #[test]
    fn long_claims_are_capped() {
        let iss = "é".repeat(200);
        let t = jwt(r#"{"alg":"HS256"}"#, &format!(r#"{{"iss":"{iss}"}}"#));
        let got = jwt_claims(&t).unwrap().iss.unwrap();
        assert!(got.len() <= MAX_CLAIM && iss.starts_with(&got));
    }
}
