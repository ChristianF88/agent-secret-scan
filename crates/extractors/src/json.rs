//! A small span-aware JSON / JSONC parser.
//!
//! `serde_json` does not report where a value sits in the file, but findings
//! need line numbers, so this parser keeps the byte range of every string
//! literal next to its decoded value.
//!
//! - Lenient on purpose: `//` and `/* */` comments and trailing commas are
//!   accepted everywhere (JSONC), invalid escapes decode to U+FFFD, and raw
//!   control characters inside strings are kept.
//! - Never panics; nesting deeper than [`MAX_DEPTH`] is an error instead of a
//!   stack overflow. Malformed or truncated input is an error, and callers
//!   fall back to scanning the raw text.
//! - Strings without escapes borrow from the input; only escaped strings
//!   allocate.

use std::borrow::Cow;
use std::ops::Range;

use agentleaks_core::TextOrigin;

/// Maximum nesting of arrays and objects.
pub const MAX_DEPTH: usize = 128;

/// A string literal: decoded value plus the byte range of the literal,
/// quotes included.
#[derive(Clone, PartialEq, Eq)]
pub struct JsonStr<'a> {
    pub value: Cow<'a, str>,
    pub span: Range<usize>,
}

/// Redacted: string values may be secrets, so `{:?}` (and `Json`'s derived
/// `Debug`, which goes through this) shows only span and length.
impl std::fmt::Debug for JsonStr<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonStr")
            .field("span", &self.span)
            .field("len", &self.value.len())
            .finish_non_exhaustive()
    }
}

impl JsonStr<'_> {
    /// Where the decoded value sits in the parsed buffer, shifted by `base`.
    /// Unescaped strings are byte-identical to the source (`Raw`).
    pub fn origin(&self, base: usize) -> TextOrigin {
        match self.value {
            Cow::Borrowed(_) => TextOrigin::Raw {
                start: base + self.span.start + 1,
            },
            Cow::Owned(_) => TextOrigin::Decoded {
                start: base + self.span.start,
                end: base + self.span.end,
            },
        }
    }
}

/// A parsed JSON value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json<'a> {
    Str(JsonStr<'a>),
    Arr(Vec<Json<'a>>),
    /// Members in file order; duplicate keys are kept.
    Obj(Vec<(JsonStr<'a>, Json<'a>)>),
    /// Number, `true`, `false` or `null`: only its span is kept.
    Scalar(Range<usize>),
}

impl<'a> Json<'a> {
    /// The member value for `key` (first match).
    pub fn get(&self, key: &str) -> Option<&Json<'a>> {
        match self {
            Json::Obj(m) => m.iter().find(|(k, _)| k.value == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(&s.value),
            _ => None,
        }
    }
}

/// Why parsing stopped (position only; never echoes input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError {
    pub offset: usize,
    pub reason: &'static str,
}

/// Parse one complete JSON / JSONC document.
pub fn parse(src: &str) -> Result<Json<'_>, ParseError> {
    let mut p = P {
        s: src,
        b: src.as_bytes(),
        i: 0,
    };
    p.skip_ws()?;
    let v = p.value(0)?;
    p.skip_ws()?;
    if p.i != p.b.len() {
        return Err(p.err("trailing data"));
    }
    Ok(v)
}

/// Quick check before trying to parse a string as nested JSON.
pub fn looks_like_json(s: &str) -> bool {
    let t = s.trim();
    (t.starts_with('{') && t.ends_with('}')) || (t.starts_with('[') && t.ends_with(']'))
}

struct P<'a> {
    s: &'a str,
    b: &'a [u8],
    i: usize,
}

impl<'a> P<'a> {
    fn err(&self, reason: &'static str) -> ParseError {
        ParseError {
            offset: self.i,
            reason,
        }
    }

    fn skip_ws(&mut self) -> Result<(), ParseError> {
        loop {
            match self.b.get(self.i) {
                Some(b' ' | b'\t' | b'\n' | b'\r') => self.i += 1,
                Some(&0xEF) if self.b[self.i..].starts_with(&[0xEF, 0xBB, 0xBF]) => self.i += 3,
                Some(b'/') => match self.b.get(self.i + 1) {
                    Some(b'/') => {
                        self.i = memchr::memchr(b'\n', &self.b[self.i..])
                            .map_or(self.b.len(), |n| self.i + n + 1);
                    }
                    Some(b'*') => {
                        let rest = &self.b[self.i + 2..];
                        match memchr::memmem::find(rest, b"*/") {
                            Some(n) => self.i += 2 + n + 2,
                            None => return Err(self.err("unterminated comment")),
                        }
                    }
                    _ => return Err(self.err("unexpected '/'")),
                },
                _ => return Ok(()),
            }
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json<'a>, ParseError> {
        match self.b.get(self.i) {
            None => Err(self.err("unexpected end")),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(_) => self.scalar(),
        }
    }

    fn scalar(&mut self) -> Result<Json<'a>, ParseError> {
        let start = self.i;
        while self
            .b
            .get(self.i)
            .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
        {
            self.i += 1;
        }
        if self.i == start {
            return Err(self.err("unexpected character"));
        }
        Ok(Json::Scalar(start..self.i))
    }

    fn array(&mut self, depth: usize) -> Result<Json<'a>, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.err("nesting too deep"));
        }
        self.i += 1; // [
        let mut items = Vec::new();
        loop {
            self.skip_ws()?;
            match self.b.get(self.i) {
                None => return Err(self.err("unterminated array")),
                Some(b']') => {
                    self.i += 1;
                    return Ok(Json::Arr(items));
                }
                _ => {}
            }
            items.push(self.value(depth)?);
            self.skip_ws()?;
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {}
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json<'a>, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.err("nesting too deep"));
        }
        self.i += 1; // {
        let mut members = Vec::new();
        loop {
            self.skip_ws()?;
            match self.b.get(self.i) {
                None => return Err(self.err("unterminated object")),
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Json::Obj(members));
                }
                Some(b'"') => {}
                _ => return Err(self.err("expected a key")),
            }
            let key = self.string()?;
            self.skip_ws()?;
            if self.b.get(self.i) != Some(&b':') {
                return Err(self.err("expected ':'"));
            }
            self.i += 1;
            self.skip_ws()?;
            let v = self.value(depth)?;
            members.push((key, v));
            self.skip_ws()?;
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {}
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
    }

    fn string(&mut self) -> Result<JsonStr<'a>, ParseError> {
        let start = self.i;
        self.i += 1; // opening quote
        let body = self.i;
        // Fast path: no escapes before the closing quote.
        match memchr::memchr2(b'"', b'\\', &self.b[body..]) {
            None => return Err(self.err("unterminated string")),
            Some(n) if self.b[body + n] == b'"' => {
                self.i = body + n + 1;
                return Ok(JsonStr {
                    value: Cow::Borrowed(&self.s[body..body + n]),
                    span: start..self.i,
                });
            }
            Some(_) => {}
        }
        let mut out = String::new();
        let mut run = body; // start of the pending unescaped run
        loop {
            let Some(n) = memchr::memchr2(b'"', b'\\', &self.b[self.i..]) else {
                return Err(self.err("unterminated string"));
            };
            self.i += n;
            out.push_str(&self.s[run..self.i]);
            if self.b[self.i] == b'"' {
                self.i += 1;
                return Ok(JsonStr {
                    value: Cow::Owned(out),
                    span: start..self.i,
                });
            }
            // Backslash escape.
            let Some(&e) = self.b.get(self.i + 1) else {
                return Err(self.err("unterminated string"));
            };
            self.i += 2;
            match e {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'b' => out.push('\u{8}'),
                b'f' => out.push('\u{c}'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'u' => out.push(self.unicode_escape()),
                _ => {
                    // Invalid escape: keep the character itself (it may be
                    // multi-byte, so step back and copy it as a run).
                    self.i -= 1;
                    run = self.i;
                    continue;
                }
            }
            run = self.i;
        }
    }

    /// After `\u`: four hex digits, combining surrogate pairs.
    fn unicode_escape(&mut self) -> char {
        let Some(hi) = self.hex4() else {
            return char::REPLACEMENT_CHARACTER;
        };
        if (0xD800..0xDC00).contains(&hi) {
            if self.b.get(self.i) == Some(&b'\\') && self.b.get(self.i + 1) == Some(&b'u') {
                let save = self.i;
                self.i += 2;
                if let Some(lo) = self.hex4()
                    && (0xDC00..0xE000).contains(&lo)
                {
                    let c = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                    return char::from_u32(c).unwrap_or(char::REPLACEMENT_CHARACTER);
                }
                self.i = save;
            }
            return char::REPLACEMENT_CHARACTER;
        }
        char::from_u32(hi).unwrap_or(char::REPLACEMENT_CHARACTER)
    }

    fn hex4(&mut self) -> Option<u32> {
        let h = self.b.get(self.i..self.i + 4)?;
        let mut v = 0u32;
        for &c in h {
            v = v * 16 + (c as char).to_digit(16)?;
        }
        self.i += 4;
        Some(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_and_decoding() {
        let src = r#"{"a": "x\"y", "b": ["plain", 1, true], "c": "\u00e4\ud83d\ude00"}"#;
        let v = parse(src).unwrap();
        let Json::Str(a) = v.get("a").unwrap() else {
            panic!()
        };
        assert_eq!(a.value, "x\"y");
        assert_eq!(&src[a.span.clone()], r#""x\"y""#);
        assert!(matches!(a.origin(0), TextOrigin::Decoded { .. }));
        let Json::Arr(b) = v.get("b").unwrap() else {
            panic!()
        };
        let Json::Str(p) = &b[0] else { panic!() };
        assert_eq!(
            p.origin(5),
            TextOrigin::Raw {
                start: 5 + p.span.start + 1
            }
        );
        assert_eq!(v.get("c").unwrap().as_str(), Some("ä😀"));
    }

    #[test]
    fn debug_is_redacted() {
        let v = parse(r#"{"password": "Tr0ub4dor-Kx9q", "e": "a\"Qw7!mZp2Lr"}"#).unwrap();
        let d = format!("{v:?}");
        assert!(
            !d.contains("Tr0ub4dor") && !d.contains("Qw7!") && !d.contains("password"),
            "{d}"
        );
        assert!(d.contains("JsonStr"));
    }

    #[test]
    fn jsonc() {
        let src = "// c\n{\n /* x */ \"a\": [1, 2,], // t\n \"b\": {\"c\": \"d\",},\n}\n";
        let v = parse(src).unwrap();
        assert!(v.get("b").unwrap().get("c").is_some());
    }

    #[test]
    fn errors_do_not_panic() {
        for s in [
            "",
            "{",
            "[",
            "\"",
            "\"\\",
            "\"\\u12",
            "{\"a\"",
            "{\"a\":",
            "[1,",
            "/*",
            "{}x",
            "@",
            "\"\\ud800\\u0041\"",
            "\"\\é\"",
        ] {
            let _ = parse(s);
        }
        assert_eq!(parse("\"\\é\"").unwrap().as_str(), Some("é"));
        let deep = "[".repeat(100_000);
        assert_eq!(parse(&deep).unwrap_err().reason, "nesting too deep");
    }
}
