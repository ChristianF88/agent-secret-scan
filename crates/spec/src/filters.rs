//! Compiled value filters and credential-name matching.
//!
//! These are pure predicates over the catalogue data; the analyzers combine
//! them into the filter stage.

use std::collections::HashSet;

use regex::RegexSet;

use crate::model::{CredentialNamesDef, MinLength, SpecRegex, ValueFiltersDef};

/// Shared value filters (catalogue section 1).
#[derive(Debug)]
pub struct ValueFilters {
    references: RegexSet,
    /// ASCII-lower-cased; matched ASCII-case-insensitively.
    placeholders: HashSet<Vec<u8>>,
    placeholder_max_len: usize,
    placeholder_patterns: RegexSet,
    /// Matched exactly (the list holds case variants such as `Password1`).
    defaults: HashSet<String>,
    pub min_length: MinLength,
    local_hosts: RegexSet,
}

impl ValueFilters {
    pub(crate) fn compile(def: &ValueFiltersDef) -> Result<Self, regex::Error> {
        Ok(Self {
            references: set_of(&def.references)?,
            placeholders: def
                .placeholders
                .iter()
                .map(|p| p.to_ascii_lowercase().into_bytes())
                .collect(),
            placeholder_max_len: def.placeholders.iter().map(String::len).max().unwrap_or(0),
            placeholder_patterns: set_of(&def.placeholder_patterns)?,
            defaults: def.defaults.iter().cloned().collect(),
            min_length: def.min_length,
            local_hosts: set_of(&def.local_hosts)?,
        })
    }

    /// The value points at a secret (`$VAR`, `${{ secrets.X }}`, a file path, ...).
    pub fn is_reference(&self, value: &str) -> bool {
        self.references.is_match(value)
    }

    /// An obvious placeholder (`changeme`, `xxx`, `your-api-key`, `sk-...`).
    /// Allocation-free.
    pub fn is_placeholder(&self, value: &str) -> bool {
        if self.placeholder_patterns.is_match(value) {
            return true;
        }
        if value.len() > self.placeholder_max_len {
            return false;
        }
        let mut buf = [0u8; NAME_BUF];
        match ascii_lower(value, &mut buf) {
            Some(lower) => self.placeholders.contains(lower),
            None => self
                .placeholders
                .contains(&value.to_ascii_lowercase().into_bytes()),
        }
    }

    /// A reference or placeholder: the value itself, the value without a
    /// trailing `,`/`;` (code: `apiKey: PLACEHOLDER,`), or the credential
    /// after an HTTP auth scheme (`Bearer <token>`, `Bearer your-token`).
    /// `value` is already cleaned ([`clean_value`]).
    pub fn is_filtered(&self, value: &str) -> bool {
        let hit = |s: &str| !s.is_empty() && (self.is_reference(s) || self.is_placeholder(s));
        if hit(value) {
            return true;
        }
        let trimmed = value.trim_end_matches([',', ';']).trim_end();
        if trimmed.len() != value.len() && hit(trimmed) {
            return true;
        }
        let Some((scheme, rest)) = trimmed.split_once(' ') else {
            return false;
        };
        ["bearer", "basic", "token"]
            .iter()
            .any(|s| scheme.eq_ignore_ascii_case(s))
            && hit(clean_value(rest.trim()))
    }

    /// A well-known default credential (reported, with low severity).
    pub fn is_default(&self, value: &str) -> bool {
        self.defaults.contains(value)
    }

    /// A local or documentation host (lowers severity).
    pub fn is_local_host(&self, host: &str) -> bool {
        self.local_hosts.is_match(host)
    }
}

/// Credential names (catalogue section 2).
#[derive(Debug)]
pub struct CredentialNames {
    /// ASCII-upper-cased exact names.
    exact: HashSet<Vec<u8>>,
    /// ASCII-upper-cased prefixes from entries ending in `*` (`MC_HOST_*`).
    exact_prefixes: Vec<Vec<u8>>,
    patterns: RegexSet,
    exclusions: RegexSet,
}

impl CredentialNames {
    pub(crate) fn compile(def: &CredentialNamesDef) -> Result<Self, regex::Error> {
        let mut exact = HashSet::new();
        let mut exact_prefixes = Vec::new();
        for name in &def.exact_env {
            match name.strip_suffix('*') {
                Some(prefix) => exact_prefixes.push(prefix.to_ascii_uppercase().into_bytes()),
                None => {
                    exact.insert(name.to_ascii_uppercase().into_bytes());
                }
            }
        }
        Ok(Self {
            exact,
            exact_prefixes,
            patterns: set_of(&def.name_patterns)?,
            exclusions: set_of(&def.name_exclusions)?,
        })
    }

    /// The name looks like a credential name but is not one
    /// (`DB_PASSWORD_FILE`, `MAX_TOKENS`, `client_id`, ...).
    pub fn is_excluded(&self, name: &str) -> bool {
        self.exclusions.is_match(name)
    }

    /// The name denotes a credential and is not excluded.
    ///
    /// Exact names match ASCII-case-insensitively only, so Unicode case
    /// folding (`ſ` → `S`) cannot create matches. Allocation-free.
    pub fn is_credential_name(&self, name: &str) -> bool {
        if name.is_empty() || self.is_excluded(name) {
            return false;
        }
        let mut buf = [0u8; NAME_BUF];
        let exact = match ascii_upper(name, &mut buf) {
            Some(upper) => {
                self.exact.contains(upper)
                    || self.exact_prefixes.iter().any(|p| upper.starts_with(p))
            }
            None => false, // longer than any environment variable name we know
        };
        exact || self.patterns.is_match(name)
    }

    /// ASCII-upper-cased exact names (prefilter input).
    pub fn exact_names(&self) -> impl Iterator<Item = &[u8]> {
        self.exact.iter().map(Vec::as_slice)
    }
}

/// Stack buffer for case-folding names and placeholders without allocating.
const NAME_BUF: usize = 128;

fn ascii_lower<'b>(s: &str, buf: &'b mut [u8; NAME_BUF]) -> Option<&'b [u8]> {
    let out = buf.get_mut(..s.len())?;
    out.copy_from_slice(s.as_bytes());
    out.make_ascii_lowercase();
    Some(out)
}

fn ascii_upper<'b>(s: &str, buf: &'b mut [u8; NAME_BUF]) -> Option<&'b [u8]> {
    let out = buf.get_mut(..s.len())?;
    out.copy_from_slice(s.as_bytes());
    out.make_ascii_uppercase();
    Some(out)
}

fn set_of(regexes: &[SpecRegex]) -> Result<RegexSet, regex::Error> {
    RegexSet::new(regexes.iter().map(SpecRegex::as_str))
}

/// Trim whitespace and one pair of matching surrounding quotes.
pub fn clean_value(value: &str) -> &str {
    let v = value.trim();
    let b = v.as_bytes();
    if b.len() >= 2 && b[0] == b[b.len() - 1] && (b[0] == b'"' || b[0] == b'\'') {
        v[1..v.len() - 1].trim()
    } else {
        v
    }
}

/// `require_complexity`: a digit, a non-alphanumeric char, or mixed case.
pub fn is_complex(value: &str) -> bool {
    let mut lower = false;
    let mut upper = false;
    for c in value.chars() {
        if c.is_numeric() || !c.is_ascii_alphanumeric() {
            return true;
        }
        lower |= c.is_ascii_lowercase();
        upper |= c.is_ascii_uppercase();
    }
    lower && upper
}

/// `trim_trailing_punctuation` post-processor.
pub fn trim_trailing_punctuation(value: &str) -> &str {
    value.trim_end_matches(['.', ',', ';', ':', ')'])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_strips_one_quote_pair() {
        assert_eq!(clean_value("  'a b'  "), "a b");
        assert_eq!(clean_value("\"x\""), "x");
        assert_eq!(clean_value("'x\""), "'x\"");
        assert_eq!(clean_value("'"), "'");
        assert_eq!(clean_value("\"\""), "");
    }

    #[test]
    fn complexity() {
        assert!(!is_complex("password"));
        assert!(!is_complex("PASSWORD"));
        assert!(is_complex("Password"));
        assert!(is_complex("pass1"));
        assert!(is_complex("pass-word"));
        assert!(is_complex("пароль")); // non-ASCII counts as non-alphanumeric
    }

    #[test]
    fn trailing_punctuation() {
        assert_eq!(trim_trailing_punctuation("abc.),"), "abc");
        assert_eq!(trim_trailing_punctuation("a.b"), "a.b");
    }
}
