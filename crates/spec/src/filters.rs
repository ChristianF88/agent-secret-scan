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
    /// Lower-cased; matched case-insensitively.
    placeholders: HashSet<String>,
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
                .map(|p| p.0.to_lowercase())
                .collect(),
            defaults: def.defaults.iter().map(|d| d.0.clone()).collect(),
            min_length: def.min_length,
            local_hosts: set_of(&def.local_hosts)?,
        })
    }

    /// The value points at a secret (`$VAR`, `${{ secrets.X }}`, a file path, ...).
    pub fn is_reference(&self, value: &str) -> bool {
        self.references.is_match(value)
    }

    /// An obvious placeholder (`changeme`, `<password>` is a reference, `xxx`, ...).
    pub fn is_placeholder(&self, value: &str) -> bool {
        // Avoid allocating for the common case: placeholders are short.
        value.len() <= 32 && self.placeholders.contains(&value.to_lowercase())
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
    /// Upper-cased exact names.
    exact: HashSet<String>,
    /// Upper-cased prefixes from entries ending in `*` (`MC_HOST_*`).
    exact_prefixes: Vec<String>,
    patterns: RegexSet,
    exclusions: RegexSet,
}

impl CredentialNames {
    pub(crate) fn compile(def: &CredentialNamesDef) -> Result<Self, regex::Error> {
        let mut exact = HashSet::new();
        let mut exact_prefixes = Vec::new();
        for name in &def.exact_env {
            match name.strip_suffix('*') {
                Some(prefix) => exact_prefixes.push(prefix.to_uppercase()),
                None => {
                    exact.insert(name.to_uppercase());
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
    pub fn is_credential_name(&self, name: &str) -> bool {
        if name.is_empty() || self.is_excluded(name) {
            return false;
        }
        let upper = name.to_uppercase();
        self.exact.contains(&upper)
            || self
                .exact_prefixes
                .iter()
                .any(|p| upper.starts_with(p.as_str()))
            || self.patterns.is_match(name)
    }

    /// Upper-cased exact names (prefilter input).
    pub fn exact_names(&self) -> impl Iterator<Item = &str> {
        self.exact.iter().map(String::as_str)
    }
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
