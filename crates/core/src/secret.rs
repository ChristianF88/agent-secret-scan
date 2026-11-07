//! A secret value that never prints itself.

use std::fmt;

/// A credential value. `Debug` and `Display` are redacted, so a secret cannot
/// leak through logging, `{:?}`, panics or error messages. The raw value is
/// only reachable through [`Secret::expose`], which reporters call when
/// `--show-secrets` is set, and fingerprinting.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }

    /// The raw value. Call sites must not log it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Redacted form for reports: a two-character hint for long values only.
    ///
    /// Short human passwords would be half-revealed by a prefix, so values
    /// under 10 characters show no hint at all.
    pub fn redacted(&self) -> String {
        let mut chars = self.0.chars();
        if self.0.chars().count() >= 10 {
            let hint: String = chars.by_ref().take(2).collect();
            format!("{hint}…[redacted]")
        } else {
            "[redacted]".to_owned()
        }
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_prints_itself() {
        let s = Secret::new("Tr0ub4dor-Kx9q");
        assert!(!format!("{s:?}").contains("Tr0ub"));
        assert!(!format!("{s}").contains("Tr0ub"));
        assert_eq!(s.redacted(), "Tr…[redacted]");
        assert_eq!(Secret::new("short1").redacted(), "[redacted]");
        assert_eq!(Secret::new("ääääääääää").redacted(), "ää…[redacted]");
    }
}
