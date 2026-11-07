//! Name/value analyzer for `Env`, `ConfigKey` and `Headers` routes: the name
//! decides whether the value is a credential (catalogue `credential_names`),
//! the value filters decide whether it is a real one.
//!
//! `value_filters.min_length` applies here (D24): the password minimum for
//! password-like names, the key or token minimum otherwise. Header values
//! lose their auth scheme first (`Bearer x` -> `x`); `Basic` credentials are
//! base64-decoded and the password after `user:` is the secret.

use agentleaks_core::{
    Candidate, Category, Confidence, Context, Route, Routed, Secret, SecretKind, Severity,
};
use agentleaks_spec::Spec;

use crate::filter::{Verdict, adjust_severity, check_value, clean_value};

pub const RULE_ENV: &str = "keyed.env";
pub const RULE_ENV_CAPTURE: &str = "keyed.env-capture";
pub const RULE_CONFIG_KEY: &str = "keyed.config-key";
pub const RULE_HEADER: &str = "keyed.header";

#[derive(Debug)]
pub struct KeyedAnalyzer<'s> {
    spec: &'s Spec,
}

impl<'s> KeyedAnalyzer<'s> {
    pub fn new(spec: &'s Spec) -> Self {
        KeyedAnalyzer { spec }
    }

    /// Analyze one routed name/value pair. `env_capture` marks environments
    /// captured by an agent (shell snapshots), reported as `env_capture`.
    pub fn analyze(&self, input: &Routed<'_>, env_capture: bool, out: &mut Vec<Candidate<'s>>) {
        let Some(name) = input.name.as_deref() else {
            return;
        };
        if !self.spec.credential_names.is_credential_name(name) {
            return;
        }
        let text: &str = &input.text;
        let c = match input.route {
            Route::Env if env_capture => self.plain(
                name,
                text,
                RULE_ENV_CAPTURE,
                Category::EnvCapture,
                Confidence::High,
            ),
            Route::Env => self.plain(
                name,
                text,
                RULE_ENV,
                Category::EnvAssignment,
                Confidence::High,
            ),
            Route::ConfigKey => self.plain(
                name,
                text,
                RULE_CONFIG_KEY,
                Category::ConfigKey,
                Confidence::Medium,
            ),
            Route::Headers => self.header(text),
            _ => None,
        };
        out.extend(c);
    }

    fn plain(
        &self,
        name: &str,
        text: &str,
        rule_id: &'static str,
        category: Category,
        confidence: Confidence,
    ) -> Option<Candidate<'s>> {
        let value = clean_value(text);
        let (kind, min) = self.kind_of_name(name);
        let off = offset_in(text, value);
        self.candidate(
            value,
            Secret::new(value),
            off..off + value.len(),
            kind,
            min,
            rule_id,
            category,
            confidence,
        )
    }

    fn header(&self, text: &str) -> Option<Candidate<'s>> {
        let value = clean_value(text);
        let ml = self.spec.value_filters.min_length;
        // `Bearer ${TOKEN}` and friends are references as a whole.
        if self.spec.value_filters.is_reference(value) {
            return None;
        }
        let (scheme, cred) = match value.split_once(' ') {
            Some((s, rest)) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphabetic()) => {
                (Some(s), rest.trim())
            }
            _ => (None, value),
        };
        let off = offset_in(text, cred);
        let span = off..off + cred.len();
        if scheme.is_some_and(|s| s.eq_ignore_ascii_case("basic"))
            && let Some(decoded) = base64_decode(cred)
            && let Ok(userpass) = String::from_utf8(decoded)
            && let Some((_, pass)) = userpass.split_once(':')
        {
            return self.candidate(
                pass,
                Secret::new(pass),
                span,
                SecretKind::Password,
                ml.password,
                RULE_HEADER,
                Category::Http,
                Confidence::High,
            );
        }
        self.candidate(
            cred,
            Secret::new(cred),
            span,
            SecretKind::Token,
            ml.token,
            RULE_HEADER,
            Category::Http,
            Confidence::High,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn candidate(
        &self,
        value: &str,
        secret: Secret,
        span: std::ops::Range<usize>,
        kind: SecretKind,
        min_len: usize,
        rule_id: &'static str,
        category: Category,
        confidence: Confidence,
    ) -> Option<Candidate<'s>> {
        let default = match check_value(self.spec, value, min_len) {
            Verdict::Keep(_) => false,
            Verdict::Default(_) => true,
            Verdict::Drop => return None,
        };
        Some(Candidate {
            rule_id,
            category,
            kind: if default {
                SecretKind::DefaultCredential
            } else {
                kind
            },
            severity: adjust_severity(self.spec, Severity::High, None, default),
            confidence,
            secret,
            span,
            context: Context::default(),
        })
    }

    /// Kind of secret and minimum length for a credential name (D24).
    ///
    /// The last word of the name decides (`COMPASS_TOKEN` is a token, not a
    /// password; `OLDPWD_KEY` is a key). Words split at `_ - . : /` and at
    /// camelCase boundaries. Single-word names may carry the keyword as a
    /// suffix (`PGPASSWORD`, `SSHPASS`).
    fn kind_of_name(&self, name: &str) -> (SecretKind, usize) {
        let ml = self.spec.value_filters.min_length;
        let (last, single) = last_word(name);
        let is = |w: &str| last.eq_ignore_ascii_case(w);
        let ends = |w: &str| ends_with_ci(last, w);
        if ends("passphrase") {
            (SecretKind::Passphrase, ml.password)
        } else if ["pass", "pwd", "pw", "pin", "passcode"]
            .iter()
            .any(|w| is(w))
            || ends("password")
            || ends("passwd")
            || (single && (ends("pass") || ends("pwd")))
        {
            (SecretKind::Password, ml.password)
        } else if ends("key") {
            (SecretKind::Key, ml.key)
        } else {
            (SecretKind::Token, ml.token)
        }
    }
}

/// The last word of an identifier, and whether it is the only word.
fn last_word(name: &str) -> (&str, bool) {
    let b = name.as_bytes();
    let sep = |c: u8| matches!(c, b'_' | b'-' | b'.' | b':' | b'/' | b' ');
    let mut end = b.len();
    while end > 0 && sep(b[end - 1]) {
        end -= 1;
    }
    let mut start = 0;
    let mut i = end;
    while i > 0 {
        i -= 1;
        let c = b[i];
        if sep(c) {
            start = i + 1;
            break;
        }
        if i > 0 && c.is_ascii_uppercase() {
            let prev = b[i - 1];
            let next_lower = b
                .get(i + 1)
                .is_some_and(|n| n.is_ascii_lowercase() && i + 1 < end);
            // fooBar -> Bar; APIKey -> Key
            if prev.is_ascii_lowercase()
                || prev.is_ascii_digit()
                || (prev.is_ascii_uppercase() && next_lower)
            {
                start = i;
                break;
            }
        }
    }
    let single = start == 0;
    (&name[start..end], single)
}

fn ends_with_ci(s: &str, suffix: &str) -> bool {
    s.len() >= suffix.len()
        && s.as_bytes()[s.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes())
}

/// Byte offset of `inner` (a subslice) inside `outer`.
fn offset_in(outer: &str, inner: &str) -> usize {
    (inner.as_ptr() as usize)
        .saturating_sub(outer.as_ptr() as usize)
        .min(outer.len())
}

/// Standard or URL-safe base64, padding optional. `None` if invalid.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentleaks_core::TextOrigin;
    use std::borrow::Cow;

    fn run(route: Route, name: &str, value: &str) -> Vec<(String, String, std::ops::Range<usize>)> {
        let spec = Spec::embedded().unwrap();
        let a = KeyedAnalyzer::new(&spec);
        let r = Routed {
            text: Cow::Borrowed(value),
            route,
            origin: TextOrigin::Raw { start: 0 },
            name: Some(Cow::Borrowed(name)),
            scope: None,
            structure: None,
        };
        let mut out = Vec::new();
        a.analyze(&r, false, &mut out);
        out.iter()
            .map(|c| {
                (
                    c.rule_id.to_owned(),
                    c.secret.expose().to_owned(),
                    c.span.clone(),
                )
            })
            .collect()
    }

    #[test]
    fn env_names_and_values() {
        assert_eq!(
            run(Route::Env, "PGPASSWORD", "McpPgPw2026!"),
            [("keyed.env".into(), "McpPgPw2026!".into(), 0..12)]
        );
        assert_eq!(run(Route::Env, "DB_PASSWORD", " 'Pw9x' ")[0].2, 2..6);
        assert!(run(Route::Env, "PGHOST", "203.0.113.20").is_empty());
        assert!(run(Route::Env, "API_KEY", "${env:API_KEY}").is_empty());
        assert!(run(Route::Env, "PASSWORD", "changeme").is_empty());
        assert!(run(Route::Env, "DB_PASSWORD_FILE", "/run/secrets/db").is_empty());
        assert!(run(Route::Env, "MAX_TOKENS", "4096").is_empty());
        // D24: tokens need 12 characters, passwords 4.
        assert!(run(Route::Env, "INTERNAL_API_TOKEN", "short-tok").is_empty());
        assert_eq!(run(Route::Env, "DB_PASS", "Pw9x").len(), 1);
        assert_eq!(
            run(Route::ConfigKey, "apiKey", "cl1ne-plain-key-0042")[0].0,
            "keyed.config-key"
        );
    }

    #[test]
    fn headers() {
        let r = run(
            Route::Headers,
            "Authorization",
            "Bearer opaq.ue7Tok3n.Value99",
        );
        assert_eq!(r[0].1, "opaq.ue7Tok3n.Value99");
        assert_eq!(r[0].2, 7..28);
        assert!(run(Route::Headers, "Authorization", "Bearer ${ACME_TOKEN}").is_empty());
        // "ci:Bas1cPw99" in base64
        let r = run(Route::Headers, "Authorization", "Basic Y2k6QmFzMWNQdzk5");
        assert_eq!(r[0].1, "Bas1cPw99");
        assert_eq!(
            run(Route::Headers, "X-Api-Key", "opaque-header-key-1")[0].1,
            "opaque-header-key-1"
        );
        assert!(run(Route::Headers, "Content-Type", "application/json").is_empty());
    }

    #[test]
    fn last_words() {
        assert_eq!(last_word("COMPASS_TOKEN"), ("TOKEN", false));
        assert_eq!(last_word("smtpPassword"), ("Password", false));
        assert_eq!(last_word("APIKey"), ("Key", false));
        assert_eq!(last_word("PGPASSWORD"), ("PGPASSWORD", true));
        assert_eq!(last_word("x-api-key"), ("key", false));
        assert_eq!(last_word("DB_PASS_"), ("PASS", false));
    }

    #[test]
    fn keywords_inside_other_words_do_not_count() {
        // Token and key names need 12 characters (D24); these are 5.
        for name in [
            "COMPASS_TOKEN",
            "BYPASS_TOKEN",
            "PASSTHROUGH_KEY",
            "OLDPWD_KEY",
            "MAPPIN_TOKEN",
        ] {
            assert!(run(Route::Env, name, "ab12c").is_empty(), "{name}");
        }
        // Real password names keep the password minimum.
        for name in [
            "PGPASSWORD",
            "SSHPASS",
            "MYSQL_PWD",
            "BIND_PW",
            "smtpPassword",
            "PM_PASS",
            "DB_PASSWD",
        ] {
            assert_eq!(run(Route::Env, name, "ab12c").len(), 1, "{name}");
        }
    }

    #[test]
    fn base64() {
        assert_eq!(base64_decode("Y2k6QmFzMWNQdzk5").unwrap(), b"ci:Bas1cPw99");
        assert_eq!(base64_decode("YQ==").unwrap(), b"a");
        assert!(base64_decode("a").is_none());
        assert!(base64_decode("!!!!").is_none());
    }
}
