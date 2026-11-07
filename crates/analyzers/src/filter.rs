//! The filter stage: decides whether a candidate value is reported.

use agentleaks_core::Severity;
use agentleaks_spec::Spec;
use agentleaks_spec::filters::clean_value;

/// Outcome of checking a candidate value against `value_filters`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict<'a> {
    /// Report it.
    Keep(&'a str),
    /// A well-known default credential: report with kind `default_credential` (D15).
    Default(&'a str),
    /// A reference, placeholder or too short: drop.
    Drop,
}

/// Clean a raw captured value and check it against the shared value filters.
pub fn check_value<'a>(spec: &Spec, raw: &'a str, min_len: usize) -> Verdict<'a> {
    let v = clean_value(raw);
    let vf = &spec.value_filters;
    if v.is_empty() || vf.is_reference(v) || vf.is_placeholder(v) {
        return Verdict::Drop;
    }
    if vf.is_default(v) {
        return Verdict::Default(v);
    }
    if v.chars().count() < min_len {
        return Verdict::Drop;
    }
    Verdict::Keep(v)
}

/// Severity after host and default-credential adjustments.
///
/// - Default credentials are `low`, unless paired with a non-local host (D15).
/// - A local or documentation host lowers severity by one level.
pub fn adjust_severity(spec: &Spec, base: Severity, host: Option<&str>, default: bool) -> Severity {
    let local = host.is_some_and(|h| spec.value_filters.is_local_host(h));
    let remote = host.is_some() && !local;
    if default {
        return if remote {
            base.min(Severity::Medium)
        } else {
            Severity::Low
        };
    }
    if local { lower(base) } else { base }
}

fn lower(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low | Severity::Info => Severity::Info,
    }
}

/// Hostname part of `user@host`, `host:port` or a URL authority.
pub fn host_of(s: &str) -> &str {
    let s = s.rsplit_once('@').map_or(s, |(_, h)| h);
    let s = s.split(['/', '?', '#']).next().unwrap_or(s);
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest); // [ipv6]:port
    }
    match s.rsplit_once(':') {
        Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdicts() {
        let spec = Spec::embedded().unwrap();
        assert_eq!(
            check_value(&spec, "'Tr0ub4dor'", 4),
            Verdict::Keep("Tr0ub4dor")
        );
        assert_eq!(check_value(&spec, "$PGPASSWORD", 4), Verdict::Drop);
        assert_eq!(check_value(&spec, "changeme", 4), Verdict::Drop);
        assert_eq!(check_value(&spec, "abc", 4), Verdict::Drop);
        assert_eq!(
            check_value(&spec, "changeit", 4),
            Verdict::Default("changeit")
        );
        // short defaults are still reported (`sa`, `root`)
        assert_eq!(check_value(&spec, "sa", 4), Verdict::Default("sa"));
    }

    #[test]
    fn severity() {
        let spec = Spec::embedded().unwrap();
        let s = |b, h, d| adjust_severity(&spec, b, h, d);
        assert_eq!(s(Severity::High, None, false), Severity::High);
        assert_eq!(
            s(Severity::High, Some("localhost"), false),
            Severity::Medium
        );
        assert_eq!(s(Severity::High, Some("db.acme.io"), false), Severity::High);
        assert_eq!(s(Severity::High, None, true), Severity::Low);
        assert_eq!(
            s(Severity::Critical, Some("db.acme.io"), true),
            Severity::Medium
        );
    }

    #[test]
    fn hosts() {
        assert_eq!(host_of("deploy@203.0.113.41"), "203.0.113.41");
        assert_eq!(host_of("db.acme.io:5432"), "db.acme.io");
        assert_eq!(host_of("[::1]:22"), "::1");
        assert_eq!(host_of("api.acme.test/health"), "api.acme.test");
    }
}
