//! URL validation and credential redaction.
//!
//! Validation mirrors git's own transport selection (`transport.c`,
//! `connect.c`) closely enough that every URL we accept is routed by git to
//! one of the allowed transports, and everything else is refused before a
//! process is spawned.

use crate::CloneError;

/// Longest URL we accept. Real repository URLs are far shorter.
const MAX_URL_LEN: usize = 4096;

/// The transport git will use for a validated URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlKind {
    /// `https://host/path`
    Https,
    /// `ssh://[user@]host[:port]/path`, `git+ssh://`, `ssh+git://` or scp-like `[user@]host:path`
    Ssh,
    /// `git://host/path` (unauthenticated, unencrypted git daemon)
    Git,
    /// `file:///path` (only with `allow_local`)
    File,
    /// A local filesystem path (only with `allow_local`)
    Local,
}

impl UrlKind {
    /// Name of the git protocol (as used by `protocol.<name>.allow`).
    pub fn protocol(self) -> &'static str {
        match self {
            UrlKind::Https => "https",
            UrlKind::Ssh => "ssh",
            UrlKind::Git => "git",
            UrlKind::File | UrlKind::Local => "file",
        }
    }
}

/// Validates `url` and returns the transport git will use for it.
///
/// Accepted: `https://`, `ssh://` (`git+ssh://`, `ssh+git://`), `git://`
/// and scp-like `[user@]host:path`. `file://` URLs and local paths are only
/// accepted when `allow_local` is true. Everything else is rejected,
/// including remote-helper transports (`ext::`, `fd::`, any `<name>::`),
/// other URL schemes (`http`, `ftp`, ...), values starting with `-`
/// (argument injection) and values containing whitespace or control
/// characters.
pub fn validate_url(url: &str, allow_local: bool) -> Result<UrlKind, CloneError> {
    let invalid = |reason: &'static str| CloneError::InvalidUrl {
        url: redact_url(url),
        reason,
    };
    let not_allowed = |protocol: &str| CloneError::ProtocolNotAllowed {
        url: redact_url(url),
        protocol: protocol.to_owned(),
    };

    if url.is_empty() {
        return Err(invalid("empty URL"));
    }
    if url.len() > MAX_URL_LEN {
        return Err(invalid("URL too long"));
    }
    if url.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(invalid("contains whitespace or control characters"));
    }
    if url.starts_with('-') {
        return Err(invalid("starts with '-' (would be parsed as an option)"));
    }

    // `<transport>::<address>` invokes the remote helper `git-remote-<transport>`
    // (`ext::` runs arbitrary commands, `fd::` uses inherited file descriptors).
    let scheme_len = scheme_prefix_len(url);
    if scheme_len > 0 && url[scheme_len..].starts_with("::") {
        return Err(not_allowed(&url[..scheme_len]));
    }

    if scheme_len > 0 && url[scheme_len..].starts_with("://") {
        let scheme = &url[..scheme_len];
        let rest = &url[scheme_len + 3..];
        let kind = match scheme {
            "https" => UrlKind::Https,
            "ssh" | "git+ssh" | "ssh+git" => UrlKind::Ssh,
            "git" => UrlKind::Git,
            "file" if allow_local => return Ok(UrlKind::File),
            other => return Err(not_allowed(other)),
        };
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        if authority.contains('%') {
            // `%2D` could decode to a leading '-' after our checks.
            return Err(invalid("percent-encoding in the host or user part"));
        }
        if authority.contains("[-") {
            return Err(invalid("host or user starts with '-'"));
        }
        let (userinfo, hostport) = match authority.rfind('@') {
            Some(at) => (Some(&authority[..at]), &authority[at + 1..]),
            None => (None, authority),
        };
        if hostport.is_empty() || hostport.starts_with(':') {
            return Err(invalid("missing host"));
        }
        if hostport.starts_with('-') || userinfo.is_some_and(|u| u.starts_with('-')) {
            return Err(invalid("host or user starts with '-'"));
        }
        return Ok(kind);
    }

    // scp-like syntax: a ':' with no '/' before it (git's `url_is_local_not_ssh`).
    if let Some(colon) = url.find(':') {
        let prefix = &url[..colon];
        let is_dos_drive = cfg!(windows) && prefix.len() == 1;
        if !prefix.contains('/') && !is_dos_drive {
            if prefix.contains('[') || prefix.contains(']') {
                return Err(invalid(
                    "bracketed hosts are not supported in scp-like syntax",
                ));
            }
            if prefix.contains('%') {
                return Err(invalid("percent-encoding in the host or user part"));
            }
            let (user, host) = match prefix.rfind('@') {
                Some(at) => (Some(&prefix[..at]), &prefix[at + 1..]),
                None => (None, prefix),
            };
            if host.is_empty() {
                return Err(invalid("missing host"));
            }
            if host.starts_with('-') || user.is_some_and(|u| u.starts_with('-')) {
                return Err(invalid("host or user starts with '-'"));
            }
            if url[colon + 1..].is_empty() {
                return Err(invalid("missing repository path"));
            }
            return Ok(UrlKind::Ssh);
        }
    }

    if allow_local {
        Ok(UrlKind::Local)
    } else {
        Err(not_allowed("file"))
    }
}

/// Length of a leading URL scheme (`[A-Za-z][A-Za-z0-9+.-]*`), 0 if none.
fn scheme_prefix_len(url: &str) -> usize {
    let bytes = url.as_bytes();
    if !bytes.first().is_some_and(u8::is_ascii_alphabetic) {
        return 0;
    }
    bytes
        .iter()
        .position(|&b| !(b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-')))
        .unwrap_or(bytes.len())
}

/// Byte ranges of `url` that may hold credentials: the userinfo of a
/// `scheme://` URL and the query string. The userinfo is taken up to the
/// *last* `@` before the query, so a password containing an unescaped `/` or
/// `@` is still covered (at the price of over-redacting the rare path that
/// contains `@`).
fn secret_ranges(url: &str) -> (Option<(usize, usize)>, Option<usize>) {
    let Some(sep) = url.find("://") else {
        return (None, None);
    };
    let start = sep + 3;
    let rest = &url[start..];
    let query = rest.find(['?', '#']).map(|q| start + q);
    let pre_query = &url[start..query.unwrap_or(url.len())];
    let userinfo = pre_query.rfind('@').map(|at| (start, start + at));
    (userinfo, query)
}

/// Returns `url` with credentials removed, safe to print or log.
///
/// `https://user:token@host/repo?x=y` becomes `https://***@host/repo?***`.
/// Control characters are replaced with `?` so the result is also safe to
/// write to a terminal. scp-like `user@host:path` is returned unchanged (that
/// syntax cannot carry a password).
pub fn redact_url(url: &str) -> String {
    let (userinfo, query) = secret_ranges(url);
    let mut out = String::with_capacity(url.len());
    let mut pos = 0;
    if let Some((start, end)) = userinfo {
        out.push_str(&url[..start]);
        out.push_str("***");
        pos = end;
    }
    match query {
        Some(q) => {
            out.push_str(&url[pos..q]);
            out.push_str(&url[q..q + 1]);
            out.push_str("***");
        }
        None => out.push_str(&url[pos..]),
    }
    sanitize(&out)
}

/// Userinfo of a `scheme://` URL parsed like [`validate_url`] and git do:
/// the authority ends at the first `/`, `?` or `#`, the userinfo is
/// everything before its last `@`. Returns `(start, at)` byte offsets.
fn strict_userinfo(url: &str) -> Option<(usize, usize)> {
    let start = url.find("://")? + 3;
    let rest = &url[start..];
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    authority.rfind('@').map(|at| (start, start + at))
}

/// The URL to store as `remote.origin.url` in the mirror, if it differs
/// from `url`: drops the password (any scheme), the whole userinfo for
/// `https` (hosts accept a token as user name) and, for `https` only, the
/// query/fragment. Host and path are never changed.
pub(crate) fn sanitized_remote_url(url: &str, kind: UrlKind) -> Option<String> {
    let start = url.find("://")? + 3;
    let end = match kind {
        UrlKind::Https => url[start..]
            .find(['?', '#'])
            .map_or(url.len(), |q| start + q),
        _ => url.len(),
    };
    let mut out = url[..start].to_owned();
    match strict_userinfo(url) {
        Some((_, at)) => {
            if kind != UrlKind::Https {
                let user = url[start..at].split(':').next().unwrap_or("");
                if !user.is_empty() {
                    out.push_str(user);
                    out.push('@');
                }
            }
            out.push_str(&url[at + 1..end]);
        }
        None => out.push_str(&url[start..end]),
    }
    (out != url).then_some(out)
}

/// Percent-decodes `s` if it contains a valid `%XX` escape and the result
/// is UTF-8; `None` otherwise.
fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut changed = false;
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        if bytes[i] == b'%'
            && let (Some(hi), Some(lo)) = (
                bytes.get(i + 1).copied().and_then(hex),
                bytes.get(i + 2).copied().and_then(hex),
            )
        {
            out.push(u8::try_from(hi * 16 + lo).unwrap_or(b'?'));
            changed = true;
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    changed.then(|| String::from_utf8(out).ok()).flatten()
}

/// Redacts free text (git's stderr) that may echo `raw_url`: every literal
/// occurrence of a credential from `raw_url` and every `scheme://` token is
/// redacted, and control characters other than newline and tab are replaced
/// with `?` (a hostile server can send terminal escapes through
/// `remote:` side-band messages).
pub(crate) fn redact_text(text: &str, raw_url: &str) -> String {
    let mut text = text.to_owned();
    let (_, query) = secret_ranges(raw_url);
    let mut secrets: Vec<&str> = Vec::new();
    if let Some((start, end)) = strict_userinfo(raw_url) {
        let info = &raw_url[start..end];
        match info.split_once(':') {
            Some((_, password)) => secrets.extend([info, password]),
            // A bare https user name is often a token; an ssh user name
            // (`git`) is not secret and would mangle every "git" in the text.
            None if raw_url.starts_with("https://") => secrets.push(info),
            None => {}
        }
    }
    if let Some(q) = query {
        let query = &raw_url[q + 1..];
        secrets.push(query);
        // Values may be echoed on their own; skip tiny ones (`1`, `on`)
        // that would mangle unrelated text.
        secrets.extend(
            query
                .split(['&', ';', '#'])
                .filter_map(|pair| pair.split_once('=').map(|(_, v)| v))
                .filter(|v| v.len() >= 3),
        );
    }
    // git and servers may echo the decoded form of `%XX`-escaped credentials.
    let mut secrets: Vec<String> = secrets
        .into_iter()
        .flat_map(|s| [Some(s.to_owned()), percent_decode(s)])
        .flatten()
        .filter(|s| !s.is_empty())
        .collect();
    // Longest first, so a secret that contains another is replaced whole.
    secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
    for secret in &secrets {
        text = text.replace(secret.as_str(), "***");
    }

    let is_boundary = |c: char| c.is_whitespace() || matches!(c, '\'' | '"' | '`' | '<' | '>');
    let mut out = String::with_capacity(text.len());
    let mut pos = 0;
    while let Some(found) = text[pos..].find("://") {
        let sep = pos + found;
        let start = text[pos..sep].rfind(is_boundary).map_or(pos, |b| {
            pos + b + text[pos + b..].chars().next().map_or(1, char::len_utf8)
        });
        let end = text[sep..]
            .find(is_boundary)
            .map_or(text.len(), |e| sep + e);
        out.push_str(&text[pos..start]);
        out.push_str(&redact_url(&text[start..end]));
        pos = end;
    }
    out.push_str(&text[pos..]);
    out.chars()
        .map(|c| {
            if c.is_control() && c != '\n' && c != '\t' {
                '?'
            } else {
                c
            }
        })
        .collect()
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_allowed_urls() {
        let cases = [
            ("https://example.invalid/group/repo.git", UrlKind::Https),
            ("https://user@example.invalid/repo", UrlKind::Https),
            ("https://example.invalid:8443/repo", UrlKind::Https),
            ("https://[::1]:8443/repo", UrlKind::Https),
            ("ssh://git@example.invalid/repo.git", UrlKind::Ssh),
            ("ssh://example.invalid:2222/repo.git", UrlKind::Ssh),
            ("git+ssh://example.invalid/repo.git", UrlKind::Ssh),
            ("ssh+git://example.invalid/repo.git", UrlKind::Ssh),
            ("git://example.invalid/repo.git", UrlKind::Git),
            ("git@example.invalid:group/repo.git", UrlKind::Ssh),
            ("example.invalid:repo.git", UrlKind::Ssh),
            ("https://example.invalid/@scope/repo", UrlKind::Https),
            ("https://example.invalid/a%20b.git", UrlKind::Https),
        ];
        for (url, kind) in cases {
            assert_eq!(validate_url(url, false).ok(), Some(kind), "{url}");
        }
    }

    #[test]
    fn rejects_dangerous_urls() {
        let cases = [
            "",
            "ext::sh -c touch% /tmp/pwned",
            "ext::sh",
            "fd::17",
            "foo::bar",
            "https::example.invalid",
            "http://example.invalid/repo",
            "ftp://example.invalid/repo",
            "HTTPS://example.invalid/repo",
            "file:///tmp/repo",
            "/tmp/repo",
            "./repo",
            "repo",
            "-uhttps://example.invalid",
            "--upload-pack=touch /tmp/pwned",
            "https://example.invalid/repo --upload-pack=x",
            "https://example.invalid/re\npo",
            "https://example.invalid/re\tpo",
            "https://example.invalid/\u{1b}[31m",
            "https://",
            "https:///path",
            "https://user@/path",
            "ssh://-oProxyCommand=touch%20x/repo",
            "ssh://-oProxyCommand=x@example.invalid/repo",
            "-oProxyCommand=x:repo",
            "git@-oProxyCommand=x:repo",
            "@:repo",
            "host:",
            "[::1]:repo",
            "https://us%65r@example.invalid/r",
            "https://example%2Einvalid/r",
            "ssh://%2DoProxyCommand=x/r",
            "ssh://git@%2DoProxyCommand=x/r",
            "ssh://[-oProxyCommand=x]/r",
            "ssh://git@[-oProxyCommand=x]:22/r",
            "git%40@example.invalid:r",
            "%2Doption:r",
        ];
        for url in cases {
            assert!(
                validate_url(url, false).is_err(),
                "{url:?} should be rejected"
            );
        }
        assert!(validate_url(&"a".repeat(MAX_URL_LEN + 1), true).is_err());
    }

    #[test]
    fn local_only_with_allow_local() {
        assert_eq!(
            validate_url("file:///tmp/repo", true).ok(),
            Some(UrlKind::File)
        );
        assert_eq!(validate_url("/tmp/repo", true).ok(), Some(UrlKind::Local));
        assert_eq!(validate_url("./repo", true).ok(), Some(UrlKind::Local));
        // allow_local never relaxes the other rules.
        assert!(validate_url("ext::sh", true).is_err());
        assert!(validate_url("-repo", true).is_err());
        assert!(validate_url("http://example.invalid/r", true).is_err());
        assert!(matches!(
            validate_url("/tmp/repo", false),
            Err(CloneError::ProtocolNotAllowed { protocol, .. }) if protocol == "file"
        ));
    }

    #[test]
    fn errors_never_contain_the_raw_credential() {
        let url = "http://someone:not-a-real-pass@example.invalid/repo";
        let err = validate_url(url, false).unwrap_err();
        assert!(!err.to_string().contains("not-a-real-pass"));
        assert!(!format!("{err:?}").contains("not-a-real-pass"));
        let err =
            validate_url("https://someone:not-a-real-pass@example.invalid/a b", false).unwrap_err();
        assert!(!format!("{err} {err:?}").contains("not-a-real-pass"));
    }

    #[test]
    fn redacts_urls() {
        let cases = [
            (
                "https://example.invalid/repo.git",
                "https://example.invalid/repo.git",
            ),
            (
                "https://user:pw@example.invalid/repo",
                "https://***@example.invalid/repo",
            ),
            (
                "https://tokenonly@example.invalid/repo",
                "https://***@example.invalid/repo",
            ),
            (
                "https://u:p@ss/word@example.invalid/r",
                "https://***@example.invalid/r",
            ),
            (
                "https://example.invalid/r?private_token=x",
                "https://example.invalid/r?***",
            ),
            (
                "https://u:p@example.invalid/r#frag",
                "https://***@example.invalid/r#***",
            ),
            ("ssh://git@example.invalid/r", "ssh://***@example.invalid/r"),
            (
                "git@example.invalid:group/r.git",
                "git@example.invalid:group/r.git",
            ),
            (
                "https://example.invalid/\u{1b}[2J",
                "https://example.invalid/?[2J",
            ),
            // Deliberate over-redaction: a password may contain an unescaped
            // '/' or '@', so display redaction runs to the last '@'.
            (
                "https://example.invalid/@scope/repo",
                "https://***@scope/repo",
            ),
            ("", ""),
        ];
        for (input, want) in cases {
            assert_eq!(redact_url(input), want, "{input}");
        }
    }

    #[test]
    fn sanitizes_remote_url() {
        let s = |u, k| sanitized_remote_url(u, k);
        assert_eq!(s("https://example.invalid/r", UrlKind::Https), None);
        assert_eq!(
            s("https://u:p@example.invalid/r", UrlKind::Https).as_deref(),
            Some("https://example.invalid/r")
        );
        assert_eq!(
            s("https://tok@example.invalid/r?a=b", UrlKind::Https).as_deref(),
            Some("https://example.invalid/r")
        );
        assert_eq!(
            s("ssh://git:pw@example.invalid/r", UrlKind::Ssh).as_deref(),
            Some("ssh://git@example.invalid/r")
        );
        assert_eq!(s("ssh://git@example.invalid/r", UrlKind::Ssh), None);
        // The origin rewrite never touches host or path.
        assert_eq!(
            s("https://example.invalid/@scope/repo", UrlKind::Https),
            None
        );
        assert_eq!(
            s("https://u:p@example.invalid/@scope/repo", UrlKind::Https).as_deref(),
            Some("https://example.invalid/@scope/repo")
        );
        assert_eq!(s("ssh://example.invalid/r?x#y", UrlKind::Ssh), None);
        assert_eq!(s("git://example.invalid/r#frag", UrlKind::Git), None);
        assert_eq!(
            s("ssh://git:pw@example.invalid/a@b?c", UrlKind::Ssh).as_deref(),
            Some("ssh://git@example.invalid/a@b?c")
        );
        assert_eq!(s("git@example.invalid:r.git", UrlKind::Ssh), None);
    }

    #[test]
    fn redacts_text() {
        let raw = "https://someone:not-a-real-pass@example.invalid/r?k=fake-query-secret";
        let text = "fatal: unable to access 'https://someone:not-a-real-pass@example.invalid/r/': \
                    denied\nremote: password not-a-real-pass rejected, fake-query-secret\n\
                    see https://other:also-fake@mirror.invalid/x\u{1b}[31m";
        let out = redact_text(text, raw);
        for secret in [
            "not-a-real-pass",
            "fake-query-secret",
            "also-fake",
            "\u{1b}",
        ] {
            assert!(!out.contains(secret), "{secret:?} leaked in {out:?}");
        }
        assert!(out.contains("'https://***@example.invalid/r/'"), "{out}");
        assert!(out.contains("https://***@mirror.invalid/x?[31m"), "{out}");
        assert!(out.contains("denied\nremote:"), "{out}");
        assert_eq!(
            redact_text("plain ünïcode\ttext", "git@h:r"),
            "plain ünïcode\ttext"
        );
        assert_eq!(
            redact_text("git: fatal", "ssh://git@example.invalid/r"),
            "git: fatal"
        );
        // The percent-decoded form of a credential is redacted too.
        let out = redact_text(
            "auth failed for p@ss/fake-pw and p%40ss%2Ffake-pw",
            "https://u:p%40ss%2Ffake-pw@example.invalid/r",
        );
        assert_eq!(out, "auth failed for *** and ***");
        assert_eq!(percent_decode("a%2Fb%zz%4"), Some("a/b%zz%4".to_owned()));
        assert_eq!(percent_decode("plain"), None);
        assert_eq!(percent_decode("%FF"), None);
    }
}
