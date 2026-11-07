//! Parsers for credential-bearing argument values.
//!
//! Every parser returns subslices of its input, so the caller can map the
//! secret back to a byte span.

/// A secret inside a value, with optional user and host for context.
/// `Debug` redacts the secret.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Cred<'a> {
    pub secret: &'a str,
    pub user: Option<&'a str>,
    pub host: Option<&'a str>,
}

impl std::fmt::Debug for Cred<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cred")
            .field(
                "secret",
                &format_args!("[redacted; {} bytes]", self.secret.len()),
            )
            .field("user", &self.user)
            .field("host", &self.host)
            .finish()
    }
}

impl<'a> Cred<'a> {
    pub fn bare(secret: &'a str) -> Self {
        Cred {
            secret,
            user: None,
            host: None,
        }
    }
}

/// `user<sep>pass`: the secret is after the first separator.
pub fn userpass<'a>(v: &'a str, sep: &str) -> Option<Cred<'a>> {
    let (user, pass) = v.split_once(sep)?;
    Some(Cred {
        secret: pass,
        user: non_empty(user),
        host: None,
    })
}

/// `scheme://user:pass@host/...`: the password in the userinfo of the first URI.
pub fn uri(v: &str) -> Option<Cred<'_>> {
    let p = v.find("://")?;
    let rest = &v[p + 3..];
    let auth_end = rest.find(['/', '?', '#', ' ']).unwrap_or(rest.len());
    let auth = &rest[..auth_end];
    let at = auth.rfind('@')?;
    let (user, pass) = auth[..at].split_once(':')?;
    let host = &auth[at + 1..];
    Some(Cred {
        secret: pass,
        user: non_empty(user),
        host: non_empty(host),
    })
}

/// libpq conninfo `host=x user=y password=z` (or a URI).
pub fn libpq(v: &str) -> Option<Cred<'_>> {
    if v.contains("://") {
        return uri(v);
    }
    let mut secret = None;
    let mut user = None;
    let mut host = None;
    let b = v.as_bytes();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let ks = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'=' {
            i += 1;
        }
        let key = &v[ks..i];
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        if b.get(i) != Some(&b'=') {
            continue;
        }
        i += 1;
        while i < b.len() && b[i] == b' ' {
            i += 1;
        }
        let (vs, ve);
        if b.get(i) == Some(&b'\'') {
            vs = i + 1;
            let mut j = vs;
            while j < b.len() && b[j] != b'\'' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            ve = j.min(b.len());
            i = ve + 1;
        } else {
            vs = i;
            while i < b.len() && !b[i].is_ascii_whitespace() {
                i += 1;
            }
            ve = i;
        }
        let val = v.get(vs..ve).unwrap_or("");
        let is = |k: &str| key.eq_ignore_ascii_case(k);
        if is("password") {
            secret = Some(val);
        } else if is("user") {
            user = non_empty(val);
        } else if is("host") || is("hostaddr") {
            host = non_empty(val);
        }
    }
    Some(Cred {
        secret: secret?,
        user,
        host,
    })
}

/// JDBC URL: userinfo, or a `password=` parameter after `;`, `?` or `&`.
pub fn jdbc(v: &str) -> Option<Cred<'_>> {
    if let Some(c) = uri(v) {
        return Some(c);
    }
    let secret = param(v, "password", &[';', '?', '&'])?;
    Some(Cred {
        secret,
        user: param(v, "user", &[';', '?', '&']).and_then(non_empty),
        host: None,
    })
}

/// Value of `name=` (ASCII-case-insensitive) that starts the text or follows
/// one of `seps`; it ends at the next separator.
fn param<'a>(v: &'a str, name: &str, seps: &[char]) -> Option<&'a str> {
    let b = v.as_bytes();
    let n = name.len();
    (0..b.len()).find_map(|at| {
        let ok = v.is_char_boundary(at)
            && (at == 0 || v[..at].ends_with(seps))
            && b.get(at..at + n)
                .is_some_and(|w| w.eq_ignore_ascii_case(name.as_bytes()))
            && b.get(at + n) == Some(&b'=');
        ok.then(|| {
            let vs = at + n + 1;
            let ve = v[vs..].find(seps).map_or(v.len(), |e| vs + e);
            &v[vs..ve]
        })
    })
}

/// Oracle `user/pass@db`; `/ as sysdba` and `/nolog` carry no secret.
pub fn oracle(v: &str) -> Option<Cred<'_>> {
    let (user, rest) = v.split_once('/')?;
    if user.is_empty() || user.contains(char::is_whitespace) || user.contains('@') {
        return None;
    }
    let (pass, host) = match rest.rfind('@') {
        Some(at) => (&rest[..at], non_empty(&rest[at + 1..])),
        None => (rest, None),
    };
    Some(Cred {
        secret: pass,
        user: Some(user),
        host,
    })
}

/// Impacket target `DOMAIN/user:PASS@host`.
pub fn impacket(v: &str) -> Option<Cred<'_>> {
    let at = v.rfind('@')?;
    let pre = &v[..at];
    let up = pre.rfind('/').map_or(pre, |s| &pre[s + 1..]);
    let (user, pass) = up.split_once(':')?;
    Some(Cred {
        secret: pass,
        user: non_empty(user),
        host: non_empty(&v[at + 1..]),
    })
}

/// CVS `:pserver:user:pass@host:/repo`.
pub fn cvs_pserver(v: &str) -> Option<Cred<'_>> {
    let rest = v.strip_prefix(':')?;
    let (_method, rest) = rest.split_once(':')?;
    let at = rest.rfind('@')?;
    let (user, pass) = rest[..at].split_once(':')?;
    let host = rest[at + 1..].split(':').next().and_then(non_empty);
    Some(Cred {
        secret: pass,
        user: non_empty(user),
        host,
    })
}

/// `key=value;key=value` connection strings (Azure storage, ADO.NET).
/// Calls `f(key, value)` for each pair.
pub fn semicolon_pairs<'a>(v: &'a str, mut f: impl FnMut(&'a str, &'a str)) {
    for part in v.split(';') {
        if let Some((k, val)) = part.split_once('=') {
            f(k.trim(), val.trim());
        }
    }
}

/// Key names of connection-string slots that hold a secret.
pub fn is_connstring_secret_key(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    ["password", "pwd", "key", "secret", "signature", "token"]
        .iter()
        .any(|s| k.ends_with(s))
}

/// SAS URL: the `sig` query parameter.
pub fn sas_url(v: &str) -> Option<Cred<'_>> {
    let q = &v[v.find('?')? + 1..];
    q.split('&')
        .find_map(|p| p.strip_prefix("sig="))
        .map(Cred::bare)
}

/// An HTTP header `Name: value`. Returns the name and the value.
pub fn header(v: &str) -> Option<(&str, &str)> {
    let (name, value) = v.split_once(':')?;
    let name = name.trim();
    if name.is_empty()
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
    {
        return None;
    }
    Some((name, value.trim()))
}

/// Scheme of an `Authorization` value (`Bearer x`, `Basic x`); returns the
/// scheme (lower-cased match) and the credential.
pub fn auth_scheme(v: &str) -> Option<(&'static str, &str)> {
    let (scheme, rest) = v.split_once(' ')?;
    let s = [
        "bearer", "basic", "token", "bot", "apikey", "api-key", "key", "sso-key",
    ]
    .into_iter()
    .find(|s| scheme.eq_ignore_ascii_case(s))?;
    Some((s, rest.trim()))
}

/// Calls `f(name, value)` for each `k=v` pair split by `sep`.
pub fn pairs<'a>(v: &'a str, sep: char, mut f: impl FnMut(&'a str, &'a str)) {
    for part in v.split(sep) {
        if let Some((k, val)) = part.split_once('=') {
            f(k.trim(), val.trim());
        }
    }
}

/// `NAME=VAL` pairs separated by commas or whitespace, where a separator only
/// counts if a `NAME=` follows it (values may contain commas and spaces).
pub fn keyvalue_list<'a>(v: &'a str, mut f: impl FnMut(&'a str, &'a str)) {
    let b = v.as_bytes();
    let mut cur = next_name(b, 0);
    while let Some((s, n)) = cur {
        let next = next_name(b, s + n);
        let mut e = next.map_or(b.len(), |(ns, _)| ns);
        // Drop the separator before the next segment.
        if next.is_some() {
            while e > s && matches!(b[e - 1], b',' | b' ' | b'\t' | b'\n') {
                e -= 1;
            }
        }
        if let Some((name, val)) = v[s..e].split_once('=') {
            f(name, val);
        }
        cur = next;
    }
}

/// The next `NAME=` segment at or after `i` that starts the text or follows a
/// separator: (start, length of `NAME=`).
fn next_name(b: &[u8], mut i: usize) -> Option<(usize, usize)> {
    while i < b.len() {
        let at_start = i == 0 || matches!(b[i - 1], b',' | b' ' | b'\t' | b'\n');
        if at_start && let Some(n) = name_len(&b[i..]) {
            return Some((i, n));
        }
        i += 1;
    }
    None
}

/// Length of `NAME=` at the start of `b` (identifier chars plus `.-:/[]@`).
fn name_len(b: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i < b.len()
        && (b[i].is_ascii_alphanumeric()
            || matches!(b[i], b'_' | b'.' | b'-' | b':' | b'/' | b'[' | b']' | b'@'))
    {
        i += 1;
    }
    (i > 0
        && b.get(i) == Some(&b'=')
        && (b[0].is_ascii_alphabetic() || matches!(b[0], b'_' | b'/')))
    .then_some(i + 1)
}

/// `"key": "value"` pairs in JSON-ish text. Calls `f(key, value)`.
pub fn json_pairs<'a>(v: &'a str, mut f: impl FnMut(&'a str, &'a str)) {
    let b = v.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'"' {
            i += 1;
            continue;
        }
        let ks = i + 1;
        let ke = string_end(b, ks);
        let mut j = ke + 1;
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if b.get(j) != Some(&b':') {
            i = ke + 1;
            continue;
        }
        j += 1;
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if b.get(j) == Some(&b'"') {
            let vs = j + 1;
            let ve = string_end(b, vs);
            if let (Some(k), Some(val)) = (v.get(ks..ke), v.get(vs..ve)) {
                f(k, val);
            }
            i = ve + 1;
        } else {
            i = j;
        }
    }
}

fn string_end(b: &[u8], mut i: usize) -> usize {
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return i,
            _ => i += 1,
        }
    }
    b.len()
}

/// HTTPie request item: `Header:Value`, `field=value`, `field:=json`,
/// `param==value`. Returns (separator, name, value).
pub fn httpie_item(v: &str) -> Option<(&'static str, &str, &str)> {
    let k = v.find([':', '=', '@'])?;
    let (name, rest) = v.split_at(k);
    for sep in ["==", ":=", "=", ":"] {
        if let Some(val) = rest.strip_prefix(sep) {
            return Some((sep, name, val));
        }
    }
    None
}

/// PowerShell hashtable `@{ k = "v"; 'k2' = 'v2' }`. Calls `f(key, value)`.
pub fn hashtable<'a>(v: &'a str, mut f: impl FnMut(&'a str, &'a str)) {
    let Some(inner) = v.trim().strip_prefix("@{") else {
        return;
    };
    let inner = inner.strip_suffix('}').unwrap_or(inner);
    for part in inner.split([';', '\n']) {
        if let Some((k, val)) = part.split_once('=') {
            f(unquote(k.trim()), unquote(val.trim()));
        }
    }
}

/// Strip one pair of matching quotes.
pub fn unquote(s: &str) -> &str {
    let b = s.as_bytes();
    if b.len() >= 2 && b[0] == b[b.len() - 1] && matches!(b[0], b'"' | b'\'') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

fn non_empty(s: &str) -> Option<&str> {
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userpass_and_uri() {
        assert_eq!(userpass("admin:Cu7l:x", ":").unwrap().secret, "Cu7l:x");
        assert_eq!(userpass("admin", ":"), None);
        let c = uri("postgres://app:Pq7zW@db.acme.io:5432/x").unwrap();
        assert_eq!(
            (c.secret, c.user, c.host),
            ("Pq7zW", Some("app"), Some("db.acme.io:5432"))
        );
        assert_eq!(uri("https://db.acme.io/x@y"), None);
        assert_eq!(uri("https://tok@db.acme.io/"), None);
    }

    #[test]
    fn libpq_conninfo() {
        let c = libpq("host=db.acme.io user=app password='a b c' dbname=x").unwrap();
        assert_eq!(
            (c.secret, c.user, c.host),
            ("a b c", Some("app"), Some("db.acme.io"))
        );
        assert_eq!(libpq("password = Zx9k port=5").unwrap().secret, "Zx9k");
        assert_eq!(libpq("orders"), None);
        assert_eq!(libpq("select 1"), None);
    }

    #[test]
    fn other_syntaxes() {
        assert_eq!(
            jdbc("jdbc:hive2://h:1/db;user=u;password=Hv8q")
                .unwrap()
                .secret,
            "Hv8q"
        );
        assert_eq!(oracle("scott/T1ger9@orcl").unwrap().secret, "T1ger9");
        assert_eq!(oracle("/ as sysdba"), None);
        assert_eq!(oracle("/nolog"), None);
        let c = impacket("CORP/alice:Wi9!x@10.0.0.5").unwrap();
        assert_eq!(
            (c.secret, c.user, c.host),
            ("Wi9!x", Some("alice"), Some("10.0.0.5"))
        );
        assert_eq!(
            cvs_pserver(":pserver:bob:Cv5s@cvs.acme.io:/repo")
                .unwrap()
                .secret,
            "Cv5s"
        );
        assert_eq!(
            sas_url("https://a.blob.x/c?sv=1&sig=AbC%2B")
                .unwrap()
                .secret,
            "AbC%2B"
        );
    }

    #[test]
    fn headers() {
        assert_eq!(
            header("Authorization: Bearer x y"),
            Some(("Authorization", "Bearer x y"))
        );
        assert_eq!(header("a b: c"), None);
        assert_eq!(auth_scheme("Bearer Zt7"), Some(("bearer", "Zt7")));
        assert_eq!(auth_scheme("Zt7"), None);
    }

    #[test]
    fn lists() {
        let mut got = Vec::new();
        keyvalue_list("user=a,password=b,c,vers=3", |k, v| got.push((k, v)));
        assert_eq!(got, vec![("user", "a"), ("password", "b,c"), ("vers", "3")]);
        got.clear();
        keyvalue_list("ansible_password=p w x=1", |k, v| got.push((k, v)));
        assert_eq!(got, vec![("ansible_password", "p w"), ("x", "1")]);
        got.clear();
        json_pairs(r#"{"user": "a", "password":"b\"c", "n": 1}"#, |k, v| {
            got.push((k, v))
        });
        assert_eq!(got, vec![("user", "a"), ("password", r#"b\"c"#)]);
        got.clear();
        hashtable(
            r#"@{Authorization="Bearer t"; 'X-Api-Key' = 'k'}"#,
            |k, v| got.push((k, v)),
        );
        assert_eq!(got, vec![("Authorization", "Bearer t"), ("X-Api-Key", "k")]);
        assert_eq!(httpie_item("token==abc"), Some(("==", "token", "abc")));
        assert_eq!(
            httpie_item("Authorization:Bearer x"),
            Some((":", "Authorization", "Bearer x"))
        );
        assert_eq!(
            httpie_item("password:=\"x\""),
            Some((":=", "password", "\"x\""))
        );
    }
}
