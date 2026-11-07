//! Structural analyzer for credential file formats (`file_formats`, catalogue
//! section 6): `.netrc`, `.pgpass`, docker `auths`, git credentials and config,
//! kubeconfig, unencrypted PuTTY keys, plus a generic `secret_keys` scanner for
//! INI/JSON/YAML-style credential files. Shell history files are split into
//! commands for the shell analyzer ([`history_commands`]).
//!
//! Candidates use the format id as rule id and category `credential_file`.
//! Spans are byte ranges in the analyzed text.

use std::ops::Range;

use agentleaks_core::{Candidate, Category, Confidence, Context, Secret, SecretKind, Severity};
use agentleaks_spec::{FileFormat, PostProcess, Spec};
use base64::Engine as _;
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;

use crate::filter::{Verdict, adjust_severity, check_value, clean_value, host_of};

/// How a format is analyzed.
#[derive(Debug)]
enum Kind {
    Netrc,
    /// The format's own regex; group `secret`, optional `user`/`host`.
    Regex(Regex),
    DockerConfig,
    GitConfig,
    Kubeconfig,
    PuttyPpk,
    /// Generic `secret_keys` scanner.
    SecretKeys(Regex),
    /// Split into commands; analyzed by the shell and regex analyzers.
    ShellHistory,
    /// Handled elsewhere (path rules → other analyzers) or not yet.
    Other,
}

#[derive(Debug)]
struct Format<'s> {
    def: &'s FileFormat,
    kind: Kind,
}

/// Matches file paths to formats and analyzes them.
#[derive(Debug)]
pub struct FormatAnalyzer<'s> {
    spec: &'s Spec,
    formats: Vec<Format<'s>>,
    globs: GlobSet,
    /// Glob index → format index.
    glob_owner: Vec<usize>,
    docker: Regex,
    git_url: Regex,
    git_header: Regex,
    kube: Regex,
}

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("file_formats.{id}: bad glob {glob:?}: {source}")]
    Glob {
        id: String,
        glob: String,
        source: globset::Error,
    },
    #[error("file_formats.{id}: {msg}")]
    Invalid { id: String, msg: String },
    #[error(transparent)]
    Regex(#[from] regex::Error),
    #[error(transparent)]
    GlobSet(#[from] globset::Error),
}

impl<'s> FormatAnalyzer<'s> {
    pub fn new(spec: &'s Spec) -> Result<Self, FormatError> {
        let mut formats = Vec::new();
        let mut b = GlobSetBuilder::new();
        let mut glob_owner = Vec::new();
        for def in &spec.file_formats {
            let kind = kind_for(def)?;
            let fi = formats.len();
            for g in &def.paths {
                let glob = glob_for(g).map_err(|source| FormatError::Glob {
                    id: def.id.clone(),
                    glob: g.clone(),
                    source,
                })?;
                b.add(glob);
                glob_owner.push(fi);
            }
            formats.push(Format { def, kind });
        }
        Ok(FormatAnalyzer {
            spec,
            formats,
            globs: b.build()?,
            glob_owner,
            docker: Regex::new(
                r#""(?P<key>auth|identitytoken|registrytoken|password)"\s*:\s*"(?P<secret>[^"\\]*)""#,
            )?,
            git_url: Regex::new(
                r"(?im)^\s*(?:url|pushurl)\s*=\s*\w[\w+.-]*://(?P<user>[^:@/\s]+):(?P<secret>[^@\s]+)@(?P<host>[^/\s:]+)",
            )?,
            git_header: Regex::new(
                r"(?im)^\s*extraheader\s*=\s*Authorization:\s*(?P<scheme>Basic|Bearer|token)\s+(?P<secret>\S+)",
            )?,
            kube: Regex::new(
                r#"(?m)^\s*(?:-\s+)?(?P<key>token|password|client-key-data|client-secret|refresh-token|id-token)\s*:\s*["']?(?P<secret>[^\s"'#]+)"#,
            )?,
        })
    }

    /// Ids of the formats whose `paths` match a report path (`/`-separated).
    pub fn formats_for(&self, path: &str) -> Vec<&'s str> {
        let mut ids: Vec<&'s str> = self
            .globs
            .matches(path)
            .into_iter()
            .map(|gi| self.formats[self.glob_owner[gi]].def.id.as_str())
            .collect();
        ids.dedup();
        ids
    }

    /// True if the format splits into commands (shell history).
    pub fn is_history(&self, id: &str) -> bool {
        self.format(id)
            .is_some_and(|f| matches!(f.kind, Kind::ShellHistory))
    }

    fn format(&self, id: &str) -> Option<&Format<'s>> {
        self.formats.iter().find(|f| f.def.id == id)
    }

    /// Analyze `text` as format `id`.
    pub fn analyze(&self, id: &str, text: &str, out: &mut Vec<Candidate<'s>>) {
        let Some(f) = self.format(id) else { return };
        let mut emit =
            |raw: Range<usize>, secret: Option<String>, ctx: Context, kind: SecretKind| {
                if let Some(c) = self.candidate(f.def, text, raw, secret, ctx, kind) {
                    out.push(c);
                }
            };
        match &f.kind {
            Kind::Netrc => netrc(text, f.def, &mut emit),
            Kind::Regex(re) => {
                for c in re.captures_iter(text) {
                    let Some(m) = c.name("secret") else { continue };
                    if line_is_comment(text, m.start()) {
                        continue;
                    }
                    let ctx = Context {
                        host: c.name("host").map(|h| host_of(h.as_str()).to_owned()),
                        user: c.name("user").map(|u| u.as_str().to_owned()),
                        ..Context::default()
                    };
                    emit(m.range(), None, ctx, SecretKind::Password);
                }
            }
            Kind::DockerConfig => {
                for c in self.docker.captures_iter(text) {
                    let (Some(k), Some(m)) = (c.name("key"), c.name("secret")) else {
                        continue;
                    };
                    if k.as_str() == "auth" {
                        // base64(user:pass) → pass
                        if let Some((user, pass)) = decode_userpass(m.as_str()) {
                            let ctx = Context {
                                user: Some(user),
                                ..Context::default()
                            };
                            emit(m.range(), Some(pass), ctx, SecretKind::Password);
                        }
                    } else {
                        emit(m.range(), None, Context::default(), SecretKind::Token);
                    }
                }
            }
            Kind::GitConfig => {
                for c in self.git_url.captures_iter(text) {
                    let Some(m) = c.name("secret") else { continue };
                    let ctx = Context {
                        host: c.name("host").map(|h| h.as_str().to_owned()),
                        user: c.name("user").map(|u| u.as_str().to_owned()),
                        ..Context::default()
                    };
                    emit(m.range(), None, ctx, SecretKind::Password);
                }
                for c in self.git_header.captures_iter(text) {
                    let Some(m) = c.name("secret") else { continue };
                    if c.name("scheme")
                        .is_some_and(|s| s.as_str().eq_ignore_ascii_case("basic"))
                    {
                        if let Some((user, pass)) = decode_userpass(m.as_str()) {
                            let ctx = Context {
                                user: Some(user),
                                ..Context::default()
                            };
                            emit(m.range(), Some(pass), ctx, SecretKind::Password);
                        }
                    } else {
                        emit(m.range(), None, Context::default(), SecretKind::Token);
                    }
                }
            }
            Kind::Kubeconfig => {
                for c in self.kube.captures_iter(text) {
                    let (Some(k), Some(m)) = (c.name("key"), c.name("secret")) else {
                        continue;
                    };
                    let kind = match k.as_str() {
                        "password" => SecretKind::Password,
                        "client-key-data" => SecretKind::Key,
                        _ => SecretKind::Token,
                    };
                    emit(m.range(), None, Context::default(), kind);
                }
            }
            Kind::PuttyPpk => putty(text, &mut emit),
            Kind::SecretKeys(re) => {
                for c in re.captures_iter(text) {
                    let Some(m) = c
                        .name("secret")
                        .or_else(|| c.name("secret2"))
                        .or_else(|| c.name("secret3"))
                    else {
                        continue;
                    };
                    if line_is_comment(text, m.start()) {
                        continue;
                    }
                    emit(m.range(), None, Context::default(), SecretKind::Credential);
                }
            }
            Kind::ShellHistory | Kind::Other => {}
        }
    }

    fn candidate(
        &self,
        def: &'s FileFormat,
        text: &str,
        raw: Range<usize>,
        decoded: Option<String>,
        ctx: Context,
        kind: SecretKind,
    ) -> Option<Candidate<'s>> {
        let min = match kind {
            SecretKind::Password | SecretKind::Passphrase | SecretKind::Credential => {
                self.spec.value_filters.min_length.password
            }
            SecretKind::Key => self.spec.value_filters.min_length.key,
            _ => self.spec.value_filters.min_length.token,
        };
        let (value, span) = match &decoded {
            Some(d) => (clean_value(d), raw),
            None => {
                let v = clean_value(&text[raw.clone()]);
                let off = v.as_ptr() as usize - text.as_ptr() as usize;
                (v, off..off + v.len())
            }
        };
        let (value, default) = match check_value(self.spec, value, min) {
            Verdict::Keep(v) => (v, false),
            Verdict::Default(v) => (v, true),
            Verdict::Drop => return None,
        };
        let base = def.severity.unwrap_or(Severity::High);
        Some(Candidate {
            rule_id: &def.id,
            category: Category::CredentialFile,
            kind: if default {
                SecretKind::DefaultCredential
            } else {
                kind
            },
            severity: adjust_severity(self.spec, base, ctx.host.as_deref(), default),
            confidence: Confidence::High,
            secret: Secret::new(value),
            span,
            context: ctx,
        })
    }
}

fn kind_for(def: &FileFormat) -> Result<Kind, FormatError> {
    let invalid = |msg: &str| FormatError::Invalid {
        id: def.id.clone(),
        msg: msg.to_owned(),
    };
    Ok(match def.id.as_str() {
        "fmt.netrc" => Kind::Netrc,
        "fmt.docker-config" => {
            let decodes = def
                .postprocess
                .values()
                .any(|p| *p == PostProcess::Base64DecodeUserpass);
            if !decodes {
                return Err(invalid(
                    "expected base64_decode_userpass post-processing for auth",
                ));
            }
            Kind::DockerConfig
        }
        "fmt.git-config" => Kind::GitConfig,
        "fmt.kubeconfig" => Kind::Kubeconfig,
        "fmt.putty-ppk" => Kind::PuttyPpk,
        "fmt.shell-history" => Kind::ShellHistory,
        _ => match (&def.regex, def.secret_keys.is_empty()) {
            (Some(re), _) if re.has_group("secret") => Kind::Regex(re.regex().clone()),
            (_, false) => Kind::SecretKeys(secret_keys_regex(&def.secret_keys)?),
            _ => Kind::Other,
        },
    })
}

/// `key = value`, `key: value`, `"key": "value"`, `<key>value</key>`-free
/// generic scanner for a list of exact (case-insensitive) key names.
fn secret_keys_regex(keys: &[String]) -> Result<Regex, regex::Error> {
    let alts: Vec<String> = keys.iter().map(|k| regex::escape(k)).collect();
    Regex::new(&format!(
        r#"(?im)(?:^|[\s{{,])["']?(?:{})["']?\s*[:=]\s*(?:"(?P<secret>[^"\\\n]*)"|'(?P<secret2>[^'\n]*)'|(?P<secret3>[^\s"',#;}}\]]+))"#,
        alts.join("|")
    ))
}

/// Catalogue globs → globset. `**/x` also matches `x` at the root.
fn glob_for(g: &str) -> Result<Glob, globset::Error> {
    globset::GlobBuilder::new(g)
        .literal_separator(true)
        .case_insensitive(false)
        .build()
}

fn line_is_comment(text: &str, pos: usize) -> bool {
    let start = text[..pos].rfind('\n').map_or(0, |i| i + 1);
    let line = text[start..pos].trim_start();
    line.starts_with('#') || line.starts_with(';')
}

/// `base64(user:pass)` → (user, pass). None if not decodable or no colon.
pub fn decode_userpass(b64: &str) -> Option<(String, String)> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let s = String::from_utf8(raw).ok()?;
    let (u, p) = s.split_once(':')?;
    Some((u.to_owned(), p.to_owned()))
}

/// `.netrc`: whitespace-separated tokens; `password` and `account` values are
/// secrets; `macdef` bodies (up to a blank line) are skipped.
fn netrc(
    text: &str,
    def: &FileFormat,
    emit: &mut impl FnMut(Range<usize>, Option<String>, Context, SecretKind),
) {
    let mut toks = tokens(text).peekable();
    let (mut host, mut user): (Option<String>, Option<String>) = (None, None);
    while let Some((t, _)) = toks.next() {
        match t {
            "machine" => {
                host = toks.next().map(|(h, _)| h.to_owned());
                user = None;
            }
            "default" => {
                host = None;
                user = None;
            }
            "login" => user = toks.next().map(|(u, _)| u.to_owned()),
            "macdef" => {
                // Skip the macro body: everything up to the next blank line.
                let Some((_, name_span)) = toks.next() else {
                    break;
                };
                let body_end = text[name_span.end..]
                    .find("\n\n")
                    .map_or(text.len(), |i| name_span.end + i);
                while toks.peek().is_some_and(|(_, s)| s.start < body_end) {
                    toks.next();
                }
            }
            field if def.secret_fields.iter().any(|f| f == field) => {
                if let Some((_, span)) = toks.next() {
                    let ctx = Context {
                        host: host.clone(),
                        user: user.clone(),
                        ..Context::default()
                    };
                    emit(span, None, ctx, SecretKind::Password);
                }
            }
            _ => {}
        }
    }
}

fn tokens(text: &str) -> impl Iterator<Item = (&str, Range<usize>)> {
    let mut pos = 0;
    std::iter::from_fn(move || {
        let rest = &text[pos..];
        let start = pos + rest.find(|c: char| !c.is_whitespace())?;
        let len = text[start..]
            .find(char::is_whitespace)
            .unwrap_or(text.len() - start);
        pos = start + len;
        Some((&text[start..start + len], start..start + len))
    })
}

/// Unencrypted PuTTY key: report the first private-key line.
fn putty(text: &str, emit: &mut impl FnMut(Range<usize>, Option<String>, Context, SecretKind)) {
    let encrypted = text
        .lines()
        .find_map(|l| l.strip_prefix("Encryption:"))
        .is_some_and(|v| v.trim() != "none");
    if encrypted {
        return;
    }
    let Some(i) = text.find("Private-Lines:") else {
        return;
    };
    let after = &text[i..];
    let Some(nl) = after.find('\n') else { return };
    let start = i + nl + 1;
    let end = text[start..].find('\n').map_or(text.len(), |e| start + e);
    let line = text[start..end].trim_end_matches('\r');
    if !line.is_empty() {
        emit(
            start..start + line.len(),
            None,
            Context::default(),
            SecretKind::Key,
        );
    }
}

/// Split shell history into command byte ranges: bash (one per line), zsh
/// extended (`: <ts>:<dur>;cmd`) and fish (`- cmd: ...`). Multi-line zsh
/// commands (trailing `\`) are kept together.
pub fn history_commands(text: &str) -> Vec<Range<usize>> {
    let mut out = Vec::new();
    let mut pos = 0;
    let mut pending: Option<usize> = None; // start of a continued zsh command
    for line in text.split_inclusive('\n') {
        let start = pos;
        pos += line.len();
        let body = line.trim_end_matches(['\n', '\r']);
        let end = start + body.len();
        if let Some(s) = pending {
            if !body.ends_with('\\') {
                out.push(s..end);
                pending = None;
            }
            continue;
        }
        let cmd_start = if let Some(rest) = body.strip_prefix(": ") {
            // zsh extended history: ": 1700000000:0;cmd"
            match rest.find(';') {
                Some(i) if rest[..i].bytes().all(|b| b.is_ascii_digit() || b == b':') => {
                    start + 2 + i + 1
                }
                _ => start,
            }
        } else if let Some(rest) = body.strip_prefix("- cmd: ") {
            start + (body.len() - rest.len())
        } else if body.trim_start().starts_with("when:") || body.trim_start().starts_with("paths:")
        {
            continue; // fish metadata
        } else {
            start
        };
        if cmd_start >= end {
            continue;
        }
        if body.ends_with('\\') {
            pending = Some(cmd_start);
        } else {
            out.push(cmd_start..end);
        }
    }
    if let Some(s) = pending {
        out.push(s..text.len());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(id: &str, text: &str) -> Vec<String> {
        let spec = Spec::embedded().unwrap();
        let a = FormatAnalyzer::new(&spec).unwrap();
        let mut out = Vec::new();
        a.analyze(id, text, &mut out);
        out.iter().map(|c| c.secret.expose().to_owned()).collect()
    }

    #[test]
    fn routes_paths_to_formats() {
        let spec = Spec::embedded().unwrap();
        let a = FormatAnalyzer::new(&spec).unwrap();
        assert!(a.formats_for("home/.pgpass").contains(&"fmt.pgpass"));
        assert!(a.formats_for(".pgpass").contains(&"fmt.pgpass"));
        assert!(
            a.formats_for("home/.docker/config.json")
                .contains(&"fmt.docker-config")
        );
        assert!(
            a.formats_for("home/.bash_history")
                .contains(&"fmt.shell-history")
        );
        assert!(a.formats_for("src/main.rs").is_empty());
    }

    #[test]
    fn pgpass() {
        assert_eq!(
            found("fmt.pgpass", "# c\ndb.acme.io:5432:app:app:PgP4ssFile9\n"),
            ["PgP4ssFile9"]
        );
        assert!(found("fmt.pgpass", "#db:5432:app:app:Commented9\n").is_empty());
    }

    #[test]
    fn docker_auth_is_decoded() {
        // base64("ci:D0ckerCfgPw")
        let t = r#"{"auths":{"r.acme.io":{"auth":"Y2k6RDBja2VyQ2ZnUHc="}}}"#;
        let spec = Spec::embedded().unwrap();
        let a = FormatAnalyzer::new(&spec).unwrap();
        let mut out = Vec::new();
        a.analyze("fmt.docker-config", t, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].secret.expose(), "D0ckerCfgPw");
        assert_eq!(&t[out[0].span.clone()], "Y2k6RDBja2VyQ2ZnUHc=");
        assert_eq!(out[0].context.user.as_deref(), Some("ci"));
    }

    #[test]
    fn netrc_fields() {
        let t = "machine api.acme.io login bob password N3trcPw9\nmacdef init\npassword NotThis1\n\ndefault login x password D3fault7z\n";
        assert_eq!(found("fmt.netrc", t), ["N3trcPw9", "D3fault7z"]);
    }

    #[test]
    fn git_config_and_kubeconfig() {
        let g = "[remote \"origin\"]\n\turl = https://bob:G1tCfgPw@git.acme.io/x.git\n[http]\n\textraheader = Authorization: Bearer opaqueTok3nValue\n";
        assert_eq!(found("fmt.git-config", g), ["G1tCfgPw", "opaqueTok3nValue"]);
        let k = "users:\n- name: a\n  user:\n    token: kub3T0kenValue99\n    password: \"K8sPw2026\"\n";
        assert_eq!(
            found("fmt.kubeconfig", k),
            ["kub3T0kenValue99", "K8sPw2026"]
        );
    }

    #[test]
    fn putty_unencrypted_only() {
        let k = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: x\nPublic-Lines: 1\nAAAApub\nPrivate-Lines: 1\nAAAAprivKeyLine\nPrivate-MAC: ab\n";
        assert_eq!(found("fmt.putty-ppk", k), ["AAAAprivKeyLine"]);
        assert!(
            found(
                "fmt.putty-ppk",
                &k.replace("Encryption: none", "Encryption: aes256-cbc")
            )
            .is_empty()
        );
    }

    #[test]
    fn secret_keys_formats() {
        let aws = "[default]\naws_access_key_id = AKIDNOTREAL\naws_secret_access_key = wJalrXUtnF3MI/K7MDENG\n";
        assert_eq!(found("fmt.aws-files", aws), ["wJalrXUtnF3MI/K7MDENG"]);
        let cnf = "[client]\nuser=root\npassword=\"MyCnfPw9\"\n; password=old\n";
        assert_eq!(found("fmt.my-cnf", cnf), ["MyCnfPw9"]);
    }

    #[test]
    fn history_split() {
        let t = "ls\n: 1700000000:0;sshpass -p X ssh h\n- cmd: mysql -pY\n  when: 1700000000\nmulti \\\n  line\n";
        let cmds: Vec<&str> = history_commands(t).into_iter().map(|r| &t[r]).collect();
        assert_eq!(
            cmds,
            ["ls", "sshpass -p X ssh h", "mysql -pY", "multi \\\n  line"]
        );
    }

    #[test]
    fn no_panics_on_odd_input() {
        let spec = Spec::embedded().unwrap();
        let a = FormatAnalyzer::new(&spec).unwrap();
        for f in &spec.file_formats {
            for t in [
                "",
                "\n",
                "ä",
                "machine",
                "macdef",
                "Private-Lines:",
                "password",
                ": 1;",
                "- cmd: ",
            ] {
                a.analyze(&f.id, t, &mut Vec::new());
                history_commands(t);
            }
        }
    }
}
