//! Data that flows between pipeline stages.
//!
//! ```text
//! Source ─► Item ─► Extractor ─► Routed ─► Analyzer ─► Candidate ─► (filters) ─► Finding ─► Reporter
//! ```

use std::borrow::Cow;
use std::ops::Range;

use serde::Serialize;

use crate::{Category, Confidence, Secret, Severity};

/// How a routed string should be analyzed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    /// Free text: regex rules (natural-language rules only where in scope).
    Text,
    /// One shell command line: shell analyzer + regex rules.
    Command,
    /// A command given as argv tokens joined with spaces.
    CommandArgv,
    /// `name` = an environment variable, `text` = its value.
    Env,
    /// `name` = an HTTP header, `text` = its value.
    Headers,
    /// A URL: query parameters and userinfo.
    Url,
    /// SQL statements.
    Sql,
    /// `name` = a config key, `text` = its value.
    ConfigKey,
}

/// Where a routed string sits inside its item, to map findings to lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextOrigin {
    /// The text is a byte-identical slice of the item starting here, so
    /// offsets inside the text map exactly.
    Raw { start: usize },
    /// The text was decoded (JSON string escapes, base64, argv joining) from
    /// this byte range; findings map to its start.
    Decoded { start: usize, end: usize },
}

impl TextOrigin {
    /// Byte range in the item of a span inside the routed text.
    pub fn item_span(self, span: &Range<usize>) -> Range<usize> {
        match self {
            TextOrigin::Raw { start } => start + span.start..start + span.end,
            TextOrigin::Decoded { start, end } => start..end,
        }
    }
}

/// A string pulled out of an item, with the route that says how to analyze it.
#[derive(Debug, Clone)]
pub struct Routed<'a> {
    pub text: Cow<'a, str>,
    pub route: Route,
    pub origin: TextOrigin,
    /// Key, env var or header name for `Env`, `ConfigKey` and `Headers`.
    pub name: Option<Cow<'a, str>>,
    /// Regex-rule scope this text belongs to (`transcript.user_message`,
    /// `memory_file`, ...). `None` = no scope; scoped rules don't run.
    pub scope: Option<&'a str>,
    /// Agent structure that produced this text.
    pub structure: Option<&'a str>,
}

impl<'a> Routed<'a> {
    /// The whole item as one raw text string.
    pub fn raw_text(text: &'a str, route: Route) -> Self {
        Routed {
            text: Cow::Borrowed(text),
            route,
            origin: TextOrigin::Raw { start: 0 },
            name: None,
            scope: None,
            structure: None,
        }
    }
}

/// What a secret is. `DefaultCredential` replaces the kind for well-known
/// default passwords (D15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Password,
    Token,
    Key,
    Passphrase,
    Hash,
    /// A credential whose exact kind is unknown (generic config keys, DSNs).
    Credential,
    DefaultCredential,
}

/// A potential secret found by an analyzer, relative to its routed text.
#[derive(Debug, Clone)]
pub struct Candidate<'s> {
    /// Rule or structure id (borrowed from the spec).
    pub rule_id: &'s str,
    pub category: Category,
    pub kind: SecretKind,
    pub severity: Severity,
    pub confidence: Confidence,
    pub secret: Secret,
    /// Byte span of the secret in the routed text.
    pub span: Range<usize>,
    pub context: Context,
}

/// Optional facts that feed risk scoring and reports.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Context {
    pub tool: Option<String>,
    pub host: Option<String>,
    pub user: Option<String>,
    pub harness: Option<String>,
    pub structure: Option<String>,
}

/// Where a finding is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Location {
    /// `local` or `git`, later `gitlab`.
    pub source: &'static str,
    /// Path relative to the scan root (`/`-separated).
    pub path: Option<String>,
    /// 1-based.
    pub line: usize,
    /// 1-based, in characters.
    pub column: usize,
    pub byte_span: [usize; 2],
    /// Git provenance; only for findings from git history (or local findings
    /// whose secret is also committed at the same path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git: Option<Box<GitLocation>>,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// Where a finding sits in git history. Ids are full hex object ids.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct GitLocation {
    /// The remote URL the repository was cloned from (credentials redacted);
    /// absent for local repositories.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// The blob that holds the secret.
    pub blob: String,
    /// The first commit (oldest by committer time, reachable ones first)
    /// whose tree showed the blob; empty when no commit references it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub commits: Vec<String>,
    /// Committer time of `commits[0]`, ISO 8601.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    /// Refs (and `HEAD`s) whose history contains `commits[0]`, sorted, at
    /// most 8; `refs_omitted` counts the rest.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub refs: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub refs_omitted: usize,
    /// Every distinct path the blob had, when more than one.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// No ref reaches the blob (rewritten, reset or dropped history, D38).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub unreachable: bool,
}

/// A reported secret.
#[derive(Debug, Clone)]
pub struct Finding {
    pub rule_id: String,
    pub category: Category,
    pub kind: SecretKind,
    pub severity: Severity,
    pub confidence: Confidence,
    pub secret: Secret,
    /// `blake3-keyed:<hex>`; see the report crate.
    pub fingerprint: String,
    pub location: Location,
    pub context: Context,
    pub default_credential: bool,
}

/// Scan-wide options.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Files larger than this are skipped (bytes).
    pub max_file_size: u64,
    /// SQLite agent stores larger than this are skipped (bytes).
    pub max_db_size: u64,
    pub respect_gitignore: bool,
    pub follow_symlinks: bool,
    /// Worker threads; 0 = number of CPUs.
    pub threads: usize,
    /// Scan only agent-harness files (files a catalogue path rule or agent
    /// structure claims, except the generic `log` rule).
    pub agent_files_only: bool,
    /// Local scans: also scan the history of `.git` directories met by the
    /// walk (`--no-git-history` turns it off).
    pub git_history: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            max_file_size: 64 * 1024 * 1024,
            max_db_size: 1024 * 1024 * 1024,
            respect_gitignore: false, // D10
            follow_symlinks: false,
            threads: 0,
            agent_files_only: false,
            git_history: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_maps_spans() {
        assert_eq!(TextOrigin::Raw { start: 10 }.item_span(&(2..5)), 12..15);
        assert_eq!(
            TextOrigin::Decoded { start: 10, end: 40 }.item_span(&(2..5)),
            10..40
        );
    }
}
