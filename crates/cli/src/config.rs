//! Project config `.agentleaks.toml` (D19).
//!
//! ```toml
//! [allowlist]
//! description = "Invented test credentials"      # optional
//! paths = ['''^fixtures/''']                       # Rust regex, see below
//! rules = ["config.yaml-key"]                      # rule ids
//! fingerprints = ["blake3-keyed:0123…"]            # from earlier reports
//! ```
//!
//! - **Discovery:** for each scan root, `.agentleaks.toml` in the root (the
//!   parent directory for a file root) and in the root of the enclosing git
//!   work tree (the nearest ancestor with a `.git` directory or file). Both
//!   apply when both exist; a file found twice is loaded once. A discovered
//!   config applies only to findings from the roots it was discovered for.
//! - `--config FILE` replaces discovery and applies to every finding.
//!   `--no-config` disables configs.
//! - **`paths`** are unanchored Rust regexes (anchor with `^` yourself),
//!   matched against the finding's path relative to the config file's
//!   directory, `/`-separated. For a finding outside that directory (only
//!   possible with `--config`), they are matched against the report path.
//! - **`fingerprints`** compare with the report's `fingerprint` field. They
//!   are keyed, so they are only stable across runs when the same key is set
//!   in `AGENT_SECRET_SCAN_HMAC_KEY`; with the default
//!   per-run random key they never match.
//! - **Strict:** unknown keys, wrong types and invalid regexes are errors
//!   (exit 2).
//!
//! Allowlisted findings are counted in the stats line and never printed.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use agentleaks_core::Finding;
use anyhow::Context as _;
use regex::Regex;
use serde::Deserialize;

/// File name looked up during discovery.
pub const CONFIG_FILE_NAME: &str = ".agentleaks.toml";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    #[serde(default)]
    allowlist: Option<AllowlistFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowlistFile {
    #[serde(default)]
    #[allow(dead_code)] // documentation for humans
    description: Option<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    rules: Vec<String>,
    #[serde(default)]
    fingerprints: Vec<String>,
}

/// A loaded, validated config.
#[derive(Debug, Clone)]
pub struct Config {
    /// The config file.
    pub path: PathBuf,
    /// Absolute directory that `paths` are relative to.
    pub dir: PathBuf,
    paths: Vec<Regex>,
    rules: HashSet<String>,
    fingerprints: HashSet<String>,
}

impl Config {
    /// Parse a config. `path` is used for errors and to locate `dir`.
    pub fn parse(text: &str, path: &Path) -> anyhow::Result<Config> {
        let file: ConfigFile =
            toml::from_str(text).with_context(|| format!("invalid config {}", path.display()))?;
        let al = file.allowlist.unwrap_or(AllowlistFile {
            description: None,
            paths: Vec::new(),
            rules: Vec::new(),
            fingerprints: Vec::new(),
        });
        let paths = al
            .paths
            .iter()
            .map(|p| {
                Regex::new(p).with_context(|| {
                    format!("invalid regex in {} allowlist.paths: {p:?}", path.display())
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let abs = std::path::absolute(path)
            .with_context(|| format!("cannot resolve {}", path.display()))?;
        let dir = abs.parent().map(Path::to_path_buf).unwrap_or_default();
        Ok(Config {
            path: path.to_path_buf(),
            dir,
            paths,
            rules: al.rules.into_iter().collect(),
            fingerprints: al.fingerprints.into_iter().collect(),
        })
    }

    /// Read and parse a config file.
    pub fn load(path: &Path) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read config {}", path.display()))?;
        Config::parse(&text, path)
    }

    /// Whether the allowlist drops `f`. `abs_path` is the finding's absolute
    /// file path when known.
    pub fn allows(&self, f: &Finding, abs_path: Option<&Path>) -> bool {
        if self.rules.contains(&f.rule_id) || self.fingerprints.contains(&f.fingerprint) {
            return true;
        }
        if self.paths.is_empty() {
            return false;
        }
        let rel = abs_path
            .and_then(|p| p.strip_prefix(&self.dir).ok())
            .map(slash_path);
        let path = match &rel {
            Some(r) => r.as_str(),
            None => f.location.path.as_deref().unwrap_or(""),
        };
        self.paths.iter().any(|re| re.is_match(path))
    }
}

/// `/`-separated form of a relative path.
fn slash_path(p: &Path) -> String {
    let mut s = String::new();
    for (i, c) in p.components().enumerate() {
        if i > 0 {
            s.push('/');
        }
        s.push_str(&c.as_os_str().to_string_lossy());
    }
    s
}

/// The nearest ancestor of `dir` (inclusive) containing `.git`.
pub fn git_work_tree(dir: &Path) -> Option<&Path> {
    dir.ancestors().find(|d| d.join(".git").exists())
}

/// Config files that apply to a scan root, in discovery order (root first,
/// then the git work-tree root), without duplicates.
pub fn discover(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let abs =
        std::path::absolute(root).with_context(|| format!("cannot resolve {}", root.display()))?;
    let dir = if abs.is_dir() {
        abs.as_path()
    } else {
        abs.parent().unwrap_or(&abs)
    };
    let mut out = Vec::new();
    let candidates = [Some(dir), git_work_tree(dir)];
    for d in candidates.into_iter().flatten() {
        let p = d.join(CONFIG_FILE_NAME);
        if p.is_file() && !out.contains(&p) {
            out.push(p);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentleaks_core::{Category, Confidence, Context, Location, Secret, SecretKind, Severity};

    fn finding(path: &str, rule: &str, fp: &str) -> Finding {
        Finding {
            rule_id: rule.into(),
            category: Category::ConfigKey,
            kind: SecretKind::Credential,
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            secret: Secret::new("Mof4-tralo-Wesk"),
            fingerprint: fp.into(),
            location: Location {
                source: "local",
                path: Some(path.into()),
                line: 1,
                column: 1,
                byte_span: [0, 15],
                git: None,
            },
            context: Context::default(),
            default_credential: false,
        }
    }

    fn cfg(text: &str) -> anyhow::Result<Config> {
        Config::parse(text, Path::new("/proj/.agentleaks.toml"))
    }

    #[test]
    fn strict_parsing() {
        assert!(cfg("").is_ok());
        assert!(cfg("[allowlist]\n").is_ok());
        assert!(cfg("title = \"x\"\n").is_err(), "unknown top-level key");
        assert!(
            cfg("[allowlist]\npath = []\n").is_err(),
            "unknown allowlist key"
        );
        assert!(cfg("[allowlist]\npaths = '^x'\n").is_err(), "wrong type");
        let e = cfg("[allowlist]\npaths = ['(unclosed']\n").unwrap_err();
        assert!(format!("{e:#}").contains("invalid regex"), "{e:#}");
        assert!(
            cfg("[allowlist]\npaths = ['(?=x)']\n").is_err(),
            "no lookaround"
        );
    }

    #[test]
    fn allowlists_by_path_rule_and_fingerprint() {
        let c = cfg(r#"
            [allowlist]
            description = "test data"
            paths = ['^fixtures/', '\.example$']
            rules = ["config.yaml-key"]
            fingerprints = ["blake3-keyed:aa"]
        "#)
        .unwrap();
        let abs = |p: &str| PathBuf::from("/proj").join(p);
        let f = finding("fixtures/a.env", "x", "fp");
        assert!(c.allows(&f, Some(&abs("fixtures/a.env"))));
        assert!(!c.allows(&f, Some(&abs("src/fixtures/a.env"))), "anchored");
        assert!(c.allows(&f, Some(&abs("src/a.example"))));
        assert!(c.allows(
            &finding("src/x", "config.yaml-key", "fp"),
            Some(&abs("src/x"))
        ));
        assert!(c.allows(
            &finding("src/x", "r", "blake3-keyed:aa"),
            Some(&abs("src/x"))
        ));
        assert!(!c.allows(
            &finding("src/x", "r", "blake3-keyed:bb"),
            Some(&abs("src/x"))
        ));
        // Outside the config directory: the report path is used.
        assert!(c.allows(&f, Some(Path::new("/elsewhere/q"))));
    }
}
