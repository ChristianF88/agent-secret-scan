//! `--preset agent-home`: scan only the agent-harness locations of a
//! developer machine.
//!
//! Locations come from the catalogue:
//! - every `p2` (developer machine) path rule glob, with `{EDITOR}` and
//!   `{a,b}` expanded;
//! - home-level credential files from `file_formats` whose glob is a fixed
//!   path under any directory (`**/.pgpass` → `~/.pgpass`); globs with further
//!   wildcards (`**/*.conf`) are not used, they would cover the whole home;
//! - `home_relocations`: `~/.claude` is also resolved under
//!   `$CLAUDE_CONFIG_DIR` when set, `%APPDATA%` under `$APPDATA`, `$TMPDIR`
//!   under `$TMPDIR` or its default; `scan: true` variables add their whole
//!   file or directory.
//!
//! Each glob is split into a literal base directory and a pattern. Only bases
//! that exist are walked, no deeper than the pattern needs, and only files
//! matching a pattern are scanned. Report paths under the home directory are
//! written `~/…` so the router's home-anchored path rules apply.

use std::path::{Path, PathBuf};

use agentleaks_core::ScanOptions;
use agentleaks_extractors::router::expand_glob;
use agentleaks_source_local::{self as local, LocalFile};
use agentleaks_spec::{Priority, Spec};
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

/// Files the preset selects, plus the walk errors met on the way.
#[derive(Debug)]
pub struct PresetFiles {
    pub files: Vec<LocalFile>,
    pub errors: Vec<String>,
    /// Existing base directories or files that were walked.
    pub bases: Vec<PathBuf>,
}

/// One resolved location: a literal absolute base and the glob rest.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    base: PathBuf,
    /// Remaining pattern below `base` (`/`-separated, may be empty).
    rest: String,
}

/// Resolve and walk the agent-home locations.
///
/// `env` looks up environment variables; pass `|_| None` to ignore the
/// process environment (as `--home` does, so a scan of another home directory
/// is not redirected by the operator's own variables).
///
/// `system` also includes machine-wide locations outside `home` (`/etc/…`,
/// `/tmp/claude-*`, `/Library/…`). Turn it off when `home` is not this
/// machine's home (another user's home, a mounted image).
pub fn agent_home(
    spec: &Spec,
    home: &Path,
    env: &dyn Fn(&str) -> Option<String>,
    system: bool,
    opts: &ScanOptions,
) -> anyhow::Result<PresetFiles> {
    let mut targets = targets(spec, home, env);
    if !system {
        targets.retain(|t| t.base.starts_with(home));
    }

    // Absolute patterns for filtering walked files.
    let mut b = GlobSetBuilder::new();
    let mut whole: Vec<PathBuf> = Vec::new(); // scanned in full
    for t in &targets {
        if t.rest.is_empty() || t.rest == "**" {
            whole.push(t.base.clone());
            continue;
        }
        let pat = format!("{}/{}", globset::escape(&t.base.to_string_lossy()), t.rest);
        b.add(GlobBuilder::new(&pat).literal_separator(true).build()?);
    }
    let set: GlobSet = b.build()?;

    // Walk existing bases, each no deeper than its patterns need; drop bases
    // nested inside another base with unlimited depth.
    let mut roots: Vec<(PathBuf, Option<usize>)> = Vec::new();
    for t in &targets {
        if !t.base.exists() {
            continue;
        }
        let depth = depth_of(&t.rest);
        match roots.iter_mut().find(|(r, _)| *r == t.base) {
            Some((_, d)) => *d = max_depth(*d, depth),
            None => roots.push((t.base.clone(), depth)),
        }
    }
    let unlimited: Vec<PathBuf> = roots
        .iter()
        .filter(|(_, d)| d.is_none())
        .map(|(r, _)| r.clone())
        .collect();
    roots.retain(|(r, _)| !unlimited.iter().any(|u| u != r && r.starts_with(u)));
    roots.sort();

    let (walked, errors) = local::walk_limited(&roots, opts);
    let mut files: Vec<LocalFile> = walked
        .into_iter()
        .filter(|f| set.is_match(&f.path) || whole.iter().any(|w| f.path.starts_with(w)))
        .map(|f| LocalFile {
            display: display(home, &f.path),
            path: f.path,
        })
        .collect();
    files.sort_by(|a, b| a.display.cmp(&b.display));
    files.dedup_by(|a, b| a.path == b.path);
    Ok(PresetFiles {
        files,
        errors,
        bases: roots.into_iter().map(|(r, _)| r).collect(),
    })
}

/// All absolute targets from the catalogue.
fn targets(spec: &Spec, home: &Path, env: &dyn Fn(&str) -> Option<String>) -> Vec<Target> {
    let mut globs: Vec<String> = Vec::new();
    for rule in spec
        .path_rules
        .iter()
        .filter(|r| r.priority == Priority::P2)
    {
        for g in &rule.globs {
            globs.extend(expand_glob(g, &rule.editors));
        }
    }
    for ff in &spec.file_formats {
        for g in &ff.paths {
            if let Some(rest) = g.strip_prefix("**/")
                && !rest.contains(['*', '?', '[', '{'])
            {
                globs.push(format!("~/{rest}"));
            }
        }
    }

    let mut out: Vec<Target> = Vec::new();
    for g in globs {
        for abs in resolve(&g, home, spec, env) {
            let t = split(&abs);
            if !out.contains(&t) {
                out.push(t);
            }
        }
    }
    for r in spec.home_relocations.iter().filter(|r| r.scan) {
        if let Some(v) = env(&r.env).filter(|v| !v.is_empty()) {
            let t = Target {
                base: PathBuf::from(v),
                rest: String::new(),
            };
            if !out.contains(&t) {
                out.push(t);
            }
        }
    }
    out
}

/// Resolve one expanded glob to absolute patterns: the default location and,
/// for each relocation that covers it, the relocated one.
fn resolve(g: &str, home: &Path, spec: &Spec, env: &dyn Fn(&str) -> Option<String>) -> Vec<String> {
    let mut out = Vec::new();
    let home_s = home.to_string_lossy();
    if let Some(rest) = g.strip_prefix("~/") {
        out.push(format!("{}/{rest}", home_s.trim_end_matches('/')));
    } else if g.starts_with('/') {
        out.push(g.to_owned());
    } else if cfg!(windows) && g.as_bytes().get(1) == Some(&b':') {
        out.push(g.to_owned()); // drive paths only exist on Windows
    } // `%VAR%` and `$TMPDIR` forms resolve only through relocations below.

    for r in &spec.home_relocations {
        let Some(prefix) = r.replaces.as_deref() else {
            continue;
        };
        let Some(rest) = strip_component_prefix(g, prefix) else {
            continue;
        };
        let value = env(&r.env)
            .filter(|v| !v.is_empty())
            .or_else(|| r.default.clone());
        if let Some(v) = value {
            let v = v.trim_end_matches(['/', '\\']);
            let p = if rest.is_empty() {
                v.to_owned()
            } else {
                format!("{v}/{rest}")
            };
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    out
}

/// `~/.claude/x` with prefix `~/.claude` → `x`; `~/.claudex` → None.
fn strip_component_prefix<'a>(g: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = g.strip_prefix(prefix)?;
    if rest.is_empty() {
        Some(rest)
    } else {
        rest.strip_prefix('/')
    }
}

/// Split an absolute pattern at the first component with a glob character.
fn split(abs: &str) -> Target {
    let abs = abs.trim_end_matches('/');
    let comps: Vec<&str> = abs.split('/').collect();
    let first_glob = comps.iter().position(|c| c.contains(['*', '?', '[', '{']));
    match first_glob {
        None => Target {
            base: PathBuf::from(abs),
            rest: String::new(),
        },
        Some(i) => {
            let base = comps[..i].join("/");
            Target {
                base: PathBuf::from(if base.is_empty() {
                    "/".to_owned()
                } else {
                    base
                }),
                rest: comps[i..].join("/"),
            }
        }
    }
}

/// Walk depth a pattern needs below its base (`None` = unlimited).
fn depth_of(rest: &str) -> Option<usize> {
    if rest.is_empty() {
        return None; // a literal path: file or whole directory
    }
    if rest.contains("**") {
        None
    } else {
        Some(rest.split('/').count())
    }
}

fn max_depth(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        _ => None,
    }
}

/// `~/…` under the home directory, else the absolute path.
fn display(home: &Path, p: &Path) -> String {
    match p.strip_prefix(home) {
        Ok(rel) => {
            let mut s = String::from("~");
            for c in rel.components() {
                s.push('/');
                s.push_str(&c.as_os_str().to_string_lossy());
            }
            s
        }
        Err(_) => p.to_string_lossy().into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_literal_base() {
        assert_eq!(
            split("/h/.claude/projects/**/*.jsonl"),
            Target {
                base: "/h/.claude/projects".into(),
                rest: "**/*.jsonl".into()
            }
        );
        assert_eq!(
            split("/h/.pgpass"),
            Target {
                base: "/h/.pgpass".into(),
                rest: String::new()
            }
        );
        assert_eq!(depth_of("roo-code-settings*.json"), Some(1));
        assert_eq!(depth_of("*/tasks/*.json"), Some(3));
        assert_eq!(depth_of("**/x"), None);
    }

    #[test]
    fn relocations_resolve() {
        let spec = Spec::embedded().unwrap();
        let env = |k: &str| match k {
            "CLAUDE_CONFIG_DIR" => Some("/alt/claude".to_owned()),
            "APPDATA" => Some("C:/Users/u/AppData/Roaming".to_owned()),
            _ => None,
        };
        let r = resolve("~/.claude/settings.json", Path::new("/h"), &spec, &env);
        assert_eq!(r, ["/h/.claude/settings.json", "/alt/claude/settings.json"]);
        let r = resolve("%APPDATA%/Claude/x.json", Path::new("/h"), &spec, &env);
        assert_eq!(r, ["C:/Users/u/AppData/Roaming/Claude/x.json"]);
        let none = |_: &str| None;
        assert!(resolve("%APPDATA%/Claude/x.json", Path::new("/h"), &spec, &none).is_empty());
        let r = resolve("$TMPDIR/gemini/ide/*.json", Path::new("/h"), &spec, &none);
        assert_eq!(r, ["/tmp/gemini/ide/*.json"]); // default
        assert_eq!(strip_component_prefix("~/.claudex/a", "~/.claude"), None);
    }

    #[test]
    fn displays_home_relative() {
        assert_eq!(
            display(Path::new("/h"), Path::new("/h/.claude/x.json")),
            "~/.claude/x.json"
        );
        assert_eq!(display(Path::new("/h"), Path::new("/etc/x")), "/etc/x");
    }
}

#[cfg(test)]
mod walk_tests {
    use super::*;

    #[test]
    fn relocated_dir_is_scanned_and_system_paths_are_optional() {
        let root = std::env::temp_dir().join(format!("agentleaks-preset-{}", std::process::id()));
        let home = root.join("home");
        let codex = root.join("elsewhere/codex");
        std::fs::create_dir_all(home.join(".codex/rules")).unwrap();
        std::fs::create_dir_all(codex.join("rules")).unwrap();
        std::fs::write(home.join(".codex/rules/a.rules"), "x\n").unwrap();
        std::fs::write(codex.join("rules/b.rules"), "x\n").unwrap();
        std::fs::write(home.join("unrelated.txt"), "x\n").unwrap();

        let spec = Spec::embedded().unwrap();
        let codex_s = codex.to_string_lossy().into_owned();
        let env = move |k: &str| (k == "CODEX_HOME").then(|| codex_s.clone());
        let found = agent_home(&spec, &home, &env, false, &ScanOptions::default()).unwrap();
        let names: Vec<&str> = found.files.iter().map(|f| f.display.as_str()).collect();
        assert!(names.contains(&"~/.codex/rules/a.rules"), "{names:?}");
        // CODEX_HOME lies outside home: dropped when system locations are off.
        assert!(!names.iter().any(|n| n.ends_with("b.rules")), "{names:?}");
        assert!(!names.iter().any(|n| n.ends_with("unrelated.txt")));

        let found = agent_home(&spec, &home, &env, true, &ScanOptions::default()).unwrap();
        assert!(
            found
                .files
                .iter()
                .any(|f| f.path.ends_with("rules/b.rules"))
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
