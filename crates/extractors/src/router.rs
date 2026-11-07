//! Path router: matches a report path against `path_rules` globs and
//! `agent_structures.applies_to`, and decides how the file is parsed.
//!
//! Report paths are relative and `/`-separated, so globs are normalised:
//!
//! - `~/X` (home-anchored) is treated as `**/X` until `--preset agent-home`
//!   resolves the home directory. Scanning a copied home dir then works.
//! - `{EDITOR}` expands to the rule's `editors` (or the default
//!   VS Code-family list); `{a,b}` groups are expanded here, not by globset.
//! - Alternatives with `%APPDATA%`, `%LOCALAPPDATA%` or `$TMPDIR`, and
//!   absolute-only globs (`/etc/...`, `C:/...`), cannot match a relative
//!   path; they are skipped and listed in [`Router::skipped_globs`].
//! - A trailing `/` (a directory) matches everything below it.

use agentleaks_core::Severity;
use agentleaks_spec::{AgentStructure, Parser, PathKind, PathRule, Spec};
use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};

/// Used for `{EDITOR}` when a rule lists no `editors`.
const DEFAULT_EDITORS: &[&str] = &[
    "Code",
    "Code - Insiders",
    "VSCodium",
    "Cursor",
    "Windsurf",
    "Devin",
    "Trae",
    "Kiro",
    "Void",
];

/// Upper bound on brace expansion per glob (defensive; the catalogue needs ~81).
const MAX_EXPANSION: usize = 1024;

/// How one file is handled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePlan<'s> {
    /// Resolved parser (`auto` is resolved by extension when possible).
    pub parser: Parser,
    pub kind: Option<PathKind>,
    pub harness: Option<&'s str>,
    pub severity: Option<Severity>,
    /// Indices into [`Router::structures`], in catalogue order.
    pub structures: Vec<usize>,
    /// Analyzer names from `use` that are not agent structures
    /// (`config_key`, `regex_rules`, `shell_command`, ...).
    pub analyzers: Vec<&'s str>,
}

impl FilePlan<'_> {
    pub fn uses_analyzer(&self, name: &str) -> bool {
        self.analyzers.contains(&name)
    }
}

#[derive(Debug)]
pub struct Router<'s> {
    rules: Vec<&'s PathRule>,
    rule_set: GlobSet,
    /// glob index -> rule index
    rule_of: Vec<usize>,
    structures: &'s [AgentStructure],
    applies_set: GlobSet,
    /// glob index -> structure index
    structure_of: Vec<usize>,
    skipped: Vec<String>,
}

impl<'s> Router<'s> {
    pub fn new(spec: &'s Spec) -> Result<Self, String> {
        let mut skipped = Vec::new();
        let mut rb = GlobSetBuilder::new();
        let mut rule_of = Vec::new();
        let rules: Vec<&PathRule> = spec.path_rules.iter().collect();
        for (ri, rule) in rules.iter().enumerate() {
            for g in &rule.globs {
                for norm in normalize(g, &rule.editors, &mut skipped) {
                    rb.add(glob(&norm)?);
                    rule_of.push(ri);
                }
            }
        }
        let mut sb = GlobSetBuilder::new();
        let mut structure_of = Vec::new();
        for (si, s) in spec.agent_structures.iter().enumerate() {
            for g in &s.applies_to {
                for norm in normalize(g, &[], &mut skipped) {
                    sb.add(glob(&norm)?);
                    structure_of.push(si);
                }
            }
        }
        Ok(Router {
            rules,
            rule_set: rb.build().map_err(|e| e.to_string())?,
            rule_of,
            structures: &spec.agent_structures,
            applies_set: sb.build().map_err(|e| e.to_string())?,
            structure_of,
            skipped,
        })
    }

    /// Globs that can never match a relative report path (see module docs).
    pub fn skipped_globs(&self) -> &[String] {
        &self.skipped
    }

    pub fn structures(&self) -> &'s [AgentStructure] {
        self.structures
    }

    /// The plan for a report path, or `None` when no rule applies.
    pub fn plan(&self, path: &str) -> Option<FilePlan<'s>> {
        let mut rule_hits: Vec<usize> = self
            .rule_set
            .matches(path)
            .into_iter()
            .map(|g| self.rule_of[g])
            .collect();
        rule_hits.sort_unstable();
        rule_hits.dedup();
        let mut struct_hits: Vec<usize> = self
            .applies_set
            .matches(path)
            .into_iter()
            .map(|g| self.structure_of[g])
            .collect();
        if rule_hits.is_empty() && struct_hits.is_empty() {
            return None;
        }

        let by_ext = parser_by_extension(path);
        let mut plan = FilePlan {
            parser: Parser::Auto,
            kind: None,
            harness: None,
            severity: None,
            structures: Vec::new(),
            analyzers: Vec::new(),
        };
        // The first rule whose parser fits the extension decides the parser
        // and metadata; otherwise the first rule.
        // A markdown rule (memory, skills, rules dirs) covers whole
        // directories; files in them with another format keep that format,
        // and code files are plain text (no natural-language scope: scripts
        // in `.claude/skills/x/scripts/` are not instructions).
        let resolved = |r: &PathRule| match (r.parser, by_ext) {
            (Parser::Auto, e) => e.unwrap_or(Parser::Auto),
            (Parser::Md, Some(e)) if e != Parser::Md => e,
            (Parser::Md, None) if is_code_file(path) => Parser::Text,
            (p, _) => p,
        };
        let lead = rule_hits
            .iter()
            .copied()
            .find(|&ri| by_ext.is_none_or(|e| same_family(resolved(self.rules[ri]), e)))
            .or_else(|| rule_hits.first().copied());
        if let Some(ri) = lead {
            let r = self.rules[ri];
            plan.parser = resolved(r);
            plan.kind = Some(r.kind);
            plan.harness = r.harness.as_slice().first().map(String::as_str);
            plan.severity = r.severity;
        }
        for &ri in &rule_hits {
            for u in &self.rules[ri].uses {
                if let Some(si) = self.structures.iter().position(|s| &s.id == u) {
                    struct_hits.push(si);
                } else if !plan.analyzers.contains(&u.as_str()) {
                    plan.analyzers.push(u.as_str());
                }
            }
        }
        struct_hits.sort_unstable();
        struct_hits.dedup();
        plan.structures = struct_hits;
        if lead.is_none() {
            // Only `applies_to` matched: derive the parser from the structure.
            plan.parser = by_ext.unwrap_or_else(|| {
                plan.structures.first().map_or(Parser::Auto, |&si| {
                    parser_of_structure(&self.structures[si])
                })
            });
        }
        Some(plan)
    }
}

fn glob(pattern: &str) -> Result<Glob, String> {
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .backslash_escape(true)
        .build()
        .map_err(|e| format!("path glob {pattern:?}: {e}"))
}

/// Normalise one catalogue glob into zero or more globset patterns.
pub fn normalize(glob: &str, editors: &[String], skipped: &mut Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for alt in expand_glob(glob, editors) {
        let unresolvable = alt.contains('%') || alt.contains("$TMPDIR");
        let alt = if let Some(rest) = alt.strip_prefix("~/") {
            format!("**/{rest}")
        } else if alt.starts_with('/') || alt.as_bytes().get(1) == Some(&b':') {
            skipped.push(alt);
            continue;
        } else {
            alt
        };
        if unresolvable {
            skipped.push(alt);
            continue;
        }
        let alt = if alt.ends_with('/') {
            format!("{alt}**")
        } else {
            alt
        };
        if !out.contains(&alt) {
            out.push(alt);
        }
    }
    out
}

/// Substitute `{EDITOR}` (the rule's `editors`, or the default list) and
/// expand every `{a,b}` group. Home, `%VAR%` and `$TMPDIR` prefixes are left
/// as written; callers resolve them.
pub fn expand_glob(glob: &str, editors: &[String]) -> Vec<String> {
    let editor_list: Vec<&str> = if editors.is_empty() {
        DEFAULT_EDITORS.to_vec()
    } else {
        editors.iter().map(String::as_str).collect()
    };
    let g = glob.replace("{EDITOR}", &format!("{{{}}}", editor_list.join(",")));
    expand_braces(&g)
}

/// Expand every (non-nested) `{a,b}` group.
fn expand_braces(g: &str) -> Vec<String> {
    let mut acc = vec![String::new()];
    let mut rest = g;
    while let Some(open) = rest.find('{') {
        let Some(close) = rest[open..].find('}').map(|c| open + c) else {
            break;
        };
        for a in &mut acc {
            a.push_str(&rest[..open]);
        }
        let alts: Vec<&str> = rest[open + 1..close].split(',').collect();
        let mut next = Vec::with_capacity(acc.len() * alts.len());
        for a in &acc {
            for alt in &alts {
                if next.len() < MAX_EXPANSION {
                    next.push(format!("{a}{alt}"));
                }
            }
        }
        acc = next;
        rest = &rest[close + 1..];
    }
    for a in &mut acc {
        a.push_str(rest);
    }
    acc
}

fn parser_by_extension(path: &str) -> Option<Parser> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase())?;
    Some(match ext.as_str() {
        "json" | "jsonc" | "json5" => Parser::Jsonc,
        "jsonl" | "ndjson" => Parser::Jsonl,
        "md" | "mdc" | "markdown" => Parser::Md,
        "toml" => Parser::Toml,
        "yaml" | "yml" => Parser::Yaml,
        "rules" => Parser::Starlark,
        "db" | "sqlite" | "sqlite3" | "vscdb" => Parser::Sqlite,
        _ => return None,
    })
}

/// Source code and markup that is not prose, by extension.
fn is_code_file(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return false;
    };
    !stem.is_empty()
        && matches!(
            ext.to_ascii_lowercase().as_str(),
            "js" | "mjs"
                | "cjs"
                | "jsx"
                | "ts"
                | "mts"
                | "cts"
                | "tsx"
                | "py"
                | "rb"
                | "go"
                | "rs"
                | "java"
                | "kt"
                | "kts"
                | "scala"
                | "swift"
                | "c"
                | "h"
                | "cc"
                | "cpp"
                | "hpp"
                | "cs"
                | "php"
                | "lua"
                | "pl"
                | "sh"
                | "bash"
                | "zsh"
                | "fish"
                | "ps1"
                | "psm1"
                | "bat"
                | "cmd"
                | "sql"
                | "html"
                | "htm"
                | "css"
                | "scss"
                | "xml"
                | "vue"
                | "svelte"
                | "dart"
                | "r"
                | "ex"
                | "exs"
                | "erl"
                | "clj"
                | "zig"
        )
}

fn same_family(a: Parser, b: Parser) -> bool {
    let fam = |p| match p {
        Parser::Json | Parser::Jsonc => 1,
        other => other as u8 + 10,
    };
    fam(a) == fam(b)
}

fn parser_of_structure(s: &AgentStructure) -> Parser {
    if !s.extract.is_empty() || s.format.as_deref() == Some("starlark") {
        Parser::Starlark
    } else if s.regex.is_some() {
        Parser::Text
    } else if !s.json_paths.is_empty() || !s.json_roots.is_empty() {
        Parser::Jsonc
    } else {
        Parser::Auto
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_globs() {
        let mut sk = Vec::new();
        assert_eq!(
            normalize("~/.claude/x.json", &[], &mut sk),
            ["**/.claude/x.json"]
        );
        assert!(normalize("%APPDATA%/Claude/**", &[], &mut sk).is_empty());
        assert!(normalize("/etc/codex/*.toml", &[], &mut sk).is_empty());
        assert!(normalize("C:/ProgramData/x.json", &[], &mut sk).is_empty());
        assert_eq!(
            normalize("~/.gemini/history/*/", &[], &mut sk),
            ["**/.gemini/history/*/**"]
        );
        let v = normalize(
            "{~/Library/Application Support,~/.config,%APPDATA%}/{EDITOR}/User/settings.json",
            &["Code".into(), "Cursor".into()],
            &mut sk,
        );
        assert_eq!(
            v,
            [
                "**/Library/Application Support/Code/User/settings.json",
                "**/Library/Application Support/Cursor/User/settings.json",
                "**/.config/Code/User/settings.json",
                "**/.config/Cursor/User/settings.json",
            ]
        );
    }

    #[test]
    fn plans_fixture_paths() {
        let spec = Spec::embedded().unwrap();
        let r = Router::new(&spec).unwrap();
        let ids = |p: &str| {
            let plan = r.plan(p).unwrap();
            let ids: Vec<&str> = plan
                .structures
                .iter()
                .map(|&i| r.structures()[i].id.as_str())
                .collect();
            (plan.parser, ids)
        };
        let (p, s) = ids("repo/.claude/settings.local.json");
        assert_eq!(p, Parser::Json);
        assert!(s.contains(&"agent.claude.permission-rules"));
        let (p, s) = ids("home/.claude/projects/-home-dev-shop/5f.jsonl");
        assert_eq!(p, Parser::Jsonl);
        assert_eq!(s, ["agent.transcript.jsonl"]);
        let (p, _) = ids("repo/.specstory/history/x.md");
        assert_eq!(p, Parser::Md);
        let (p, s) = ids("home/.codex/rules/default.rules");
        assert_eq!(p, Parser::Starlark);
        assert_eq!(s, ["agent.codex.exec-policy-rules"]);
        let (p, _) = ids("repo/memory-bank/techContext.md");
        assert_eq!(p, Parser::Md);
        let (p, s) = ids("x/.config/Code/User/settings.json");
        assert_eq!(p, Parser::Jsonc);
        assert!(s.contains(&"agent.vscode-settings.autoapprove"));
        assert!(r.plan("src/main.rs").is_none());
        assert!(r.plan("negatives/transcript.jsonl").is_none());
    }
}
