//! Loads and validates the detection catalogue `spec/detection-patterns.yaml`.
//!
//! The catalogue is embedded at build time ([`Spec::embedded`]) and can be
//! replaced at runtime ([`Spec::from_path`], CLI `--rules`). Loading fails if
//! the YAML has unknown keys, a regex does not compile or uses syntax the Rust
//! `regex` crate lacks, a regex rule has no `secret` group or no keywords, or
//! ids are duplicated.

pub mod filters;
pub mod model;

use std::collections::HashSet;
use std::path::Path;

pub use filters::{CredentialNames, ValueFilters};
pub use model::*;

/// The catalogue shipped with the binary.
pub const EMBEDDED_YAML: &str = include_str!("../../../spec/detection-patterns.yaml");

/// Name of the capture group that holds the credential.
pub const SECRET_GROUP: &str = "secret";

#[derive(Debug, thiserror::Error)]
pub enum SpecError {
    #[error("cannot read rules file {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid rules YAML: {0}")]
    Yaml(String),
    #[error("invalid rules catalogue:\n  - {}", .0.join("\n  - "))]
    Invalid(Vec<String>),
}

/// A parse error of a user-supplied file, safe to print: a fixed category
/// and nothing from the input. Parser messages echo values (``integer
/// `98765432123` ``, `string "..."`), unknown keys and source snippets, and
/// `--config`/`--rules` may point at a credential file. For unknown fields
/// only the expected-field list (our own schema) is kept.
pub fn error_category(msg: &str) -> String {
    let m = msg.to_ascii_lowercase();
    // Our own regex validation (model.rs): keep the construct name (a fixed
    // word list), never the pattern.
    if let Some(rest) = msg.split("unsupported regex syntax `").nth(1)
        && let Some((construct, _)) = rest.split_once('`')
        && construct
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b' ')
    {
        return format!("unsupported regex syntax `{construct}`");
    }
    let category = if m.contains("regex does not compile") {
        "regex does not compile"
    } else if m.contains("unknown field") {
        // serde: "unknown field `x`, expected one of `a`, `b`". The tail
        // after the last ", expected " is ours; the unknown name is not.
        // Kept only if it is a plain list of backticked identifiers.
        let tail = msg.rfind(", expected ").map(|i| msg[i + 11..].trim_end());
        let names_only = |t: &str| {
            let t = t.strip_prefix("one of ").unwrap_or(t);
            t.split(", ").flat_map(|p| p.split(" or ")).all(|n| {
                n.len() > 2
                    && n.starts_with('`')
                    && n.ends_with('`')
                    && n[1..n.len() - 1]
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            })
        };
        return match tail {
            Some(t) if names_only(t) => format!("unknown field (expected {t})"),
            _ => "unknown field".to_owned(),
        };
    } else if m.contains("invalid type") || m.contains("invalid value") {
        "wrong value type"
    } else if m.contains("missing field") {
        "missing field"
    } else if m.contains("unknown variant") {
        "unknown value"
    } else if m.contains("duplicate") {
        "duplicate key"
    } else if m.contains("invalid length") {
        "wrong number of elements"
    } else {
        "syntax error"
    };
    category.to_owned()
}

#[cfg(test)]
mod error_category_tests {
    use super::error_category;

    #[test]
    fn nothing_from_the_input_survives() {
        for (msg, want) in [
            (
                "invalid type: string \"Pw-9x\", expected a sequence\n1 | a = \"Pw-9x\"",
                "wrong value type",
            ),
            (
                "invalid type: integer `98765432123`, expected a string",
                "wrong value type",
            ),
            (
                "unknown field `Pw-9x`, expected one of `paths`, `rules`",
                "unknown field (expected one of `paths`, `rules`)",
            ),
            ("unknown field `Pw-9x, expected x`", "unknown field"),
            ("key with no value, expected `=`", "syntax error"),
        ] {
            assert_eq!(error_category(msg), want);
            assert!(!error_category(msg).contains("Pw-9x"));
        }
    }
}

/// The validated, compiled catalogue.
#[derive(Debug)]
pub struct Spec {
    pub meta: Meta,
    pub value_filters: ValueFilters,
    pub credential_names: CredentialNames,
    pub shell: ShellSemantics,
    pub cli_tools: Vec<CliTool>,
    pub regex_rules: Vec<RegexRule>,
    pub file_formats: Vec<FileFormat>,
    pub agent_structures: Vec<AgentStructure>,
    pub path_rules: Vec<PathRule>,
    pub home_relocations: Vec<HomeRelocation>,
}

impl Spec {
    /// The catalogue embedded in the binary.
    pub fn embedded() -> Result<Self, SpecError> {
        Self::from_yaml(EMBEDDED_YAML)
    }

    /// A catalogue file given at runtime (`--rules`).
    pub fn from_path(path: &Path) -> Result<Self, SpecError> {
        let text = std::fs::read_to_string(path).map_err(|source| SpecError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Self::from_yaml(&text)
    }

    pub fn from_yaml(yaml: &str) -> Result<Self, SpecError> {
        // Position and category only: `--rules` may point at any file,
        // including one full of credentials.
        let file: SpecFile = serde_saphyr::from_str(yaml).map_err(|e| {
            let at = e.location().map_or(String::new(), |l| {
                format!(" at line {}, column {}", l.line(), l.column())
            });
            SpecError::Yaml(format!(
                "{}{at}",
                error_category(&e.without_snippet().to_string())
            ))
        })?;
        validate(&file)?;
        let compile_err = |what: &str, e: regex::Error| {
            SpecError::Invalid(vec![format!("{what}: cannot build regex set: {e}")])
        };
        Ok(Spec {
            value_filters: ValueFilters::compile(&file.value_filters)
                .map_err(|e| compile_err("value_filters", e))?,
            credential_names: CredentialNames::compile(&file.credential_names)
                .map_err(|e| compile_err("credential_names", e))?,
            meta: file.meta,
            shell: file.shell_semantics,
            cli_tools: file.cli_tools,
            regex_rules: file.regex_rules,
            file_formats: file.file_formats,
            agent_structures: file.agent_structures,
            path_rules: file.path_rules,
            home_relocations: file.home_relocations,
        })
    }

    pub fn regex_rule(&self, id: &str) -> Option<&RegexRule> {
        self.regex_rules.iter().find(|r| r.id == id)
    }
}

/// Cross-field checks that serde cannot express. Collects every problem.
fn validate(f: &SpecFile) -> Result<(), SpecError> {
    let mut errs = Vec::new();

    if f.meta.secret_group != SECRET_GROUP {
        errs.push(format!(
            "meta.secret_group is {:?}; the engine requires {SECRET_GROUP:?}",
            f.meta.secret_group
        ));
    }
    if f.meta.regex_dialect != "rust-regex" {
        errs.push(format!(
            "meta.regex_dialect is {:?}; expected \"rust-regex\"",
            f.meta.regex_dialect
        ));
    }

    let mut seen = HashSet::new();
    for r in &f.regex_rules {
        if !seen.insert(r.id.as_str()) {
            errs.push(format!("regex_rules: duplicate id {}", r.id));
        }
        if !r.regex.has_group(SECRET_GROUP) {
            errs.push(format!(
                "regex_rules.{}: regex has no `{SECRET_GROUP}` group",
                r.id
            ));
        }
        if let Some(alt) = &r.alt_regex
            && !alt.has_group(SECRET_GROUP)
        {
            errs.push(format!(
                "regex_rules.{}: alt_regex has no `{SECRET_GROUP}` group",
                r.id
            ));
        }
        if r.keywords.is_empty() {
            errs.push(format!(
                "regex_rules.{}: no keywords (the prefilter would never run it)",
                r.id
            ));
        }
        if r.keywords.iter().any(|k| k.trim().is_empty()) {
            errs.push(format!(
                "regex_rules.{}: empty keyword (it would match everywhere)",
                r.id
            ));
        }
    }

    for t in &f.cli_tools {
        for (i, a) in t.args.iter().enumerate() {
            let at = format!("cli_tools.{}.args[{i}]", t.tool);
            if let Some(p) = &a.pattern {
                if !p.has_group(SECRET_GROUP) {
                    errs.push(format!("{at}: pattern has no `{SECRET_GROUP}` group"));
                }
            } else if a.flag.is_none() && a.position.is_none() {
                errs.push(format!("{at}: needs a flag, a position or a pattern"));
            }
            if a.form == Some(ArgForm::Positional) && a.position.is_none() {
                errs.push(format!("{at}: form positional without a position"));
            }
        }
    }

    let mut seen = HashSet::new();
    for ff in &f.file_formats {
        if !seen.insert(ff.id.as_str()) {
            errs.push(format!("file_formats: duplicate id {}", ff.id));
        }
    }

    let mut seen = HashSet::new();
    let structure_ids: HashSet<&str> = f.agent_structures.iter().map(|s| s.id.as_str()).collect();
    for s in &f.agent_structures {
        if !seen.insert(s.id.as_str()) {
            errs.push(format!("agent_structures: duplicate id {}", s.id));
        }
        for jp in s.json_paths.iter().chain(&s.per_server) {
            if let Some(u) = &jp.unwrap
                && u.capture_names().flatten().count() != 1
            {
                errs.push(format!(
                    "agent_structures.{}: unwrap for {} must have exactly one named group",
                    s.id, jp.path
                ));
            }
        }
    }

    for r in &f.home_relocations {
        if r.replaces.is_some() == r.scan {
            errs.push(format!(
                "home_relocations.{}: needs exactly one of `replaces` or `scan: true`",
                r.env
            ));
        }
        if r.default.is_some() && r.scan {
            errs.push(format!(
                "home_relocations.{}: `default` needs `replaces`",
                r.env
            ));
        }
    }

    for (i, pr) in f.path_rules.iter().enumerate() {
        if pr.globs.is_empty() && pr.refs.is_empty() {
            errs.push(format!("path_rules[{i}]: neither globs nor refs"));
        }
        for u in &pr.uses {
            if u.starts_with("agent.") && !structure_ids.contains(u.as_str()) {
                errs.push(format!("path_rules[{i}]: unknown agent structure {u}"));
            }
        }
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(SpecError::Invalid(errs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_catalogue_loads() {
        let spec = Spec::embedded().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(spec.regex_rules.len(), 67);
        assert_eq!(spec.cli_tools.len(), 187);
        assert!(spec.regex_rule("cli.sshpass").is_some());
    }

    #[test]
    fn defaults_keep_numeric_scalars_as_text() {
        let spec = Spec::embedded().unwrap();
        assert!(spec.value_filters.is_default("123456"));
        assert!(spec.value_filters.is_default("Password1"));
        assert!(!spec.value_filters.is_default("PASSWORD1"));
    }

    #[test]
    fn credential_names() {
        let n = &Spec::embedded().unwrap().credential_names;
        for yes in [
            "PGPASSWORD",
            "pgpassword",
            "MC_HOST_minio",
            "DB_PASSWORD",
            "clientSecret",
            "x-api-key",
            "Authorization",   // header name, despite the author exclusions
            "DbPassword",      // PascalCase (C#/.NET config keys)
            "SharedAccessKey", // Azure connection-string style
        ] {
            assert!(n.is_credential_name(yes), "{yes}");
        }
        for no in [
            "DB_PASSWORD_FILE",
            "MAX_TOKENS",
            "client_id",
            "PATH",
            "HOME",
            "",
            "PGPAſSWORD", // Unicode case folding must not create matches
            "Co-Authored-By",
            "authority",
        ] {
            assert!(!n.is_credential_name(no), "{no}");
        }
    }

    #[test]
    fn value_filters() {
        let v = &Spec::embedded().unwrap().value_filters;
        for r in [
            "$X",
            "${X:-y}",
            "$(cat f)",
            "{{ .Values.pw }}",
            "${{ secrets.T }}",
            "<YOUR_TOKEN>",
            "***",
        ] {
            assert!(v.is_reference(r), "{r}");
        }
        assert!(!v.is_reference("Tr0ub4dor-Kx9q"));
        assert!(v.is_placeholder("ChangeMe"));
        assert!(!v.is_placeholder("Tr0ub4dor-Kx9q"));
        assert!(v.is_local_host("localhost"));
        assert!(v.is_local_host("203.0.113.41"));
        assert!(!v.is_local_host("db.acme.io"));
    }

    /// Shapes seen as false positives in real agent files (2026-11-07 run).
    /// References and code are never secrets; placeholders only drop
    /// non-passwords: passwords have no shape, so every password value stays.
    #[test]
    fn filtered_shapes() {
        let v = &Spec::embedded().unwrap().value_filters;
        for s in [
            "Bearer ${token}",
            "this.config?.github?.token ?? \"\"",
            "data.server.password",
            "keys[name].apiKey.trim()",
            "string (required)",
            "hashedPassword,",
            "AuthState",
        ] {
            assert!(v.is_filtered(s, true), "{s}");
            assert!(v.is_filtered(s, false), "{s}");
        }
        for s in [
            "\"OPENAI_API_KEY_HERE\",",
            "PLACEHOLDER,",
            "your_key_here",
            "sk-proj-XXXXXXXXXXXXXXXXXXXX",
            "AIzaSy...BwM",
            "Bearer your-api-token",
            "jwt_token",
            "^9.0.0",
        ] {
            assert!(v.is_filtered(s, false), "token/key placeholder: {s}");
        }
        // Passwords: any value may be real.
        for s in [
            "changeme",
            "password",
            "testpass123",
            "Password123",
            "your_password",
            "cGFzc3dvcmQ=",
        ] {
            assert!(!v.is_filtered(s, true), "password kept: {s}");
        }
        for s in [
            "Tr0ub4dor-Kx9q",
            "\"Kq7vRm2pLx9\",",
            "Bearer 9fQ2vX7LmP4kT8wZ",
            "eyJ0eXAiOiJKV1QiLCJhbGciOi.payload.sig",
            "db01.acme.io",
        ] {
            assert!(!v.is_filtered(s, false), "{s}");
        }
    }

    fn with_rule(regex: &str) -> String {
        EMBEDDED_YAML.replacen(
            "regex_rules:\n",
            &format!(
                "regex_rules:\n  - {{id: t.x, category: http, overlap: none, confidence: low, \
                 severity: low, keywords: [k], regex: '{regex}', pos: [x]}}\n"
            ),
            1,
        )
    }

    #[test]
    fn rejects_lookaround_and_missing_secret_group() {
        let e = Spec::from_yaml(&with_rule("k(?=x)"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("lookahead"), "{e}");
        let e = Spec::from_yaml(&with_rule("k(?P<value>x)"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("t.x: regex has no `secret` group"), "{e}");
    }

    #[test]
    fn rejects_unknown_keys() {
        let y = EMBEDDED_YAML.replacen(
            "  - id: cli.sshpass\n",
            "  - id: cli.sshpass\n    keywrods: [x]\n",
            1,
        );
        assert!(Spec::from_yaml(&y).is_err());
    }
}
