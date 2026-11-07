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
        let file: SpecFile =
            serde_saphyr::from_str(yaml).map_err(|e| SpecError::Yaml(e.to_string()))?;
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
