//! Typed form of `spec/detection-patterns.yaml`.
//!
//! Structs use `deny_unknown_fields`, so a typo in the catalogue fails loudly
//! instead of silently disabling a rule. Regexes are compiled while
//! deserializing (see [`SpecRegex`]).

use std::collections::BTreeMap;
use std::fmt;

use agentleaks_core::{Category, Confidence, Severity};
use regex::Regex;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Helper value types
// ---------------------------------------------------------------------------

/// A regex from the catalogue, compiled with the Rust `regex` crate.
///
/// Deserializing fails if the pattern uses syntax the crate lacks
/// (lookaround, backreferences, atomic groups, possessive quantifiers) or
/// does not compile.
#[derive(Clone)]
pub struct SpecRegex(Regex);

impl SpecRegex {
    pub fn new(pattern: &str) -> Result<Self, String> {
        if let Some(construct) = unsupported_construct(pattern) {
            return Err(format!(
                "unsupported regex syntax {construct:?} (Rust regex has no lookaround, \
                 backreferences or possessive quantifiers): {pattern}"
            ));
        }
        Regex::new(pattern)
            .map(SpecRegex)
            .map_err(|e| format!("regex does not compile: {e}"))
    }

    pub fn regex(&self) -> &Regex {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// True if the pattern defines a capture group with this name.
    pub fn has_group(&self, name: &str) -> bool {
        self.0.capture_names().flatten().any(|n| n == name)
    }
}

impl std::ops::Deref for SpecRegex {
    type Target = Regex;
    fn deref(&self) -> &Regex {
        &self.0
    }
}

impl fmt::Debug for SpecRegex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SpecRegex({:?})", self.0.as_str())
    }
}

impl TryFrom<String> for SpecRegex {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        SpecRegex::new(&s)
    }
}

impl<'de> Deserialize<'de> for SpecRegex {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        SpecRegex::new(&s).map_err(serde::de::Error::custom)
    }
}

/// Finds constructs the Rust `regex` crate does not support, mirroring the
/// check in `spec/test_patterns.py`: `(?=`, `(?!`, `(?<=`, `(?<!`, `\1`..`\9`,
/// `(?>`, and possessive quantifiers (`*+`, `++`, `?+`, `}+`).
fn unsupported_construct(p: &str) -> Option<&'static str> {
    let b = p.as_bytes();
    let mut i = 0;
    // Nesting depth of character classes (`[a[bc]]`, `[[:alpha:]]`).
    let mut class_depth = 0usize;
    while i < b.len() {
        // Escapes: skip `\x`, and the whole braced body of `\p{..}`, `\x{..}`, `\u{..}`.
        if b[i] == b'\\' {
            let next = b.get(i + 1).copied();
            if class_depth == 0 && next.is_some_and(|c| (b'1'..=b'9').contains(&c)) {
                return Some("backreference");
            }
            i += 2;
            if matches!(next, Some(b'p' | b'P' | b'x' | b'u' | b'U')) && b.get(i) == Some(&b'{') {
                while i < b.len() && b[i] != b'}' {
                    i += 1;
                }
                i += 1;
            }
            continue;
        }
        if class_depth > 0 {
            match b[i] {
                b'[' => class_depth += 1,
                b']' => class_depth -= 1,
                _ => {}
            }
            i += 1;
            continue;
        }
        match b[i] {
            b'[' => {
                class_depth = 1;
                // A `]` right after `[` or `[^` is a literal, not the end.
                if b.get(i + 1) == Some(&b'^') {
                    i += 1;
                }
                if b.get(i + 1) == Some(&b']') {
                    i += 1;
                }
            }
            b'(' if b.get(i + 1) == Some(&b'?') => match (b.get(i + 2), b.get(i + 3)) {
                (Some(b'='), _) | (Some(b'!'), _) => return Some("lookahead"),
                (Some(b'<'), Some(b'=')) | (Some(b'<'), Some(b'!')) => return Some("lookbehind"),
                (Some(b'>'), _) => return Some("atomic group"),
                _ => {}
            },
            // `a++` and `a{2}+` compile in Rust but mean something else.
            b'*' | b'+' | b'?' | b'}' if b.get(i + 1) == Some(&b'+') => {
                return Some("possessive quantifier");
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// `x` or `[x, y]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    pub fn as_slice(&self) -> &[T] {
        match self {
            OneOrMany::One(x) => std::slice::from_ref(x),
            OneOrMany::Many(v) => v,
        }
    }
}

/// Whether a rule overlaps with Betterleaks/TruffleHog coverage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Overlap {
    #[default]
    None,
    Partial,
}

// ---------------------------------------------------------------------------
// Top level
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecFile {
    pub meta: Meta,
    pub value_filters: ValueFiltersDef,
    pub credential_names: CredentialNamesDef,
    pub shell_semantics: ShellSemantics,
    pub cli_tools: Vec<CliTool>,
    pub regex_rules: Vec<RegexRule>,
    pub file_formats: Vec<FileFormat>,
    pub agent_structures: Vec<AgentStructure>,
    pub path_rules: Vec<PathRule>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Meta {
    pub name: String,
    pub regex_dialect: String,
    pub secret_group: String,
    pub severities: Vec<Severity>,
    pub confidence_levels: Vec<Confidence>,
}

// ---------------------------------------------------------------------------
// 1. value filters, 2. credential names (raw form; compiled in `filters`)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValueFiltersDef {
    pub references: Vec<SpecRegex>,
    /// Read as `String`, so unquoted scalars such as `123456` or `000000`
    /// keep their exact text.
    pub placeholders: Vec<String>,
    pub defaults: Vec<String>,
    pub min_length: MinLength,
    pub local_hosts: Vec<SpecRegex>,
}

/// Minimum secret length after filtering, by kind of secret.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinLength {
    pub password: usize,
    pub token: usize,
    pub key: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialNamesDef {
    pub exact_env: Vec<String>,
    pub name_patterns: Vec<SpecRegex>,
    pub name_exclusions: Vec<SpecRegex>,
}

// ---------------------------------------------------------------------------
// 3. shell semantics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellSemantics {
    /// Informational description of the tokenizer; the lexer implements it.
    pub tokenizer: serde::de::IgnoredAny,
    pub env_prefix: bool,
    pub wrappers: Wrappers,
    pub stdin_sources: Vec<String>,
    pub stdin_sinks: Vec<StdinSink>,
    /// Entries such as `helm --set` or `docker run -e`: tool words, then the flag.
    pub keyvalue_arg_tools: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wrappers {
    /// Commands whose remaining argv is another command. Multi-word entries
    /// (`op run --`) list the words to skip.
    pub passthrough: Vec<String>,
    pub string_arg: Vec<StringArgWrapper>,
    pub after_double_dash: Vec<String>,
    pub container_exec_after_container_name: Vec<String>,
}

/// A wrapper whose command is inside one string argument (`bash -c '...'`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StringArgWrapper {
    pub cmd: Vec<String>,
    #[serde(default)]
    pub flag: Option<OneOrMany<String>>,
    /// `after host` (ssh) or `all` (eval).
    #[serde(default)]
    pub arg: Option<String>,
    #[serde(default)]
    pub subcommand: Option<OneOrMany<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StdinSink {
    pub cmd: Vec<String>,
    #[serde(default)]
    pub flag: Option<OneOrMany<String>>,
    #[serde(default)]
    pub arg: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

// ---------------------------------------------------------------------------
// 4. CLI knowledge base
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliTool {
    pub tool: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub args: Vec<CliArg>,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub sql_statements: bool,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliArg {
    #[serde(default)]
    pub flag: Option<String>,
    #[serde(default)]
    pub form: Option<ArgForm>,
    #[serde(default)]
    pub kind: Option<ArgKind>,
    #[serde(default)]
    pub position: Option<Position>,
    /// A regex over the command text; the credential is group `secret`.
    #[serde(default)]
    pub pattern: Option<SpecRegex>,
    #[serde(default)]
    pub subcommand: Option<OneOrMany<String>>,
    #[serde(default)]
    pub note: Option<String>,
}

/// How a credential is attached to its flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArgForm {
    /// `-pSECRET`
    Attached,
    /// `-p SECRET`
    Separate,
    AttachedOrSeparate,
    /// `--password=SECRET`
    Equals,
    EqualsOrSeparate,
    /// `/p:SECRET`
    Colon,
    /// n-th non-flag argument after the subcommand
    Positional,
    /// Documented flag that carries no secret (e.g. `--askpass`).
    None,
}

/// What kind of value a credential argument holds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum ArgKind {
    Password,
    Token,
    Key,
    Passphrase,
    /// `user<sep>pass`; the secret is after the first separator.
    UserPass(String),
    /// A connect string in the named syntax (`uri`, `libpq_keyvalue`, ...).
    Connect(String),
    /// The value starts with this prefix, followed by the secret (`pass:x`).
    Prefixed(String),
    /// `NAME=VAL`; NAME is checked against credential names.
    KeyValue,
    /// `NAME VAL` as two arguments.
    KeyValuePair,
    Header,
    HeaderOrItem,
    HeaderHashtable,
    Body,
    Cookie,
    None,
}

impl TryFrom<String> for ArgKind {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        let nonempty = |rest: &str, what: &str| {
            if rest.is_empty() {
                Err(format!("arg kind {s:?}: missing {what}"))
            } else {
                Ok(rest.to_owned())
            }
        };
        Ok(match s.as_str() {
            "password" => ArgKind::Password,
            "token" => ArgKind::Token,
            "key" => ArgKind::Key,
            "passphrase" => ArgKind::Passphrase,
            "keyvalue" => ArgKind::KeyValue,
            "keyvalue_pair" => ArgKind::KeyValuePair,
            "header" => ArgKind::Header,
            "header_or_item" => ArgKind::HeaderOrItem,
            "header_hashtable" => ArgKind::HeaderHashtable,
            "body" => ArgKind::Body,
            "cookie" => ArgKind::Cookie,
            "none" => ArgKind::None,
            other => {
                if let Some(rest) = other.strip_prefix("userpass:") {
                    ArgKind::UserPass(nonempty(rest, "separator")?)
                } else if let Some(rest) = other.strip_prefix("connect:") {
                    ArgKind::Connect(nonempty(rest, "syntax")?)
                } else if let Some(rest) = other.strip_prefix("prefixed:") {
                    ArgKind::Prefixed(nonempty(rest, "prefix")?)
                } else {
                    return Err(format!("unknown arg kind {other:?}"));
                }
            }
        })
    }
}

/// Position of a positional argument: 1-based index, any, or last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Position {
    Index(u32),
    Any,
    Last,
}

impl<'de> Deserialize<'de> for Position {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            N(u32),
            S(String),
        }
        match Raw::deserialize(d)? {
            Raw::N(0) => Err(serde::de::Error::custom(
                "position is 1-based; 0 is invalid",
            )),
            Raw::N(n) => Ok(Position::Index(n)),
            Raw::S(s) if s == "any" => Ok(Position::Any),
            Raw::S(s) if s == "last" => Ok(Position::Last),
            Raw::S(s) => Err(serde::de::Error::custom(format!(
                "position must be a number, `any` or `last`, not {s:?}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// 5. regex rules
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegexRule {
    pub id: String,
    pub category: Category,
    pub overlap: Overlap,
    pub confidence: Confidence,
    pub severity: Severity,
    /// Prefilter keywords (matched case-insensitively). Must not be empty.
    pub keywords: Vec<String>,
    pub regex: SpecRegex,
    #[serde(default)]
    pub alt_regex: Option<SpecRegex>,
    /// Inputs the rule must match (self-test).
    #[serde(default, deserialize_with = "null_as_empty")]
    pub pos: Vec<String>,
    /// Inputs the rule must not match (self-test).
    #[serde(default, deserialize_with = "null_as_empty")]
    pub neg: Vec<String>,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub postprocess: Option<PostProcess>,
    /// Restrict the rule to these input scopes; empty = everywhere.
    #[serde(default)]
    pub scope: Vec<String>,
    /// Drop values that are a single-case run of letters.
    #[serde(default)]
    pub require_complexity: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostProcess {
    Base64DecodeUserpass,
    TrimTrailingPunctuation,
    Bip39WordlistCheck,
    JwtDecodeCheckExp,
}

fn null_as_empty<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    Ok(Option::<Vec<String>>::deserialize(d)?.unwrap_or_default())
}

// ---------------------------------------------------------------------------
// 6. file formats
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileFormat {
    pub id: String,
    pub paths: Vec<String>,
    #[serde(default)]
    pub parser: Option<String>,
    #[serde(default)]
    pub regex: Option<SpecRegex>,
    #[serde(default)]
    pub secret_fields: Vec<String>,
    #[serde(default)]
    pub secret_keys: Vec<String>,
    #[serde(default)]
    pub secret_keys_from: Option<String>,
    #[serde(default)]
    pub json_paths: Vec<String>,
    /// JSON path -> post-processor.
    #[serde(default)]
    pub postprocess: BTreeMap<String, PostProcess>,
    #[serde(default)]
    pub checks: Vec<String>,
    #[serde(default)]
    pub overlap: Overlap,
    #[serde(default)]
    pub analyzers: Vec<String>,
    #[serde(default)]
    pub severity: Option<Severity>,
    #[serde(default)]
    pub k8s_secret_decode: bool,
    #[serde(default)]
    pub note: Option<String>,
}

// ---------------------------------------------------------------------------
// 7. agent structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentStructure {
    pub id: String,
    #[serde(default)]
    pub applies_to: Vec<String>,
    #[serde(default)]
    pub note: Option<String>,
    /// Route for structures that send everything one way (`command`, `env`, ...).
    #[serde(default)]
    pub route: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub json_paths: Vec<JsonPathRoute>,
    #[serde(default)]
    pub extract: Vec<ExtractRule>,
    #[serde(default)]
    pub regex: Option<SpecRegex>,
    #[serde(default)]
    pub toml_keys: Vec<String>,
    #[serde(default)]
    pub key_names: Vec<String>,
    #[serde(default)]
    pub json_key_names: Vec<String>,
    // MCP servers
    #[serde(default)]
    pub json_roots: Vec<String>,
    #[serde(default)]
    pub per_server: Vec<JsonPathRoute>,
    #[serde(default)]
    pub toml_roots: Vec<String>,
    #[serde(default)]
    pub yaml_roots: Vec<String>,
    // transcripts
    /// route -> JSON keys whose string values take that route.
    #[serde(default)]
    pub route_by_key: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub also_scan_unrouted_strings_with: Vec<String>,
    #[serde(default)]
    pub json_string_arguments: bool,
    /// code-fence language -> route (`''` = no language).
    #[serde(default)]
    pub route_code_fences: BTreeMap<String, String>,
    #[serde(default)]
    pub strip_prompt_prefix: Option<SpecRegex>,
    // stores
    #[serde(default)]
    pub tables_and_columns: Vec<TableColumn>,
    #[serde(default)]
    pub value_decoding: Vec<String>,
    #[serde(default)]
    pub then: Option<String>,
    #[serde(default)]
    pub analyzers: Vec<String>,
}

/// One JSON path inside an agent file, with an optional unwrap regex and the
/// route its string values take.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JsonPathRoute {
    pub path: String,
    pub route: String,
    /// Regex whose single named group is the payload (`cmd`, `url`, `arg`).
    #[serde(default)]
    pub unwrap: Option<SpecRegex>,
    #[serde(default)]
    pub key_is_header_name: bool,
    #[serde(default)]
    pub join_with: Option<String>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtractRule {
    pub regex: SpecRegex,
    pub route: String,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TableColumn {
    pub table: String,
    pub column: String,
}

// ---------------------------------------------------------------------------
// 8. path rules
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRule {
    pub kind: PathKind,
    pub priority: Priority,
    pub parser: Parser,
    /// Agent-structure ids and/or analyzer names to run.
    #[serde(rename = "use")]
    pub uses: Vec<String>,
    pub harness: OneOrMany<String>,
    #[serde(default)]
    pub globs: Vec<String>,
    /// Git refs (checkpoint rules) instead of globs.
    #[serde(default)]
    pub refs: Vec<String>,
    /// Values for `{EDITOR}` in globs.
    #[serde(default)]
    pub editors: Vec<String>,
    #[serde(default)]
    pub severity: Option<Severity>,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    Allowlist,
    Settings,
    Mcp,
    Transcript,
    History,
    CredentialStore,
    EnvCapture,
    Checkpoint,
    Memory,
    Log,
    Export,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    /// In repositories (often committed).
    P1,
    /// On the developer machine.
    P2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Parser {
    Json,
    Jsonc,
    Jsonl,
    Toml,
    Yaml,
    Md,
    Sqlite,
    Starlark,
    Text,
    Git,
    Auto,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_constructs_are_named() {
        for (p, want) in [
            ("a(?=b)", "lookahead"),
            ("a(?!b)", "lookahead"),
            ("(?<=a)b", "lookbehind"),
            ("(?<!a)b", "lookbehind"),
            (r"(a)\1", "backreference"),
            ("(?>a)", "atomic group"),
            ("a++", "possessive quantifier"),
            ("a{2}+", "possessive quantifier"),
        ] {
            assert_eq!(unsupported_construct(p), Some(want), "{p}");
        }
        // Escaped and named-group syntax is fine.
        for p in [
            r"\(\?=",
            r"(?P<secret>x)",
            r"(?<secret>x)",
            r"\\1",
            r"a+b",
            r"[+]+",
            r"[*+?]",
            r"[]*+]",
            r"[^]*+]x",
            r"[\]*+]",
            r"\p{L}+",
            r"\P{N}+x",
            r"\x{41}+",
            r"[[:alpha:]*+]",
            r"[a[b*+]]",
        ] {
            assert_eq!(unsupported_construct(p), None, "{p}");
        }
    }

    #[test]
    fn arg_kind_parses_parameterised_forms() {
        let k = |s: &str| ArgKind::try_from(s.to_owned());
        assert_eq!(k("userpass::"), Ok(ArgKind::UserPass(":".into())));
        assert_eq!(k("userpass:%"), Ok(ArgKind::UserPass("%".into())));
        assert_eq!(k("connect:uri"), Ok(ArgKind::Connect("uri".into())));
        assert_eq!(k("prefixed:pass:"), Ok(ArgKind::Prefixed("pass:".into())));
        assert!(k("userpass:").is_err());
        assert!(k("passwrod").is_err());
    }
}
