//! Extractors: turn a file into routed strings.
//!
//! [`Extractors::plan`] routes a report path through `path_rules` (and
//! `agent_structures.applies_to`); [`Extractors::extract`] parses the file
//! with the planned parser and calls a sink once per [`Routed`] string.
//!
//! The sink style lets routed strings borrow from per-file parse trees
//! without copying them.
//!
//! Parsers: JSON / JSONC / JSONL (span-aware, see [`json`]), TOML and YAML
//! (converted to the same span-aware tree, see [`toml_tree`] and
//! [`yaml_tree`]), Markdown, Starlark (`prefix_rule`) and plain text. TOML
//! and YAML files are also scanned as raw text, so line-oriented rules
//! (`key: value`) keep working on them.

pub mod json;
pub mod jsonpath;
pub mod markdown;
pub mod router;
pub mod sqlite;
mod structures;
pub mod toml_tree;
pub mod transcript;
pub mod yaml_tree;

use std::borrow::Cow;

use agentleaks_core::{Route, Routed, TextOrigin};
use agentleaks_spec::{Parser, PathKind, Spec};

pub use router::{FilePlan, Router};
pub use structures::{Structures, Syntax};

/// Receives routed strings. Called synchronously during extraction.
pub type Sink<'x> = dyn FnMut(&Routed<'_>) + 'x;

/// Path routing plus the compiled agent structures.
#[derive(Debug)]
pub struct Extractors<'s> {
    router: Router<'s>,
    structures: Structures<'s>,
}

impl<'s> Extractors<'s> {
    pub fn new(spec: &'s Spec) -> Result<Self, String> {
        Ok(Extractors {
            router: Router::new(spec)?,
            structures: Structures::compile(spec)?,
        })
    }

    pub fn router(&self) -> &Router<'s> {
        &self.router
    }

    /// The plan for a report path, or `None` when no path rule applies.
    pub fn plan(&self, path: &str) -> Option<FilePlan<'s>> {
        self.router.plan(path)
    }

    /// Read a SQLite database planned as an agent store and call `f` once
    /// per decoded value of the catalogue's `tables_and_columns`. Values
    /// that are binary are skipped. Damaged pages are skipped and reported
    /// in the returned [`sqlite::Damage`]; an unreadable header or schema is
    /// an error.
    pub fn sqlite_values(
        &self,
        plan: &FilePlan<'s>,
        bytes: &[u8],
        f: &mut dyn FnMut(&StoreRow<'_>, &str),
    ) -> Result<sqlite::Damage, sqlite::Error> {
        let Some(store) = self.structures.store(plan) else {
            return Ok(sqlite::Damage::default());
        };
        let utf16 = store.value_decoding.iter().any(|d| d == "utf16_json");
        let db = sqlite::Db::open(bytes)?;
        let mut reader = db.reader();
        let tables = reader.tables()?;
        for tc in &store.tables_and_columns {
            let Some(t) = tables.iter().find(|t| t.name == tc.table) else {
                continue;
            };
            let Some(col) = t.column(&tc.column) else {
                continue;
            };
            let key_col = t.column("key");
            reader.walk(t.root, &mut |row| {
                let Ok(values) = row.values() else { return };
                let text = match values.get(col) {
                    Some(sqlite::Value::Text(v)) => db.text(v),
                    Some(sqlite::Value::Blob(v)) => match sqlite::decode_value(v, utf16) {
                        Some(s) => s,
                        None => return,
                    },
                    _ => return,
                };
                let key = match key_col.and_then(|k| values.get(k)) {
                    Some(sqlite::Value::Text(k)) => Some(db.text(k)),
                    _ => None,
                };
                let r = StoreRow {
                    table: &t.name,
                    key,
                    rowid: row.rowid,
                };
                f(&r, &text);
            });
        }
        Ok(reader.damage)
    }

    /// Route one value read by [`Self::sqlite_values`]. A non-JSON value is
    /// a config value named by [`StoreRow::name`].
    pub fn extract_store_value(
        &self,
        plan: &FilePlan<'s>,
        row: &StoreRow<'_>,
        text: &str,
        sink: &mut Sink<'_>,
    ) {
        self.structures.store_value(plan, row.name(), text, sink);
    }

    /// Extract routed strings from one file.
    pub fn extract(&self, plan: &FilePlan<'s>, path: &str, text: &str, sink: &mut Sink<'_>) {
        let st = &self.structures;
        match plan.parser {
            Parser::Json | Parser::Jsonc => match json::parse(text) {
                Ok(root) => st.tree_file(plan, &root, Syntax::Json, sink),
                Err(_) => raw(text, sink),
            },
            Parser::Jsonl => st.jsonl_file(plan, text, sink),
            Parser::Md => st.markdown_file(plan, path, text, sink),
            Parser::Starlark => st.starlark_file(plan, text, sink),
            Parser::Text => st.text_file(plan, text, sink),
            Parser::Auto => {
                let t = text.trim_start_matches('\u{feff}').trim_start();
                if t.starts_with(['{', '[']) {
                    match json::parse(text) {
                        Ok(root) => st.tree_file(plan, &root, Syntax::Json, sink),
                        Err(_) => st.jsonl_file(plan, text, sink),
                    }
                } else if plan.kind == Some(PathKind::Transcript)
                    || plan.kind == Some(PathKind::Memory)
                {
                    st.markdown_file(plan, path, text, sink)
                } else {
                    st.text_file(plan, text, sink)
                }
            }
            Parser::Toml => {
                if let Ok(root) = toml_tree::parse(text) {
                    st.tree_file(plan, &root, Syntax::Toml, sink);
                }
                raw(text, sink);
            }
            Parser::Yaml => {
                if let Ok(docs) = yaml_tree::parse(text) {
                    for doc in &docs {
                        st.tree_file(plan, doc, Syntax::Yaml, sink);
                    }
                }
                raw(text, sink);
            }
            // SQLite stores are read from bytes (see `sqlite_values`); a
            // text file here is not a database.
            // TODO(extractors): git checkpoints. Until then: whole file as text.
            Parser::Sqlite | Parser::Git => raw(text, sink),
        }
    }
}

/// SQLite side files (`-wal`, `-shm`, `-journal`) that a `state.vscdb*`
/// glob also matches. Not readable yet (the WAL format is not parsed), so
/// they are skipped explicitly rather than sniffed as binary.
pub fn is_sqlite_sidecar(path: &str) -> bool {
    ["-wal", "-shm", "-journal"]
        .iter()
        .any(|s| path.ends_with(s))
}

/// One row of an agent store, as handed to [`Extractors::sqlite_values`].
#[derive(Debug)]
pub struct StoreRow<'r> {
    pub table: &'r str,
    /// The row's `key` column, when the table has one.
    pub key: Option<Cow<'r, str>>,
    pub rowid: i64,
}

impl StoreRow<'_> {
    /// The value's config name: the last segment of the row key
    /// (`cursorAuth/accessToken` -> `accessToken`); empty without a key.
    pub fn name(&self) -> &str {
        let k = self.key.as_deref().unwrap_or("");
        k.rsplit(['/', '.', ':']).next().unwrap_or(k)
    }

    /// Label for a report path: `<table>/<key>` (control characters
    /// replaced, at most 160 characters) or `<table>/#<rowid>`. Built only
    /// for rows with findings.
    pub fn label(&self) -> String {
        match &self.key {
            Some(k) => {
                let k: String = k
                    .chars()
                    .take(160)
                    .map(|c| if c.is_control() { '?' } else { c })
                    .collect();
                format!("{}/{k}", self.table)
            }
            None => format!("{}/#{}", self.table, self.rowid),
        }
    }
}

/// The whole file as one raw text string.
fn raw(text: &str, sink: &mut Sink<'_>) {
    sink(&Routed::raw_text(text, Route::Text));
}

/// A routed string with the common fields filled in.
pub(crate) fn routed<'a>(
    text: impl Into<Cow<'a, str>>,
    route: Route,
    origin: TextOrigin,
    name: Option<&'a str>,
    scope: Option<&'a str>,
    structure: Option<&'a str>,
) -> Routed<'a> {
    Routed {
        text: text.into(),
        route,
        origin,
        name: name.map(Cow::Borrowed),
        scope,
        structure,
    }
}

/// Map a catalogue route name to a core route. Structural pseudo-routes
/// (`mcp_servers`, `command_keys`, ...) are handled by the caller.
pub fn route_of(name: &str) -> Option<Route> {
    Some(match name {
        "command" | "command_with_prompt" => Route::Command,
        "command_argv" => Route::CommandArgv,
        "text" => Route::Text,
        "url" => Route::Url,
        "env" => Route::Env,
        "headers" => Route::Headers,
        "sql" | "sql_statement" => Route::Sql,
        "config_key" => Route::ConfigKey,
        _ => return None,
    })
}

/// Strip an allow-rule glob suffix: `npm run:*` -> `npm run`, `git push *` -> `git push`.
pub fn strip_glob_suffix(cmd: &str) -> &str {
    let t = cmd.trim_end();
    t.strip_suffix(":*")
        .or_else(|| t.strip_suffix(" *"))
        .map_or(t, str::trim_end)
}

/// Join argv tokens into one shell command line, single-quoting tokens that
/// the shell would otherwise split or expand.
pub fn shell_join<'t>(tokens: impl IntoIterator<Item = &'t str>) -> String {
    let mut out = String::new();
    for (i, t) in tokens.into_iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let safe = !t.is_empty()
            && t.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_@%+=:,./!-".contains(&b));
        if safe {
            out.push_str(t);
        } else {
            out.push('\'');
            out.push_str(&t.replace('\'', r"'\''"));
            out.push('\'');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_suffix() {
        assert_eq!(strip_glob_suffix("npm run:*"), "npm run");
        assert_eq!(strip_glob_suffix("git push *"), "git push");
        assert_eq!(strip_glob_suffix("ls -la"), "ls -la");
        assert_eq!(strip_glob_suffix("echo a*"), "echo a*");
    }

    #[test]
    fn join() {
        assert_eq!(
            shell_join(["mysql", "-pX1!", "a b", "it's", "$x"]),
            r"mysql -pX1! 'a b' 'it'\''s' '$x'"
        );
        assert_eq!(shell_join(["-pC0dex", "db"]), "-pC0dex db");
        assert_eq!(shell_join([""]), "''");
    }
}
