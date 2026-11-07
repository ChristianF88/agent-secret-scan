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

pub mod archive;
pub mod heapsnapshot;
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

    /// The plan for an archive entry at `vpath` (`<archive>!/<path>`): its
    /// own path rule if one matches, else the archive's plan (entries of an
    /// agent archive such as a Playwright trace inherit it), with the
    /// parser taken from the entry's extension.
    pub fn plan_entry(&self, archive: Option<&FilePlan<'s>>, vpath: &str) -> Option<FilePlan<'s>> {
        self.plan(vpath).or_else(|| {
            archive.map(|p| FilePlan {
                parser: router::parser_by_extension(vpath).unwrap_or(Parser::Auto),
                ..p.clone()
            })
        })
    }

    /// Read a SQLite database planned as an agent store and call `f` once
    /// per decoded value of the catalogue's `tables_and_columns`. Values
    /// that are binary are skipped. Damaged pages are skipped and reported
    /// in the returned [`sqlite::Damage`]; an unreadable header or schema is
    /// an error.
    ///
    /// `wal`: the bytes of the `-wal` file next to the database, read the
    /// way SQLite reads it (an unusable WAL is noted in the damage and the
    /// database is read without it). After the live rows, deleted rows
    /// still on disk are recovered ([`sqlite::Reader::recover`]) and
    /// delivered with [`StoreRow::deleted`] set, unless the same value was
    /// already delivered.
    pub fn sqlite_values(
        &self,
        plan: &FilePlan<'s>,
        bytes: &[u8],
        wal: Option<&[u8]>,
        f: &mut dyn FnMut(&StoreRow<'_>, &str),
    ) -> Result<sqlite::Damage, sqlite::Error> {
        let Some(store) = self.structures.store(plan) else {
            return Ok(sqlite::Damage::default());
        };
        let utf16 = store.value_decoding.iter().any(|d| d == "utf16_json");
        let mut wal_problem = None;
        let parsed = match wal.map(sqlite::Wal::parse) {
            Some(Ok(w)) => w,
            Some(Err(e)) => {
                wal_problem = Some(e);
                None
            }
            None => None,
        };
        let db = match parsed
            .as_ref()
            .map(|w| sqlite::Db::open_with_wal(bytes, Some(w)))
        {
            Some(Ok(db)) => db,
            Some(Err(e)) => {
                wal_problem = Some(e);
                sqlite::Db::open(bytes)?
            }
            None => sqlite::Db::open(bytes)?,
        };
        let mut reader = db.reader();
        let tables = reader.tables()?;
        // (table, value column, key column) per listed table.
        let mut wanted: Vec<(&sqlite::Table, usize, Option<usize>)> = Vec::new();
        for tc in &store.tables_and_columns {
            if let Some(t) = tables.iter().find(|t| t.name == tc.table)
                && let Some(col) = t.column(&tc.column)
                && !wanted.iter().any(|w| w.0.root == t.root)
            {
                wanted.push((t, col, t.column("key")));
            }
        }
        let value_of = |values: &[sqlite::Value<'_>], col: usize| -> Option<String> {
            match values.get(col) {
                Some(sqlite::Value::Text(v)) => Some(db.text(v).into_owned()),
                Some(sqlite::Value::Blob(v)) => sqlite::decode_value(v, utf16).map(Cow::into_owned),
                _ => None,
            }
        };
        // Values delivered so far (hashes): recovered copies of live rows,
        // and repeated copies across stale pages, are not delivered again.
        let mut delivered: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for &(t, col, key_col) in &wanted {
            reader.walk(t.root, &mut |row| {
                let Ok(values) = row.values() else { return };
                let Some(text) = value_of(&values, col) else {
                    return;
                };
                delivered.insert(hash_of(&text));
                let r = StoreRow {
                    table: &t.name,
                    key: key_text(&db, &values, key_col),
                    rowid: row.rowid,
                    deleted: false,
                };
                f(&r, &text);
            });
        }
        let cols = |root: u32| {
            wanted
                .iter()
                .find(|w| w.0.root == root)
                .map(|w| w.0.columns.len())
        };
        let mut free_cols: Vec<usize> = wanted.iter().map(|w| w.0.columns.len()).collect();
        free_cols.sort_unstable();
        free_cols.dedup();
        reader.recover(&cols, &free_cols, &mut |root, row| {
            let Ok(values) = row.values() else { return };
            // The table of a row on a free page is unknown: the first
            // listed table with that many columns decides the columns.
            let target = match root {
                Some(r) => wanted.iter().find(|w| w.0.root == r),
                None => wanted.iter().find(|w| w.0.columns.len() == values.len()),
            };
            let Some(&(t, col, key_col)) = target else {
                return;
            };
            let Some(text) = value_of(&values, col) else {
                return;
            };
            if !delivered.insert(hash_of(&text)) {
                return;
            }
            let r = StoreRow {
                table: if root.is_some() { &t.name } else { "(deleted)" },
                key: key_text(&db, &values, key_col),
                rowid: row.rowid,
                deleted: true,
            };
            f(&r, &text);
        });
        let mut damage = reader.damage;
        damage.wal = wal_problem;
        Ok(damage)
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
/// glob also matches. They are not scanned on their own: a `-wal` is read
/// with its database; `-shm` and rollback `-journal` files are not read.
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
    /// [`sqlite::UNKNOWN_ROWID`] for records carved from free space.
    pub rowid: i64,
    /// Recovered from free space (deleted, overwritten or uncheckpointed
    /// history); `table` is `(deleted)` when the row's table is unknown.
    pub deleted: bool,
}

/// The text of a row's key column.
fn key_text<'v>(
    db: &sqlite::Db<'_>,
    values: &[sqlite::Value<'v>],
    k: Option<usize>,
) -> Option<Cow<'v, str>> {
    match k.and_then(|k| values.get(k)) {
        Some(sqlite::Value::Text(t)) => Some(db.text(t)),
        _ => None,
    }
}

/// Hash of a delivered store value (dedup of recovered copies).
fn hash_of(text: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::hash::DefaultHasher::new();
    text.hash(&mut h);
    h.finish()
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
            None if self.rowid == sqlite::UNKNOWN_ROWID => format!("{}/#?", self.table),
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
