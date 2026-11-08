//! Agent structures (catalogue section 7) applied to parsed files.

use std::collections::HashSet;

use agentleaks_core::{Route, TextOrigin};
use agentleaks_spec::{AgentStructure, JsonPathRoute, PathKind, Spec};

use crate::json::{self, Json, JsonStr};
use crate::jsonpath::JsonPath;
use crate::markdown::{self, Fences};
use crate::router::FilePlan;
use crate::transcript::{self, Base, KeyRoutes};
use crate::{Sink, raw, route_of, routed, shell_join, strip_glob_suffix};

/// The syntax a parsed tree came from. It selects which catalogue fields
/// apply: `json_paths`/`json_roots` to JSON, `toml_roots`/`toml_keys` to
/// TOML, `yaml_roots` to YAML. `key_names`, `per_server` and `config_key`
/// apply to all three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    Json,
    Toml,
    Yaml,
}

#[derive(Debug)]
struct Compiled<'s> {
    def: &'s AgentStructure,
    json_paths: Vec<(JsonPath, &'s JsonPathRoute)>,
    per_server: Vec<(JsonPath, &'s JsonPathRoute)>,
    json_roots: Vec<JsonPath>,
    toml_roots: Vec<JsonPath>,
    yaml_roots: Vec<JsonPath>,
    key_names: HashSet<&'s str>,
    toml_keys: HashSet<&'s str>,
    transcript: Option<KeyRoutes<'s>>,
    fences: Option<Fences<'s>>,
}

/// Every agent structure, compiled once. Indices match
/// `spec.agent_structures` (and [`FilePlan::structures`]).
#[derive(Debug)]
pub struct Structures<'s> {
    items: Vec<Compiled<'s>>,
    /// The structure that describes MCP server objects (`per_server`).
    mcp: Option<usize>,
    /// The structure that maps code-fence languages to routes.
    fences: Option<usize>,
}

impl<'s> Structures<'s> {
    pub fn compile(spec: &'s Spec) -> Result<Self, String> {
        let paths = |id: &str, v: &'s [JsonPathRoute]| {
            v.iter()
                .map(|jp| {
                    JsonPath::parse(&jp.path)
                        .map(|p| (p, jp))
                        .map_err(|e| format!("agent_structures.{id}: {e}"))
                })
                .collect::<Result<Vec<_>, _>>()
        };
        let roots = |id: &str, v: &[String]| {
            v.iter()
                .map(|r| JsonPath::parse(r).map_err(|e| format!("agent_structures.{id}: {e}")))
                .collect::<Result<Vec<_>, _>>()
        };
        let mut items = Vec::with_capacity(spec.agent_structures.len());
        for def in &spec.agent_structures {
            items.push(Compiled {
                def,
                json_paths: paths(&def.id, &def.json_paths)?,
                per_server: paths(&def.id, &def.per_server)?,
                json_roots: roots(&def.id, &def.json_roots)?,
                toml_roots: roots(&def.id, &def.toml_roots)?,
                yaml_roots: roots(&def.id, &def.yaml_roots)?,
                key_names: def.key_names.iter().map(String::as_str).collect(),
                toml_keys: def.toml_keys.iter().map(String::as_str).collect(),
                transcript: KeyRoutes::compile(def),
                fences: Fences::compile(def),
            });
        }
        let mcp = items
            .iter()
            .position(|c| !c.json_roots.is_empty() && !c.per_server.is_empty());
        let fences = items.iter().position(|c| c.fences.is_some());
        Ok(Structures { items, mcp, fences })
    }

    fn planned<'p>(&'p self, plan: &'p FilePlan<'_>) -> impl Iterator<Item = &'p Compiled<'s>> {
        plan.structures.iter().filter_map(|&i| self.items.get(i))
    }

    // ---------------------------------------------------------------- JSON

    /// Apply the planned structures to a parsed JSON, TOML or YAML document.
    /// For TOML and YAML the caller also scans the raw text, so strings no
    /// structure routed are not emitted again here.
    pub(crate) fn tree_file(
        &self,
        plan: &FilePlan<'_>,
        root: &Json<'_>,
        syntax: Syntax,
        sink: &mut Sink<'_>,
    ) {
        self.doc_value(plan, root, 0, syntax, sink);
    }

    /// The JSONL lines that start in `range` (see
    /// [`crate::Extractors::jsonl_records`]).
    pub(crate) fn jsonl_lines(
        &self,
        plan: &FilePlan<'_>,
        text: &str,
        range: std::ops::Range<usize>,
        sink: &mut Sink<'_>,
    ) {
        let mut start = range.start;
        let lines = memchr::memchr_iter(b'\n', &text.as_bytes()[range.clone()])
            .map(|i| range.start + i)
            .chain([range.end]);
        for end in lines {
            let line = &text[start..end];
            if !line.trim().is_empty() {
                match json::parse(line) {
                    Ok(root) => self.doc_value(plan, &root, start, Syntax::Json, sink),
                    Err(_) => sink(&routed(
                        line,
                        Route::Text,
                        TextOrigin::Raw { start },
                        None,
                        None,
                        None,
                    )),
                }
            }
            start = end + 1;
            if start > text.len() {
                break;
            }
        }
    }

    /// Apply the planned structures to one document at `base`.
    fn doc_value(
        &self,
        plan: &FilePlan<'_>,
        root: &Json<'_>,
        base: usize,
        syntax: Syntax,
        sink: &mut Sink<'_>,
    ) {
        let base_ = Base::Offset(base);
        // Transcripts (JSON records) route every string leaf themselves.
        if syntax == Syntax::Json
            && let Some(c) = self.planned(plan).find(|c| c.transcript.is_some())
            && let Some(kr) = &c.transcript
        {
            transcript::walk(kr, root, base_, Some(&c.def.id), sink);
            return;
        }
        let mut cx = JsonCx {
            base: base_,
            consumed: HashSet::new(),
        };
        for c in self.planned(plan) {
            let sid = Some(c.def.id.as_str());
            if syntax == Syntax::Json {
                for (path, jp) in &c.json_paths {
                    let mut sel = Vec::new();
                    path.select(root, &mut sel);
                    for (key, node) in sel {
                        self.route_node(jp, key, node, sid, &mut cx, sink);
                    }
                }
            }
            let roots = match syntax {
                Syntax::Json => &c.json_roots,
                Syntax::Toml => &c.toml_roots,
                Syntax::Yaml => &c.yaml_roots,
            };
            for path in roots {
                let mut sel = Vec::new();
                path.select(root, &mut sel);
                for (_, node) in sel {
                    self.mcp_servers(node, &mut cx, sink);
                }
            }
            if !c.key_names.is_empty() {
                key_names(c, &c.key_names, root, None, &mut cx, sink);
            }
            if syntax == Syntax::Toml && !c.toml_keys.is_empty() {
                key_names(c, &c.toml_keys, root, None, &mut cx, sink);
            }
        }
        if plan.uses_analyzer("config_key") {
            config_keys(root, None, &mut cx, sink);
        }
        if syntax == Syntax::Json {
            unconsumed(root, &cx, sink);
        }
    }

    fn route_node<'t>(
        &self,
        jp: &JsonPathRoute,
        key: Option<&'t JsonStr<'_>>,
        node: &'t Json<'_>,
        sid: Option<&str>,
        cx: &mut JsonCx,
        sink: &mut Sink<'_>,
    ) {
        match jp.route.as_str() {
            "mcp_servers" => self.mcp_servers(node, cx, sink),
            "command_keys" | "command_keys_or_regex" | "url_keys" => {
                let Json::Obj(members) = node else { return };
                for (k, _) in members {
                    let is_regex =
                        k.value.len() > 1 && k.value.starts_with('/') && k.value.ends_with('/');
                    // VS Code "Always Allow Exact Command Line" stores the
                    // whole command as `/^<escaped>$/`: analyze it as one.
                    let literal = (jp.route != "url_keys" && is_regex)
                        .then(|| literal_regex_command(&k.value))
                        .flatten();
                    let origin = cx.base.origin(k);
                    if let Some(cmd) = literal {
                        sink(&routed(cmd, Route::Command, origin, None, None, sid));
                        continue;
                    }
                    let route = if jp.route == "url_keys" {
                        Route::Url
                    } else if is_regex {
                        Route::Text // `/regex/` keys
                    } else {
                        Route::Command
                    };
                    let text = match route {
                        Route::Command => strip_glob_suffix(&k.value),
                        _ => &k.value,
                    };
                    sink(&routed(text, route, origin, None, None, sid));
                }
            }
            "command_args" => {} // joined into `command` (join_with)
            r => {
                let route = route_of(r).unwrap_or(Route::Text);
                match node {
                    Json::Str(s) => emit_value(jp, route, key, s, sid, cx, sink),
                    Json::Arr(items) => {
                        for it in items {
                            if let Json::Str(s) = it {
                                emit_value(jp, route, key, s, sid, cx, sink);
                            }
                        }
                    }
                    Json::Obj(members)
                        if matches!(route, Route::Env | Route::Headers | Route::ConfigKey) =>
                    {
                        for (k, v) in members {
                            if let Json::Str(s) = v {
                                emit_value(jp, route, Some(k), s, sid, cx, sink);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// MCP server definitions: an object keyed by server name, or a list of
    /// server objects (Continue's YAML `mcpServers: [- name: ...]`).
    fn mcp_servers(&self, node: &Json<'_>, cx: &mut JsonCx, sink: &mut Sink<'_>) {
        let Some(mi) = self.mcp else { return };
        let servers: Vec<&Json<'_>> = match node {
            Json::Obj(m) => m.iter().map(|(_, s)| s).collect(),
            Json::Arr(a) => a.iter().collect(),
            _ => return,
        };
        let c = &self.items[mi];
        let sid = Some(c.def.id.as_str());
        for server in servers {
            if !matches!(server, Json::Obj(_)) {
                continue;
            }
            for (path, jp) in &c.per_server {
                if let Some(args_key) = &jp.join_with {
                    join_command(jp, server, args_key, sid, cx, sink);
                    continue;
                }
                let mut sel = Vec::new();
                path.select(server, &mut sel);
                for (key, n) in sel {
                    self.route_node(jp, key, n, sid, cx, sink);
                }
            }
        }
    }

    // ------------------------------------------------------------ Markdown

    pub(crate) fn markdown_file(
        &self,
        plan: &FilePlan<'_>,
        path: &str,
        text: &str,
        sink: &mut Sink<'_>,
    ) {
        let fences = self
            .planned(plan)
            .find_map(|c| c.fences.as_ref())
            .or_else(|| self.fences.and_then(|i| self.items[i].fences.as_ref()));
        let transcript = plan.kind == Some(PathKind::Transcript)
            || self.planned(plan).any(|c| c.fences.is_some());
        let scope = if transcript {
            "chat_history"
        } else if is_memory_path(path) {
            "memory_file"
        } else {
            "instruction_file"
        };
        // The fence structure, else one that is not JSON-shaped (memory).
        let sid = self
            .planned(plan)
            .find(|c| c.fences.is_some())
            .or_else(|| {
                self.planned(plan)
                    .find(|c| c.transcript.is_none() && c.json_paths.is_empty())
            })
            .map(|c| c.def.id.as_str());
        markdown::extract(text, fences, Some(scope), sid, sink);
    }

    // ------------------------------------------------- Starlark and text

    pub(crate) fn starlark_file(&self, plan: &FilePlan<'_>, text: &str, sink: &mut Sink<'_>) {
        for c in self.planned(plan) {
            let sid = Some(c.def.id.as_str());
            for rule in &c.def.extract {
                let route = route_of(&rule.route).unwrap_or(Route::Text);
                let Some(group) = rule.regex.capture_names().flatten().next() else {
                    continue;
                };
                for caps in rule.regex.captures_iter(text) {
                    let Some(m) = caps.name(group) else { continue };
                    if route == Route::CommandArgv {
                        let joined =
                            shell_join(python_strings(m.as_str()).iter().map(String::as_str));
                        let origin = TextOrigin::Decoded {
                            start: m.start(),
                            end: m.end(),
                        };
                        sink(&routed(joined, route, origin, None, None, sid));
                    } else {
                        let origin = TextOrigin::Raw { start: m.start() };
                        sink(&routed(m.as_str(), route, origin, None, None, sid));
                    }
                }
            }
        }
        raw(text, sink);
    }

    pub(crate) fn text_file(&self, plan: &FilePlan<'_>, text: &str, sink: &mut Sink<'_>) {
        for c in self.planned(plan) {
            let Some(re) = &c.def.regex else { continue };
            let route = c
                .def
                .route
                .as_deref()
                .and_then(route_of)
                .unwrap_or(Route::Env);
            let sid = Some(c.def.id.as_str());
            for caps in re.captures_iter(text) {
                let Some(secret) = caps.name("secret") else {
                    continue;
                };
                let name = caps.name("name").map(|n| n.as_str());
                let origin = TextOrigin::Raw {
                    start: secret.start(),
                };
                sink(&routed(secret.as_str(), route, origin, name, None, sid));
            }
        }
        raw(text, sink);
    }
}

/// Per-document JSON state.
struct JsonCx {
    base: Base,
    /// Span starts of string literals a structure already routed.
    consumed: HashSet<usize>,
}

fn emit_value(
    jp: &JsonPathRoute,
    route: Route,
    key: Option<&JsonStr<'_>>,
    s: &JsonStr<'_>,
    sid: Option<&str>,
    cx: &mut JsonCx,
    sink: &mut Sink<'_>,
) {
    let (mut text, origin) = match &jp.unwrap {
        Some(u) => {
            let Some(group) = u.capture_names().flatten().next() else {
                return;
            };
            let Some(m) = u.captures(&s.value).and_then(|c| c.name(group)) else {
                return; // a different rule shape (`Read(...)`): left for the text pass
            };
            (&s.value[m.range()], cx.base.sub_origin(s, m.start()))
        }
        None => (&*s.value, cx.base.origin(s)),
    };
    if matches!(route, Route::Command | Route::CommandArgv) {
        text = strip_glob_suffix(text);
    }
    cx.consumed.insert(s.span.start);
    let name = key.map(|k| &*k.value);
    sink(&routed(text, route, origin, name, None, sid));
}

/// `command` + `args` of an MCP server as one command line.
fn join_command(
    jp: &JsonPathRoute,
    server: &Json<'_>,
    args_key: &str,
    sid: Option<&str>,
    cx: &mut JsonCx,
    sink: &mut Sink<'_>,
) {
    let Some(Json::Str(cmd)) = server.get(&jp.path) else {
        return;
    };
    let args: Vec<&JsonStr<'_>> = match server.get(args_key) {
        Some(Json::Arr(a)) => a
            .iter()
            .filter_map(|x| match x {
                Json::Str(s) => Some(s),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    cx.consumed.insert(cmd.span.start);
    let Some(last) = args.last() else {
        sink(&routed(
            &*cmd.value,
            Route::Command,
            cx.base.origin(cmd),
            None,
            None,
            sid,
        ));
        return;
    };
    // Args stay unconsumed: the text pass reports them at their own line.
    let joined = shell_join(std::iter::once(&*cmd.value).chain(args.iter().map(|a| &*a.value)));
    let origin = cx.base.range(cmd.span.start, last.span.end);
    sink(&routed(joined, Route::Command, origin, None, None, sid));
}

/// Members whose key is in `names` (`key_names`, or `toml_keys` for TOML)
/// hold commands (Kiro, Junie, Copilot, Gemini policies, ...).
fn key_names(
    c: &Compiled<'_>,
    names: &HashSet<&str>,
    node: &Json<'_>,
    key: Option<&str>,
    cx: &mut JsonCx,
    sink: &mut Sink<'_>,
) {
    let route = c
        .def
        .route
        .as_deref()
        .and_then(route_of)
        .unwrap_or(Route::Command);
    let sid = Some(c.def.id.as_str());
    match node {
        Json::Obj(m) => {
            for (k, v) in m {
                key_names(c, names, v, Some(&k.value), cx, sink);
            }
        }
        Json::Arr(a) => {
            for v in a {
                key_names(c, names, v, key, cx, sink);
            }
        }
        Json::Str(s) if key.is_some_and(|k| names.contains(k)) => {
            cx.consumed.insert(s.span.start);
            let text = strip_glob_suffix(&s.value);
            sink(&routed(text, route, cx.base.origin(s), None, None, sid));
        }
        _ => {}
    }
}

/// Every string leaf with its member name as a config key.
fn config_keys(node: &Json<'_>, key: Option<&str>, cx: &mut JsonCx, sink: &mut Sink<'_>) {
    match node {
        Json::Obj(m) => {
            for (k, v) in m {
                config_keys(v, Some(&k.value), cx, sink);
            }
        }
        Json::Arr(a) => {
            for v in a {
                config_keys(v, key, cx, sink);
            }
        }
        // Leaves a structure already routed are not analyzed twice; the
        // engine runs the regex rules on ConfigKey values, so the text pass
        // skips these leaves too.
        Json::Str(s) if !cx.consumed.contains(&s.span.start) => {
            if let Some(k) = key {
                cx.consumed.insert(s.span.start);
                sink(&routed(
                    &*s.value,
                    Route::ConfigKey,
                    cx.base.origin(s),
                    Some(k),
                    None,
                    None,
                ));
            }
        }
        _ => {}
    }
}

/// String values no structure routed go through the regex rules as text.
fn unconsumed(node: &Json<'_>, cx: &JsonCx, sink: &mut Sink<'_>) {
    match node {
        Json::Obj(m) => m.iter().for_each(|(_, v)| unconsumed(v, cx, sink)),
        Json::Arr(a) => a.iter().for_each(|v| unconsumed(v, cx, sink)),
        Json::Str(s) if !cx.consumed.contains(&s.span.start) => {
            sink(&routed(
                &*s.value,
                Route::Text,
                cx.base.origin(s),
                None,
                None,
                None,
            ));
        }
        _ => {}
    }
}

fn is_memory_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.contains("memory") || p.contains("memories")
}

/// The string literals in a Starlark/Python list body (`"a", 'b'`).
fn python_strings(list: &str) -> Vec<String> {
    let b = list.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let q = b[i];
        if q != b'"' && q != b'\'' {
            i += 1;
            continue;
        }
        i += 1;
        let mut s = String::new();
        let mut run = i;
        while i < b.len() && b[i] != q {
            if b[i] == b'\\' && i + 1 < b.len() {
                s.push_str(&list[run..i]);
                let e = b[i + 1];
                match e {
                    b'n' => s.push('\n'),
                    b't' => s.push('\t'),
                    b'\\' | b'"' | b'\'' => s.push(e as char),
                    _ => {
                        // Unknown escape: keep it verbatim (may be multi-byte).
                        i += 1;
                        run = i - 1;
                        continue;
                    }
                }
                i += 2;
                run = i;
                continue;
            }
            i += 1;
        }
        s.push_str(&list[run..i.min(b.len())]);
        out.push(s);
        i += 1; // closing quote
    }
    out
}

/// The command line behind a `/^...$/` key that only escapes regex
/// metacharacters (VS Code's `escapeRegExpCharacters`), else `None`: a key
/// with real regex syntax (`\b`, groups, alternation) is a pattern, not a
/// command someone ran.
fn literal_regex_command(key: &str) -> Option<String> {
    const META: &[u8] = b"\\{}*+?|^$.[]()";
    let body = key.strip_prefix("/^")?.strip_suffix("$/")?;
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some(e) if e.is_ascii() && META.contains(&(e as u8)) => out.push(e),
                _ => return None,
            },
            c if c.is_ascii() && META.contains(&(c as u8)) => return None,
            c => out.push(c),
        }
    }
    (!out.trim().is_empty()).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_command_line_regex_keys() {
        assert_eq!(
            literal_regex_command(r"/^mysql -h db\.test -pX shop$/").as_deref(),
            Some("mysql -h db.test -pX shop")
        );
        assert_eq!(
            literal_regex_command(r"/^echo \(a\) \$HOME$/").as_deref(),
            Some("echo (a) $HOME")
        );
        assert_eq!(literal_regex_command(r"/^git (status|diff)\b/"), None);
        assert_eq!(literal_regex_command(r"/^git status\b$/"), None);
        assert_eq!(literal_regex_command(r"/^ls .*$/"), None);
        assert_eq!(literal_regex_command("/^$/"), None);
        assert_eq!(literal_regex_command("/git/"), None);
    }

    #[test]
    fn config_key_leaves_are_routed_once() {
        let spec = Spec::embedded().unwrap();
        let ex = crate::Extractors::new(&spec).unwrap();
        let path = "h/.cline/data/secrets.json";
        let plan = ex.plan(path).unwrap();
        assert!(plan.uses_analyzer("config_key"));
        let text = r#"{"apiKey": "k-1", "nested": {"list": ["a", "b"]}}"#;
        let mut routes = Vec::new();
        ex.extract(&plan, path, text, &mut |r| {
            routes.push((r.route, r.text.to_string()));
        });
        assert_eq!(
            routes,
            [
                (Route::ConfigKey, "k-1".into()),
                (Route::ConfigKey, "a".into()),
                (Route::ConfigKey, "b".into()),
            ]
        );
    }

    #[test]
    fn python_string_list() {
        assert_eq!(
            python_strings(r#""mysql", "-pX", 'a b', "q\"x", "u\é""#),
            ["mysql", "-pX", "a b", "q\"x", "u\\é"]
        );
        assert_eq!(python_strings("\"unterminated"), ["unterminated"]);
        assert!(python_strings("").is_empty());
    }
}
