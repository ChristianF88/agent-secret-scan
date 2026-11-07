//! Transcript records (`agent.transcript.jsonl`): every string leaf is
//! routed by its key, message text gets a scope from the message role, and
//! JSON-encoded string arguments are parsed again.

use std::collections::HashSet;

use agentleaks_core::{Route, TextOrigin};
use agentleaks_spec::AgentStructure;

use crate::json::{self, Json, JsonStr};
use crate::{Sink, routed, shell_join};

pub const USER_MESSAGE: &str = "transcript.user_message";
pub const ASSISTANT_MESSAGE: &str = "transcript.assistant_message";

/// How many times a JSON-encoded string inside a string is parsed again.
const MAX_NESTED: u8 = 2;

/// Where the strings of a parsed JSON document sit in the item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base {
    /// The document starts at this item offset.
    Offset(usize),
    /// The document was decoded from a string literal: everything maps there.
    Fixed(TextOrigin),
}

impl Base {
    pub fn origin(self, s: &JsonStr<'_>) -> TextOrigin {
        match self {
            Base::Offset(b) => s.origin(b),
            Base::Fixed(o) => o,
        }
    }

    /// Origin of a substring of `s` starting at decoded offset `at`.
    pub fn sub_origin(self, s: &JsonStr<'_>, at: usize) -> TextOrigin {
        match self.origin(s) {
            TextOrigin::Raw { start } => TextOrigin::Raw { start: start + at },
            o => o,
        }
    }

    /// Origin of text decoded from the document byte range `start..end`.
    pub fn range(self, start: usize, end: usize) -> TextOrigin {
        match self {
            Base::Offset(b) => TextOrigin::Decoded {
                start: b + start,
                end: b + end,
            },
            Base::Fixed(o) => o,
        }
    }

    /// Base for a JSON document decoded from the string literal `s`.
    fn nested(self, s: &JsonStr<'_>) -> Base {
        match (self, &s.value) {
            (Base::Offset(b), std::borrow::Cow::Borrowed(_)) => Base::Offset(b + s.span.start + 1),
            _ => Base::Fixed(self.origin(s)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyRoute {
    Command,
    Url,
    Text,
}

/// `route_by_key` of a transcript structure.
#[derive(Debug)]
pub struct KeyRoutes<'s> {
    command: HashSet<&'s str>,
    url: HashSet<&'s str>,
    env: HashSet<&'s str>,
    text: HashSet<&'s str>,
    json_string_arguments: bool,
}

impl<'s> KeyRoutes<'s> {
    pub fn compile(def: &'s AgentStructure) -> Option<Self> {
        if def.route_by_key.is_empty() {
            return None;
        }
        // `input.command` is matched by its last component.
        let set = |r: &str| -> HashSet<&'s str> {
            def.route_by_key
                .get(r)
                .into_iter()
                .flatten()
                .map(|k| k.rsplit('.').next().unwrap_or(k))
                .collect()
        };
        Some(KeyRoutes {
            command: set("command"),
            url: set("url"),
            env: set("env"),
            text: set("text"),
            json_string_arguments: def.json_string_arguments,
        })
    }

    fn of(&self, key: &str) -> Option<KeyRoute> {
        if self.command.contains(key) {
            Some(KeyRoute::Command)
        } else if self.url.contains(key) {
            Some(KeyRoute::Url)
        } else if self.text.contains(key) {
            Some(KeyRoute::Text)
        } else {
            None
        }
    }
}

/// Route every string leaf of one record.
pub fn walk(
    kr: &KeyRoutes<'_>,
    root: &Json<'_>,
    base: Base,
    structure: Option<&str>,
    sink: &mut Sink<'_>,
) {
    let mut w = Walker {
        kr,
        structure,
        sink,
        nested: 0,
    };
    w.node(root, None, None, None, base);
}

struct Walker<'k, 'x, 'y> {
    kr: &'k KeyRoutes<'k>,
    structure: Option<&'k str>,
    sink: &'x mut Sink<'y>,
    nested: u8,
}

impl Walker<'_, '_, '_> {
    fn node(
        &mut self,
        n: &Json<'_>,
        key: Option<&str>,
        parent_key: Option<&str>,
        scope: Option<&'static str>,
        base: Base,
    ) {
        match n {
            Json::Obj(members) => {
                let scope = message_scope(n).unwrap_or(scope);
                for (k, v) in members {
                    self.node(v, Some(&k.value), key, scope, base);
                }
            }
            Json::Arr(items) => {
                if key.is_some_and(|k| self.kr.of(k) == Some(KeyRoute::Command))
                    && let Some(argv) = all_strings(items)
                    && let (Some(first), Some(last)) = (argv.first(), argv.last())
                {
                    let joined = shell_join(argv.iter().map(|s| &*s.value));
                    let origin = match base {
                        Base::Offset(_) => base.range(first.span.start, last.span.end),
                        Base::Fixed(o) => o,
                    };
                    (self.sink)(&routed(
                        joined,
                        Route::CommandArgv,
                        origin,
                        None,
                        None,
                        self.structure,
                    ));
                    return;
                }
                for v in items {
                    self.node(v, key, parent_key, scope, base);
                }
            }
            Json::Str(s) => self.leaf(s, key, parent_key, scope, base),
            Json::Scalar(_) => {}
        }
    }

    fn leaf(
        &mut self,
        s: &JsonStr<'_>,
        key: Option<&str>,
        parent_key: Option<&str>,
        scope: Option<&'static str>,
        base: Base,
    ) {
        if self.kr.json_string_arguments
            && self.nested < MAX_NESTED
            && json::looks_like_json(&s.value)
            && let Ok(inner) = json::parse(&s.value)
        {
            self.nested += 1;
            self.node(&inner, key, parent_key, scope, base.nested(s));
            self.nested -= 1;
            return;
        }
        let origin = base.origin(s);
        let sid = self.structure;
        let r = if parent_key.is_some_and(|p| self.kr.env.contains(p)) {
            routed(&*s.value, Route::Env, origin, key, None, sid)
        } else {
            match key.and_then(|k| self.kr.of(k)) {
                Some(KeyRoute::Command) => {
                    routed(&*s.value, Route::Command, origin, None, None, sid)
                }
                Some(KeyRoute::Url) => routed(&*s.value, Route::Url, origin, None, None, sid),
                Some(KeyRoute::Text) => routed(&*s.value, Route::Text, origin, None, scope, sid),
                None => routed(&*s.value, Route::Text, origin, None, None, sid),
            }
        };
        (self.sink)(&r);
    }
}

fn all_strings<'t, 'a>(items: &'t [Json<'a>]) -> Option<Vec<&'t JsonStr<'a>>> {
    if items.is_empty() {
        return None;
    }
    items
        .iter()
        .map(|i| match i {
            Json::Str(s) => Some(s),
            _ => None,
        })
        .collect()
}

/// Scope change at an object: message role, or none inside tool calls and
/// tool output (tool output is not something the user said).
fn message_scope(obj: &Json<'_>) -> Option<Option<&'static str>> {
    if let Some(t) = obj.get("type").and_then(Json::as_str) {
        let t = t.as_bytes();
        let starts =
            |p: &str| t.len() >= p.len() && t[..p.len()].eq_ignore_ascii_case(p.as_bytes());
        let ends = |p: &str| {
            t.len() >= p.len() && t[t.len() - p.len()..].eq_ignore_ascii_case(p.as_bytes())
        };
        let has = |p: &str| {
            t.windows(p.len())
                .any(|w| w.eq_ignore_ascii_case(p.as_bytes()))
        };
        if starts("tool") || starts("function") || ends("_output") || has("tool_") {
            return Some(None);
        }
    }
    let role = obj.get("role").and_then(Json::as_str)?;
    let is = |names: &[&str]| names.iter().any(|n| role.eq_ignore_ascii_case(n));
    Some(if is(&["user", "human"]) {
        Some(USER_MESSAGE)
    } else if is(&["assistant", "model", "ai", "bot"]) {
        Some(ASSISTANT_MESSAGE)
    } else {
        None
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentleaks_spec::Spec;

    /// (route, text, scope, name, origin)
    type Out = (Route, String, Option<String>, Option<String>, TextOrigin);

    fn run(line: &str) -> Vec<Out> {
        let spec = Spec::embedded().unwrap();
        let def = spec
            .agent_structures
            .iter()
            .find(|s| s.id == "agent.transcript.jsonl")
            .unwrap();
        let kr = KeyRoutes::compile(def).unwrap();
        let root = json::parse(line).unwrap();
        let mut out = Vec::new();
        walk(&kr, &root, Base::Offset(100), None, &mut |r| {
            out.push((
                r.route,
                r.text.to_string(),
                r.scope.map(str::to_owned),
                r.name.as_deref().map(str::to_owned),
                r.origin,
            ));
        });
        out
    }

    const USER_LINE: &str = r#"{"type":"user","message":{"role":"user","content":"hi there"}}"#;

    #[test]
    fn scopes_from_roles() {
        let out = run(USER_LINE);
        assert!(out.contains(&(
            Route::Text,
            "hi there".into(),
            Some(USER_MESSAGE.into()),
            None,
            TextOrigin::Raw {
                start: 100 + USER_LINE.find("hi there").unwrap()
            }
        )));
        let out = run(
            r#"{"message":{"role":"user","content":[{"type":"tool_result","content":"A=b"}]}}"#,
        );
        let a = out.iter().find(|o| o.1 == "A=b").unwrap();
        assert_eq!(a.2, None, "tool output has no message scope");
        let out = run(r#"{"role":"assistant","content":[{"type":"text","text":"ok"}]}"#);
        let ok = out.iter().find(|o| o.1 == "ok").unwrap();
        assert_eq!(ok.2.as_deref(), Some(ASSISTANT_MESSAGE));
    }

    #[test]
    fn routes_by_key_and_reparses_arguments() {
        let out = run(
            r#"{"type":"function_call","arguments":"{\"cmd\":[\"mysql\",\"-pX9\"],\"env\":{\"DB_PASSWORD\":\"v\"}}"}"#,
        );
        let argv = out.iter().find(|o| o.0 == Route::CommandArgv).unwrap();
        assert_eq!(argv.1, "mysql -pX9");
        assert!(matches!(argv.4, TextOrigin::Decoded { start: 136, .. }));
        let env = out.iter().find(|o| o.0 == Route::Env).unwrap();
        assert_eq!(env.3.as_deref(), Some("DB_PASSWORD"));
        let out = run(r#"{"input":{"command":"ls -la","url":"https://x"}}"#);
        assert_eq!(out[0].0, Route::Command);
        assert_eq!(out[1].0, Route::Url);
    }
}
