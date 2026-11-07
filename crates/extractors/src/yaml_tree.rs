//! YAML documents as span-aware [`Json`] trees, so agent structures
//! (`yaml_roots`, `key_names`, MCP `per_server` paths) run on the same code
//! as JSON. Built from the event parser that `serde-saphyr` re-exports
//! (`granit-parser`), which reports byte offsets for every node.
//!
//! - Every document of a stream is returned.
//! - Plain `null`/`~`/booleans/numbers become [`Json::Scalar`]; every other
//!   scalar is a string. Mapping keys are always strings; values under
//!   non-scalar keys are dropped.
//! - Aliases are not expanded (they become scalars), so alias bombs cost
//!   nothing; nesting deeper than [`MAX_DEPTH`] is an error.

use std::ops::Range;

use serde_saphyr::granit_parser::{Event, Parser, ScalarStyle, Span};

use crate::json::{Json, JsonStr, MAX_DEPTH, ParseError};

enum Frame<'a> {
    Seq(Vec<Json<'a>>),
    /// Members, and the state of the next member: `None` = expecting a key,
    /// `Some(Some(k))` = key read, `Some(None)` = non-scalar key (value dropped).
    Map(Vec<(JsonStr<'a>, Json<'a>)>, Option<Option<JsonStr<'a>>>),
}

/// Parse a YAML stream. Errors carry no input text.
pub fn parse(src: &str) -> Result<Vec<Json<'_>>, ParseError> {
    let mut docs = Vec::new();
    let mut stack: Vec<Frame<'_>> = Vec::new();
    for ev in Parser::new_from_str(src) {
        let (ev, span) = ev.map_err(|e| ParseError {
            offset: e.marker().byte_offset().unwrap_or(0),
            reason: "invalid YAML",
        })?;
        let range = byte_range(src, &span);
        let node = match ev {
            Event::Scalar(value, style, _, _) => {
                if let Some(Frame::Map(_, pending @ None)) = stack.last_mut() {
                    *pending = Some(Some(JsonStr::from_foreign(src, value, range)));
                    continue;
                }
                if style == ScalarStyle::Plain && is_plain_non_string(&value) {
                    Json::Scalar(range)
                } else {
                    Json::Str(JsonStr::from_foreign(src, value, range))
                }
            }
            Event::Alias(_) | Event::UnresolvedAlias(_) => Json::Scalar(range),
            Event::SequenceStart(..) | Event::MappingStart(..) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(ParseError {
                        offset: range.start,
                        reason: "nesting too deep",
                    });
                }
                stack.push(if matches!(ev, Event::SequenceStart(..)) {
                    Frame::Seq(Vec::new())
                } else {
                    Frame::Map(Vec::new(), None)
                });
                continue;
            }
            Event::SequenceEnd | Event::MappingEnd => match stack.pop() {
                Some(Frame::Seq(items)) => Json::Arr(items),
                Some(Frame::Map(members, _)) => Json::Obj(members),
                None => continue,
            },
            _ => continue, // stream/document markers, anchors, comments
        };
        match stack.last_mut() {
            None => docs.push(node),
            Some(Frame::Seq(items)) => items.push(node),
            Some(Frame::Map(members, pending)) => match pending.take() {
                Some(Some(k)) => members.push((k, node)),
                Some(None) => {}
                None => *pending = Some(None), // a collection used as a key
            },
        }
    }
    Ok(docs)
}

fn byte_range(src: &str, span: &Span) -> Range<usize> {
    let s = span.start.byte_offset().unwrap_or(0).min(src.len());
    let e = span.end.byte_offset().unwrap_or(s).clamp(s, src.len());
    s..e
}

/// YAML 1.2 core schema non-strings (plain style only).
fn is_plain_non_string(v: &str) -> bool {
    matches!(
        v,
        "" | "~"
            | "null"
            | "Null"
            | "NULL"
            | "true"
            | "True"
            | "TRUE"
            | "false"
            | "False"
            | "FALSE"
    ) || v.parse::<f64>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentleaks_core::TextOrigin;

    #[test]
    fn mcp_servers_with_exact_spans() {
        let src = "name: cfg\nmcpServers:\n  - name: db\n    command: mysql\n    args: [\"-uroot\", '-pZq8vLm']\n    env:\n      DB_PASSWORD: \"Rk7\\x41wPq\"\n      PORT: 5432\n";
        let docs = parse(src).unwrap();
        assert_eq!(docs.len(), 1);
        let servers = docs[0].get("mcpServers").unwrap();
        let Json::Arr(list) = servers else { panic!() };
        let db = &list[0];
        assert_eq!(db.get("command").and_then(Json::as_str), Some("mysql"));
        let Some(Json::Arr(args)) = db.get("args") else {
            panic!()
        };
        for a in args {
            let Json::Str(s) = a else { panic!() };
            let TextOrigin::Raw { start } = s.origin(0) else {
                panic!("plain/quoted values map exactly")
            };
            assert_eq!(&src[start..start + s.value.len()], s.value);
        }
        let env = db.get("env").unwrap();
        let Some(Json::Str(pw)) = env.get("DB_PASSWORD") else {
            panic!()
        };
        assert_eq!(pw.value, "Rk7AwPq");
        assert!(matches!(pw.origin(0), TextOrigin::Decoded { .. }));
        assert!(matches!(env.get("PORT"), Some(Json::Scalar(_))));
    }

    #[test]
    fn streams_aliases_and_errors() {
        let docs = parse("a: &x [1, 2]\nb: *x\n---\nc: d\n").unwrap();
        assert_eq!(docs.len(), 2);
        assert!(matches!(docs[0].get("b"), Some(Json::Scalar(_))));
        let e = parse("a: \"Secr3t-value\n  b: [").unwrap_err();
        assert!(!format!("{e:?}").contains("Secr3t"));
        let deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
        assert!(parse(&deep).is_err());
        // Collection keys drop their value.
        let docs = parse("? [a, b]\n: c\nd: e\n").unwrap();
        assert_eq!(docs[0].get("d").and_then(Json::as_str), Some("e"));
    }
}
