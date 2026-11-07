//! TOML documents as a span-aware [`Json`] tree, so agent structures
//! (`toml_roots`, `toml_keys`, MCP `per_server` paths) run on the same code
//! as JSON. Uses the `toml` crate's spanned parser.
//!
//! - Tables become objects, arrays (and arrays of tables) arrays; numbers,
//!   booleans and datetimes become [`Json::Scalar`].
//! - Members are kept in file order.
//! - Nesting deeper than [`MAX_DEPTH`] is cut off (the deeper part becomes a
//!   scalar); the raw-text pass still sees it.

use std::ops::Range;

use toml::Spanned;
use toml::de::{DeTable, DeValue};

use crate::json::{Json, JsonStr, MAX_DEPTH, ParseError};

/// Parse one TOML document. Errors carry no input text.
pub fn parse(src: &str) -> Result<Json<'_>, ParseError> {
    let doc = DeTable::parse(src).map_err(|e| ParseError {
        offset: e.span().map_or(0, |s| s.start),
        reason: "invalid TOML",
    })?;
    Ok(table(src, doc.into_inner(), 0))
}

fn table<'a>(src: &'a str, t: DeTable<'a>, depth: usize) -> Json<'a> {
    let mut members: Vec<(JsonStr<'a>, Json<'a>)> = t
        .into_iter()
        .map(|(k, v)| {
            let ks = k.span();
            (
                JsonStr::from_foreign(src, k.into_inner(), ks),
                value(src, v, depth + 1),
            )
        })
        .collect();
    members.sort_by_key(|(k, _)| k.span.start);
    Json::Obj(members)
}

fn value<'a>(src: &'a str, v: Spanned<DeValue<'a>>, depth: usize) -> Json<'a> {
    let span: Range<usize> = v.span();
    if depth > MAX_DEPTH {
        return Json::Scalar(span);
    }
    match v.into_inner() {
        DeValue::String(s) => Json::Str(JsonStr::from_foreign(src, s, span)),
        DeValue::Array(a) => Json::Arr(a.into_iter().map(|x| value(src, x, depth + 1)).collect()),
        DeValue::Table(t) => table(src, t, depth),
        _ => Json::Scalar(span),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentleaks_core::TextOrigin;

    fn strings<'a>(j: &'a Json<'a>, out: &mut Vec<(&'a str, TextOrigin)>) {
        match j {
            Json::Str(s) => out.push((&s.value, s.origin(0))),
            Json::Arr(a) => a.iter().for_each(|x| strings(x, out)),
            Json::Obj(m) => m.iter().for_each(|(_, v)| strings(v, out)),
            Json::Scalar(_) => {}
        }
    }

    #[test]
    fn codex_mcp_servers_with_spans() {
        let src = "model = \"o4\"\n\n[mcp_servers.db]\ncommand = \"mysql\"\nargs = ['-uroot', \"-p\\u0041b\"]\nenv = { DB_PASSWORD = \"Zq8-vLm\" }\nport = 5\n";
        let root = parse(src).unwrap();
        let db = root.get("mcp_servers").and_then(|m| m.get("db")).unwrap();
        assert_eq!(db.get("command").and_then(Json::as_str), Some("mysql"));
        let mut out = Vec::new();
        strings(db, &mut out);
        for (v, o) in &out {
            match *o {
                // Byte-identical values map exactly.
                TextOrigin::Raw { start } => assert_eq!(&src[start..start + v.len()], *v),
                // Escaped values map to their literal.
                TextOrigin::Decoded { start, end } => {
                    assert_eq!(*v, "-pAb");
                    assert_eq!(&src[start..end], "\"-p\\u0041b\"");
                }
            }
        }
        assert_eq!(out.len(), 4, "{out:?}");
        // File order, not key order.
        let Json::Obj(m) = &root else { panic!() };
        assert_eq!(m[0].0.value, "model");
    }

    #[test]
    fn invalid_toml_is_an_error_without_input() {
        let e = parse("a = \"Secr3t-value\nb = [").unwrap_err();
        assert!(!format!("{e:?}").contains("Secr3t"));
    }

    #[test]
    fn deep_nesting_is_cut_off() {
        let src = format!("a = {}1{}", "[".repeat(300), "]".repeat(300));
        // Either the parser refuses it or the tree is cut off; never a panic.
        let _ = parse(&src);
    }
}
