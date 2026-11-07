//! The JSONPath subset used by `agent_structures`:
//! `$`, `.key`, `["key"]`, `.*`, `[*]` and `..key` (recursive descent).
//! Paths without a leading `$` are relative (MCP `per_server` entries).

use crate::json::{Json, JsonStr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Seg {
    Key(String),
    /// `.*`: every member value of an object.
    AnyMember,
    /// `[*]`: every element of an array.
    AnyElement,
    /// `..key`: `key` at any depth below.
    Descend(String),
}

/// Compiled path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonPath(pub Vec<Seg>);

impl JsonPath {
    pub fn parse(p: &str) -> Result<Self, String> {
        let mut segs = Vec::new();
        let mut s = p.strip_prefix('$').unwrap_or(p);
        // A relative path starts with a bare key.
        if !s.is_empty() && !s.starts_with(['.', '[']) {
            let end = s.find(['.', '[']).unwrap_or(s.len());
            segs.push(Seg::Key(s[..end].to_owned()));
            s = &s[end..];
        }
        while !s.is_empty() {
            if let Some(rest) = s.strip_prefix("..") {
                let end = rest.find(['.', '[']).unwrap_or(rest.len());
                if end == 0 {
                    return Err(format!("empty key after '..' in {p}"));
                }
                segs.push(Seg::Descend(rest[..end].to_owned()));
                s = &rest[end..];
            } else if let Some(rest) = s.strip_prefix(".*") {
                segs.push(Seg::AnyMember);
                s = rest;
            } else if let Some(rest) = s.strip_prefix('.') {
                let end = rest.find(['.', '[']).unwrap_or(rest.len());
                if end == 0 {
                    return Err(format!("empty key in {p}"));
                }
                segs.push(Seg::Key(rest[..end].to_owned()));
                s = &rest[end..];
            } else if let Some(rest) = s.strip_prefix("[*]") {
                segs.push(Seg::AnyElement);
                s = rest;
            } else if let Some(rest) = s.strip_prefix("[\"") {
                let end = rest
                    .find("\"]")
                    .ok_or_else(|| format!("unterminated [\"...\"] in {p}"))?;
                segs.push(Seg::Key(rest[..end].to_owned()));
                s = &rest[end + 2..];
            } else {
                return Err(format!("unsupported JSONPath syntax in {p}"));
            }
        }
        Ok(JsonPath(segs))
    }

    /// Every node the path selects, with the object key it was found under
    /// (array elements inherit their array's key).
    pub fn select<'t, 'a>(
        &self,
        root: &'t Json<'a>,
        out: &mut Vec<(Option<&'t JsonStr<'a>>, &'t Json<'a>)>,
    ) {
        step(&self.0, None, root, out, 0);
    }
}

fn step<'t, 'a>(
    segs: &[Seg],
    key: Option<&'t JsonStr<'a>>,
    node: &'t Json<'a>,
    out: &mut Vec<(Option<&'t JsonStr<'a>>, &'t Json<'a>)>,
    depth: usize,
) {
    let Some((first, rest)) = segs.split_first() else {
        out.push((key, node));
        return;
    };
    match (first, node) {
        (Seg::Key(k), Json::Obj(m)) => {
            for (mk, v) in m.iter().filter(|(mk, _)| mk.value == k.as_str()) {
                step(rest, Some(mk), v, out, depth);
            }
        }
        (Seg::AnyMember, Json::Obj(m)) => {
            for (mk, v) in m {
                step(rest, Some(mk), v, out, depth);
            }
        }
        (Seg::AnyElement, Json::Arr(a)) => {
            for v in a {
                step(rest, key, v, out, depth);
            }
        }
        (Seg::Descend(k), _) => {
            if depth > crate::json::MAX_DEPTH {
                return;
            }
            match node {
                Json::Obj(m) => {
                    for (mk, v) in m {
                        if mk.value == k.as_str() {
                            step(rest, Some(mk), v, out, depth + 1);
                        }
                        step(segs, Some(mk), v, out, depth + 1);
                    }
                }
                Json::Arr(a) => {
                    for v in a {
                        step(segs, key, v, out, depth + 1);
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    fn sel(path: &str, src: &str) -> Vec<String> {
        let v = parse(src).unwrap();
        let mut out = Vec::new();
        JsonPath::parse(path).unwrap().select(&v, &mut out);
        out.iter()
            .map(|(k, n)| {
                format!(
                    "{}={}",
                    k.map_or("", |k| &k.value),
                    n.as_str().unwrap_or("?")
                )
            })
            .collect()
    }

    #[test]
    fn selects() {
        let src = r#"{"permissions": {"allow": ["a", "b"]}, "env": {"X": "1", "Y": "2"},
            "hooks": {"Pre": [{"hooks": [{"command": "c1"}]}], "command": "c2"},
            "chat.tools.x": {"k": "v"}}"#;
        assert_eq!(sel("$.permissions.allow[*]", src), ["allow=a", "allow=b"]);
        assert_eq!(sel("$.env.*", src), ["X=1", "Y=2"]);
        assert_eq!(sel("$.hooks..command", src), ["command=c1", "command=c2"]);
        assert_eq!(sel(r#"$["chat.tools.x"].k"#, src), ["k=v"]);
        assert_eq!(sel("env.X", src), ["X=1"]);
        assert!(JsonPath::parse("$.a[0]").is_err());
    }
}
