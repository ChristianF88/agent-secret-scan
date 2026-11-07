//! Markdown (chat exports, memory and instruction files): fenced code
//! blocks are routed by language (`route_code_fences`); everything else is
//! prose with the caller's scope.

use agentleaks_core::{Route, TextOrigin};
use agentleaks_spec::{AgentStructure, SpecRegex};

use crate::{Sink, route_of, routed};

/// `route_code_fences` and `strip_prompt_prefix` of a structure.
#[derive(Debug)]
pub struct Fences<'s> {
    /// language (lower-case) -> catalogue route name
    map: &'s std::collections::BTreeMap<String, String>,
    prompt: Option<&'s SpecRegex>,
}

impl<'s> Fences<'s> {
    pub fn compile(def: &'s AgentStructure) -> Option<Self> {
        if def.route_code_fences.is_empty() {
            return None;
        }
        Some(Fences {
            map: &def.route_code_fences,
            prompt: def.strip_prompt_prefix.as_ref(),
        })
    }
}

/// Lines of `text` as (start, end-without-newline).
fn lines(text: &str) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut start = 0;
    memchr::memchr_iter(b'\n', text.as_bytes())
        .chain(std::iter::once(text.len()))
        .filter_map(move |nl| {
            if start > text.len() || (nl == text.len() && start == text.len()) {
                return None;
            }
            let s = start;
            start = nl + 1;
            let e = if nl > s && text.as_bytes()[nl - 1] == b'\r' {
                nl - 1
            } else {
                nl
            };
            Some((s, e))
        })
}

/// Start of the line after the one ending at `e` (which excludes `\r\n`).
fn next_line(text: &str, e: usize) -> usize {
    let b = text.as_bytes();
    let skip = match b.get(e) {
        Some(b'\r') if b.get(e + 1) == Some(&b'\n') => 2,
        Some(_) => 1,
        None => 0,
    };
    (e + skip).min(text.len())
}

/// Opening or closing fence: up to 3 spaces, then 3+ backticks or tildes.
fn fence(line: &str) -> Option<(u8, usize, &str)> {
    let t = line.trim_start_matches(' ');
    if line.len() - t.len() > 3 {
        return None;
    }
    let c = *t.as_bytes().first()?;
    if c != b'`' && c != b'~' {
        return None;
    }
    let n = t.bytes().take_while(|&b| b == c).count();
    let info = t[n..].trim();
    // CommonMark: a backtick fence's info string has no backticks, so
    // ```npm ci``` is inline code, not a fence.
    (n >= 3 && !(c == b'`' && info.contains('`'))).then_some((c, n, info))
}

pub fn extract(
    text: &str,
    fences: Option<&Fences<'_>>,
    prose_scope: Option<&str>,
    structure: Option<&str>,
    sink: &mut Sink<'_>,
) {
    let prose = |sink: &mut Sink<'_>, s: usize, e: usize| {
        if text[s..e].trim().is_empty() {
            return;
        }
        sink(&routed(
            &text[s..e],
            Route::Text,
            TextOrigin::Raw { start: s },
            None,
            prose_scope,
            structure,
        ));
    };
    let mut prose_start = 0;
    // (fence char, fence length, language, body start)
    let mut open: Option<(u8, usize, String, usize)> = None;
    for (s, e) in lines(text) {
        let line = &text[s..e];
        match &open {
            None => {
                if let Some((c, n, info)) = fence(line) {
                    prose(sink, prose_start, s);
                    let lang = info
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .trim_matches(['{', '}', '.'])
                        .to_ascii_lowercase();
                    let body = next_line(text, e);
                    open = Some((c, n, lang, body));
                }
            }
            Some((c, n, lang, body)) => {
                if let Some((c2, n2, rest)) = fence(line)
                    && c2 == *c
                    && n2 >= *n
                    && rest.is_empty()
                {
                    code(text, *body, s, lang, fences, prose_scope, structure, sink);
                    open = None;
                    prose_start = next_line(text, e);
                }
            }
        }
    }
    match open {
        Some((_, _, lang, body)) => {
            code(
                text,
                body,
                text.len(),
                &lang,
                fences,
                prose_scope,
                structure,
                sink,
            );
            // An unclosed fence is often a stray marker: keep natural-language
            // rules running on the rest of the file.
            prose(sink, body, text.len());
        }
        None => prose(sink, prose_start, text.len()),
    }
}

#[allow(clippy::too_many_arguments)]
fn code(
    text: &str,
    start: usize,
    end: usize,
    lang: &str,
    fences: Option<&Fences<'_>>,
    prose_scope: Option<&str>,
    structure: Option<&str>,
    sink: &mut Sink<'_>,
) {
    if start >= end {
        return;
    }
    let body = &text[start..end];
    let route_name = fences.and_then(|f| f.map.get(lang)).map(String::as_str);
    let emit = |sink: &mut Sink<'_>, t: &str, at: usize, route: Route, name: Option<&str>| {
        sink(&routed(
            t,
            route,
            TextOrigin::Raw { start: at },
            name,
            None,
            structure,
        ));
    };
    match route_name {
        Some("command_with_prompt") => {
            let prompt = fences.and_then(|f| f.prompt);
            for (s, e) in lines(body) {
                let line = &body[s..e];
                match prompt.and_then(|p| p.find(line)).filter(|m| m.start() == 0) {
                    Some(m) => emit(
                        sink,
                        &line[m.end()..],
                        start + s + m.end(),
                        Route::Command,
                        None,
                    ),
                    None => emit(sink, line, start + s, Route::Text, None),
                }
            }
        }
        Some("env") => {
            for (s, e) in lines(body) {
                let line = &body[s..e];
                match assignment(line, b'=') {
                    Some((name, v)) => {
                        emit(sink, &line[v..], start + s + v, Route::Env, Some(name))
                    }
                    None => emit(sink, line, start + s, Route::Text, None),
                }
            }
        }
        Some("config_key") => {
            for (s, e) in lines(body) {
                let line = &body[s..e];
                if let Some((name, v)) = assignment(line, b':').or_else(|| assignment(line, b'=')) {
                    emit(
                        sink,
                        &line[v..],
                        start + s + v,
                        Route::ConfigKey,
                        Some(name),
                    );
                }
            }
            emit(sink, body, start, Route::Text, None);
        }
        Some(r) => match route_of(r).unwrap_or(Route::Text) {
            // Untyped blocks (`''` -> text) are usually quoted prose.
            Route::Text => sink(&routed(
                body,
                Route::Text,
                TextOrigin::Raw { start },
                None,
                prose_scope,
                structure,
            )),
            route => emit(sink, body, start, route, None),
        },
        None => emit(sink, body, start, Route::Text, None),
    }
}

/// `NAME<sep>value` (also `export NAME=`, `- name:`, `"name":`): the name and
/// the byte offset of the value in `line`.
fn assignment(line: &str, sep: u8) -> Option<(&str, usize)> {
    let t = line.trim_start();
    let t = t.strip_prefix("export ").unwrap_or(t);
    let t = t.strip_prefix("- ").unwrap_or(t).trim_start();
    let quoted = t.starts_with('"');
    let t = if quoted { &t[1..] } else { t };
    let n = t
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || b"_.-".contains(b))
        .count();
    if n == 0 {
        return None;
    }
    let name = &t[..n];
    let mut rest = &t[n..];
    if quoted {
        rest = rest.strip_prefix('"')?;
    }
    let rest = rest.trim_start_matches(' ');
    if rest.as_bytes().first() != Some(&sep) {
        return None;
    }
    let v = rest[1..].trim_start();
    let v = v.trim_end_matches(',').trim_end();
    if v.is_empty() {
        return None;
    }
    let off = v.as_ptr() as usize - line.as_ptr() as usize;
    Some((name, off))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentleaks_spec::Spec;

    fn run(text: &str) -> Vec<(Route, String, Option<String>, usize)> {
        let spec = Spec::embedded().unwrap();
        let def = spec
            .agent_structures
            .iter()
            .find(|s| s.id == "agent.transcript.markdown")
            .unwrap();
        let f = Fences::compile(def).unwrap();
        let mut out = Vec::new();
        extract(text, Some(&f), Some("chat_history"), None, &mut |r| {
            let TextOrigin::Raw { start } = r.origin else {
                panic!()
            };
            assert_eq!(&text[start..start + r.text.len()], &*r.text);
            out.push((
                r.route,
                r.text.to_string(),
                r.scope.map(str::to_owned),
                start,
            ));
        });
        out
    }

    #[test]
    fn fences_and_prose() {
        let t = "hello\n\n```bash\nls -la\n```\nafter\n```console\n$ mysql -pX\noutput\n```\n```env\nexport DB_PASSWORD=v1\n```\n```python\nx = 1\n```\n";
        let out = run(t);
        assert_eq!(
            out[0],
            (
                Route::Text,
                "hello\n\n".into(),
                Some("chat_history".into()),
                0
            )
        );
        assert_eq!(out[1].0, Route::Command);
        assert_eq!(out[1].1, "ls -la\n");
        assert_eq!(out[2].1, "after\n");
        assert_eq!((out[3].0, out[3].1.as_str()), (Route::Command, "mysql -pX"));
        assert_eq!((out[4].0, out[4].1.as_str()), (Route::Text, "output"));
        assert_eq!((out[5].0, out[5].1.as_str()), (Route::Env, "v1"));
        assert_eq!((out[6].0, out[6].2.as_deref()), (Route::Text, None));
    }

    #[test]
    fn unterminated_and_crlf() {
        let out = run("a\r\n```sh\r\necho 1\r\n");
        // Unclosed: routed as code and, for prose rules, as prose too.
        assert!(
            out.iter()
                .any(|o| o.0 == Route::Command && o.1 == "echo 1\r\n")
        );
        assert!(out.iter().any(|o| o.0 == Route::Text
            && o.1 == "echo 1\r\n"
            && o.2.as_deref() == Some("chat_history")));
        run("```");
        run("");
    }

    #[test]
    fn fence_edge_cases() {
        // Inline triple backticks are not a fence: the rest stays prose.
        let out = run("```npm ci``` first.\n\nthe db password is Wint3r2026! ok\n");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].2.as_deref(), Some("chat_history"));
        // Tildes, and a ``` line inside a ~~~ block does not close it.
        let out = run("~~~bash\nls\n```\nmore\n~~~\nafter\n");
        assert_eq!(
            (out[0].0, out[0].1.as_str()),
            (Route::Command, "ls\n```\nmore\n")
        );
        assert_eq!(out[1].1, "after\n");
        // Up to 3 spaces of indent open a fence; 4 do not (indented code).
        let out = run("   ```sh\nls\n   ```\n");
        assert_eq!(out[0].0, Route::Command);
        let out = run("    ```sh\n    ls\n");
        assert_eq!((out.len(), out[0].0), (1, Route::Text));
        // A closing fence must be at least as long as the opener.
        let out = run("````sh\nls\n```\n````\n");
        assert_eq!(out[0].1, "ls\n```\n");
        // Untyped blocks keep the prose scope (quoted credentials).
        let out = run("```\n- username: qa\n- password: Qa2026!\n```\n");
        assert_eq!(out[0].2.as_deref(), Some("chat_history"));
    }

    #[test]
    fn assignments() {
        assert_eq!(
            assignment("  \"password\": \"x\",", b':'),
            Some(("password", 14))
        );
        assert_eq!(assignment("- key: v", b':'), Some(("key", 7)));
        assert_eq!(assignment("no assignment", b'='), None);
    }
}
