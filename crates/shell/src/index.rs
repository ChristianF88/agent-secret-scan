//! Lookup tables built once from catalogue sections 3 (`shell_semantics`) and
//! 4 (`cli_tools`).

use std::collections::{HashMap, HashSet};

use agentleaks_spec::{ArgForm, FlagDefault, SinkPayload, SourcePayload, Spec};

/// Longest command name we look up (longer words are never tools).
pub(crate) const NAME_MAX: usize = 64;

/// Normalised command key: basename, without leading `(`/`{`, without
/// `.exe`, ASCII-lower-cased into `buf`. `None` if empty or too long.
pub(crate) fn norm_key<'b>(word: &str, buf: &'b mut [u8; NAME_MAX]) -> Option<&'b str> {
    let w = word.trim_start_matches(['(', '{']);
    let w = w.rsplit(['/', '\\']).next().unwrap_or(w);
    let w = match w.len().checked_sub(4) {
        Some(k) if w.is_char_boundary(k) && w[k..].eq_ignore_ascii_case(".exe") => &w[..k],
        _ => w,
    };
    if w.is_empty() {
        return None;
    }
    let out = buf.get_mut(..w.len())?;
    out.copy_from_slice(w.as_bytes());
    out.make_ascii_lowercase();
    std::str::from_utf8(out).ok()
}

/// Owned normalised key (index building only).
fn key(word: &str) -> Option<String> {
    let mut buf = [0u8; NAME_MAX];
    norm_key(word, &mut buf).map(str::to_owned)
}

/// Words of a catalogue entry, without a trailing `(note)`.
fn entry_words(entry: &str) -> Vec<String> {
    let e = entry.split(" (").next().unwrap_or(entry);
    e.split_whitespace().map(str::to_owned).collect()
}

/// `[first, rest...]` with the first word normalised and the rest kept.
fn cmd_words(entry: &str) -> Option<(String, Vec<String>)> {
    let mut w = entry_words(entry);
    if w.is_empty() {
        return None;
    }
    let first = key(&w.remove(0))?;
    Some((first, w))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StrMode {
    /// The string follows a flag (`bash -c`).
    Flag,
    /// The command follows the host (`ssh host cmd`).
    AfterHost,
    /// All remaining arguments (`eval`).
    All,
}

#[derive(Debug)]
pub(crate) struct StrArg {
    /// Command alternatives: (first word key, further words).
    pub cmd: Vec<(String, Vec<String>)>,
    pub flags: Vec<String>,
    pub mode: StrMode,
    /// Subcommand alternatives (`send-keys`, `-X stuff`).
    pub sub: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct AfterDd {
    pub cmd: String,
    /// Subcommand words joined by spaces (may be empty).
    pub sub: String,
    /// `vagrant ssh -c`: the command is the value of this flag instead.
    pub flag: Option<String>,
}

#[derive(Debug)]
pub(crate) struct Container {
    pub cmd: String,
    pub sub: String,
}

#[derive(Debug)]
pub(crate) struct Sink {
    pub cmd: Vec<(String, String)>,
    /// Flag alternatives, each a word sequence.
    pub flags: Vec<Vec<String>>,
    pub arg: Option<String>,
    pub payload: SinkPayload,
}

#[derive(Debug)]
pub(crate) struct Source {
    pub payload: SourcePayload,
    /// Letters of leading option clusters to skip (`echo -ne`).
    pub letters: String,
}

/// Flags of one wrapper command that take a separate value.
#[derive(Debug, Default)]
pub(crate) struct FlagSet {
    pub value: Vec<String>,
    pub boolean: Vec<String>,
    pub unlisted_value: bool,
}

impl FlagSet {
    /// Does flag word `v` consume the next word as its value?
    pub(crate) fn takes_value(&self, v: &str) -> bool {
        if v.contains('=') {
            return false;
        }
        if self.value.iter().any(|f| f == v) {
            return true;
        }
        if self.boolean.iter().any(|f| f == v) {
            return false;
        }
        // Short clusters and attached values are self-contained.
        if !v.starts_with("--") && v.len() > 2 {
            return false;
        }
        self.unlisted_value
    }
}

#[derive(Debug)]
pub(crate) struct KvTool {
    pub cmd: String,
    pub sub: String,
    /// `None`: positional `NAME=VAL` words; `--`: words after `--`.
    pub flag: Option<String>,
}

#[derive(Debug)]
pub(crate) struct Index {
    /// First word key -> (further words, tool index).
    pub tools: HashMap<String, Vec<(Vec<String>, usize)>>,
    /// Per tool: upper-cased env names (`*` suffix = prefix match).
    pub tool_env: Vec<Vec<String>>,
    /// Per tool: PowerShell-style case-insensitive flags.
    pub tool_ci: Vec<bool>,
    /// Per tool: flags whose next word is their value, not a positional
    /// argument (the tool's own separate-value args plus `value_flags`).
    pub tool_value_flags: Vec<Vec<String>>,
    pub passthrough: HashMap<String, Vec<Vec<String>>>,
    pub string_args: Vec<StrArg>,
    pub after_dd: Vec<AfterDd>,
    pub container: Vec<Container>,
    pub sinks: Vec<Sink>,
    pub sources: HashMap<String, Source>,
    /// Wrapper command key -> its value-taking flags.
    pub value_flags: HashMap<String, FlagSet>,
    pub kv_tools: Vec<KvTool>,
    /// Every command key that is a tool or a wrapper.
    pub known: HashSet<String>,
}

impl Index {
    pub(crate) fn build(spec: &Spec) -> Result<Self, String> {
        let mut ix = Index {
            tools: HashMap::new(),
            tool_env: Vec::new(),
            tool_ci: Vec::new(),
            tool_value_flags: Vec::new(),
            passthrough: HashMap::new(),
            string_args: Vec::new(),
            after_dd: Vec::new(),
            container: Vec::new(),
            sinks: Vec::new(),
            sources: HashMap::new(),
            value_flags: HashMap::new(),
            kv_tools: Vec::new(),
            known: HashSet::new(),
        };

        for (t, tool) in spec.cli_tools.iter().enumerate() {
            for name in std::iter::once(&tool.tool).chain(&tool.aliases) {
                let Some((first, rest)) = cmd_words(name) else {
                    return Err(format!("cli_tools.{}: empty name or alias", tool.tool));
                };
                ix.known.insert(first.clone());
                let e = ix.tools.entry(first).or_default();
                if !e.iter().any(|(r, i)| *i == t && *r == rest) {
                    e.push((rest, t));
                }
            }
            ix.tool_env.push(
                tool.env
                    .iter()
                    .filter_map(|e| entry_words(e).into_iter().next())
                    .map(|e| e.to_ascii_uppercase())
                    .collect(),
            );
            let first = tool.tool.chars().next().unwrap_or('a');
            ix.tool_ci
                .push(first.is_ascii_uppercase() && tool.tool.contains('-'));
        }

        let w = &spec.shell.wrappers;
        for p in &w.passthrough {
            let (first, mut rest) = cmd_words(p).ok_or("empty passthrough wrapper")?;
            // `op run --`: options may sit before `--`; the inner-command
            // search stops at `--` anyway.
            if rest.last().is_some_and(|l| l == "--") {
                rest.pop();
            }
            ix.known.insert(first.clone());
            ix.passthrough.entry(first).or_default().push(rest);
        }
        for s in &w.string_arg {
            let mode = match (s.arg.as_deref(), &s.flag) {
                (Some("after host"), _) => StrMode::AfterHost,
                (Some("all"), _) => StrMode::All,
                (None, Some(_)) => StrMode::Flag,
                (a, f) => {
                    return Err(format!(
                        "shell_semantics.wrappers.string_arg {:?}: unsupported arg {a:?} / flag {f:?}",
                        s.cmd
                    ));
                }
            };
            let cmd: Vec<_> = s.cmd.iter().filter_map(|c| cmd_words(c)).collect();
            for (f, _) in &cmd {
                ix.known.insert(f.clone());
            }
            ix.string_args.push(StrArg {
                cmd,
                flags: s
                    .flag
                    .as_ref()
                    .map(|f| f.as_slice().to_vec())
                    .unwrap_or_default(),
                mode,
                sub: s
                    .subcommand
                    .as_ref()
                    .map(|f| f.as_slice().to_vec())
                    .unwrap_or_default(),
            });
        }
        for e in &w.after_double_dash {
            let (first, mut rest) = cmd_words(e).ok_or("empty after_double_dash entry")?;
            let flag = match rest.last() {
                Some(l) if l.starts_with('-') => rest.pop(),
                _ => None,
            };
            ix.known.insert(first.clone());
            ix.after_dd.push(AfterDd {
                cmd: first,
                sub: rest.join(" "),
                flag,
            });
        }
        for e in &w.container_exec_after_container_name {
            let (first, rest) = cmd_words(e).ok_or("empty container_exec entry")?;
            ix.known.insert(first.clone());
            ix.container.push(Container {
                cmd: first,
                sub: rest.join(" "),
            });
        }

        for vf in &spec.shell.value_flags {
            for c in &vf.cmd {
                let k = key(c).ok_or("empty value_flags cmd")?;
                let set = ix.value_flags.entry(k).or_default();
                set.value.extend(vf.value.iter().cloned());
                set.boolean.extend(vf.boolean.iter().cloned());
                set.unlisted_value |= vf.unlisted == FlagDefault::Value;
            }
        }
        // A passthrough wrapper's own separate-value credential flags
        // (`sshpass -p x scp ...`).
        let wrappers: Vec<String> = ix.passthrough.keys().cloned().collect();
        for w in wrappers {
            let Some(entries) = ix.tools.get(&w) else {
                continue;
            };
            let set = ix.value_flags.entry(w.clone()).or_default();
            for (rest, t) in entries {
                if !rest.is_empty() {
                    continue;
                }
                for a in &spec.cli_tools[*t].args {
                    let separate = matches!(
                        a.form,
                        Some(
                            ArgForm::Separate
                                | ArgForm::AttachedOrSeparate
                                | ArgForm::EqualsOrSeparate
                        )
                    );
                    if let Some(f) = a.flag.as_ref().filter(|_| separate)
                        && a.subcommand.is_none()
                        && !set.value.contains(f)
                    {
                        set.value.push(f.clone());
                    }
                }
            }
        }

        for tool in &spec.cli_tools {
            let mut v: Vec<String> = Vec::new();
            for a in &tool.args {
                let separate = matches!(
                    a.form,
                    Some(
                        ArgForm::Separate | ArgForm::AttachedOrSeparate | ArgForm::EqualsOrSeparate
                    )
                );
                if let Some(f) = a.flag.as_ref().filter(|f| separate && f.starts_with('-'))
                    && !v.contains(f)
                {
                    v.push(f.clone());
                }
            }
            for name in std::iter::once(&tool.tool).chain(&tool.aliases) {
                if let Some(set) = cmd_words(name).and_then(|(k, _)| ix.value_flags.get(&k)) {
                    for f in &set.value {
                        if !v.contains(f) {
                            v.push(f.clone());
                        }
                    }
                }
            }
            ix.tool_value_flags.push(v);
        }

        for s in &spec.shell.stdin_sources {
            let k = key(&s.cmd).ok_or("empty stdin_sources cmd")?;
            let letters = s.flags.iter().filter_map(|f| f.strip_prefix('-')).collect();
            ix.sources.insert(
                k,
                Source {
                    payload: s.payload,
                    letters,
                },
            );
        }
        for s in &spec.shell.stdin_sinks {
            let cmd: Vec<_> = s
                .cmd
                .iter()
                .filter_map(|c| cmd_words(c))
                .map(|(f, r)| (f, r.join(" ")))
                .collect();
            let flags: Vec<Vec<String>> = s
                .flag
                .as_ref()
                .map(|f| f.as_slice().iter().map(|x| entry_words(x)).collect())
                .unwrap_or_default();
            ix.sinks.push(Sink {
                payload: s.payload,
                cmd,
                flags,
                arg: s.arg.clone(),
            });
        }
        for e in &spec.shell.keyvalue_arg_tools {
            let words = entry_words(e);
            let split = words
                .iter()
                .position(|w| w.starts_with('-'))
                .unwrap_or(words.len());
            let Some(first) = words.first().and_then(|f| key(f)) else {
                return Err("empty keyvalue_arg_tools entry".into());
            };
            ix.kv_tools.push(KvTool {
                cmd: first,
                sub: words[1..split.max(1)].join(" "),
                flag: words.get(split).cloned(),
            });
        }
        Ok(ix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalises_command_names() {
        let mut b = [0u8; NAME_MAX];
        assert_eq!(norm_key("/usr/bin/mysql", &mut b), Some("mysql"));
        let mut b = [0u8; NAME_MAX];
        assert_eq!(norm_key("./mvnw", &mut b), Some("mvnw"));
        let mut b = [0u8; NAME_MAX];
        assert_eq!(
            norm_key("C:\\Tools\\PsExec64.EXE", &mut b),
            Some("psexec64")
        );
        let mut b = [0u8; NAME_MAX];
        assert_eq!(norm_key("(cd", &mut b), Some("cd"));
        let mut b = [0u8; NAME_MAX];
        assert_eq!(norm_key(".exe", &mut b), None);
        let mut b = [0u8; NAME_MAX];
        assert_eq!(norm_key("é.exe", &mut b), Some("é"));
    }

    #[test]
    fn builds_from_embedded_catalogue() {
        let spec = Spec::embedded().unwrap();
        let ix = Index::build(&spec).unwrap();
        assert!(ix.tools.contains_key("mysql"));
        assert!(ix.tools["clickhouse"].iter().any(|(r, _)| r == &["client"]));
        assert!(ix.tools.contains_key("isql")); // `isql (firebird)`
        assert!(ix.passthrough["op"].contains(&vec!["run".to_owned()]));
        assert!(
            ix.after_dd
                .iter()
                .any(|a| a.cmd == "vagrant" && a.flag.as_deref() == Some("-c"))
        );
        assert!(ix.sources.contains_key("echo"));
        assert_eq!(ix.sources["cat"].payload, SourcePayload::Stdin);
        assert_eq!(ix.sources["echo"].letters, "neE");
        assert!(ix.sinks.iter().any(|s| s.payload == SinkPayload::Userpass));
        assert!(ix.sinks.iter().any(|s| s.payload == SinkPayload::Sql));
        // ssh: listed letters; containers: unlisted long flags take values.
        let ssh = &ix.value_flags["ssh"];
        assert!(ssh.takes_value("-p") && !ssh.takes_value("-t") && !ssh.takes_value("-p22"));
        let docker = &ix.value_flags["docker"];
        assert!(docker.takes_value("--network") && !docker.takes_value("--rm"));
        assert!(!docker.takes_value("-it") && !docker.takes_value("--env=X"));
        // sshpass: `-p` from its own catalogue entry.
        assert!(ix.value_flags["sshpass"].takes_value("-p"));
        assert!(
            ix.kv_tools
                .iter()
                .any(|k| k.cmd == "make" && k.flag.is_none())
        );
    }
}
