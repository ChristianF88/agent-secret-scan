//! Shell-command analyzer (M1, decision D6): finds credentials in shell
//! commands by position, using the CLI knowledge base in catalogue sections 3
//! (`shell_semantics`) and 4 (`cli_tools`).
//!
//! # Pipeline
//!
//! 1. Glob suffixes of allow rules (`npm test:*`, `git log *`) are stripped.
//! 2. Text that looks like the inside of a JSON string (no bare `"`, but `\"`,
//!    `\\` or `\n` escapes) is JSON-decoded first; spans map back through a
//!    byte table.
//! 3. The [`lexer`] splits the text into simple commands (`&& || ; | |& &`,
//!    newlines) with quoting, heredocs and here-strings.
//! 4. Per command: leading `NAME=value` env prefixes (and arguments of
//!    `export`/`declare`/`typeset`/`local`/`readonly`/`set`), wrapper
//!    recursion (depth limit 4), knowledge-base matching with subcommand
//!    scoping, `keyvalue_arg_tools`, and stdin pipelines.
//!
//! # Rule ids
//!
//! | id | category | what |
//! |---|---|---|
//! | `shell.env-prefix` | `env_assignment` | `PGPASSWORD=x psql`, `export X=y` with a credential name (or a name in the tool's `env` list) |
//! | `shell.cli-arg` | `cli_argument` | a `cli_tools` flag or positional argument (`mysql -pX`, `curl -u u:p`) |
//! | `shell.pattern` | `cli_argument` | a `cli_tools` `pattern` entry (group `secret`) |
//! | `shell.keyvalue-arg` | `cli_argument` | `NAME=VAL` arguments of `keyvalue_arg_tools` (`helm --set db.password=x`) |
//! | `shell.stdin-pipe` | `cli_stdin` | `echo x \| docker login --password-stdin`, here-strings and heredocs into a `stdin_sinks` command |
//!
//! # Semantics worth knowing
//!
//! - Subcommands match the first non-flag word, or the second one when the
//!   first directly follows a flag (`kubectl -n prod create secret`).
//! - `separate` values that start with `-` are taken as the next flag, so
//!   `mongosh -p --host x` (prompt) yields nothing.
//! - Positional password/token/key values of the form `name=...` are skipped
//!   (`vault login -method=userpass username=x`).
//! - A `cli_tools` arg whose `note` starts with `ANY ` treats every `NAME=VAL`
//!   as sensitive regardless of the name (`kubectl create secret
//!   --from-literal`, `vault kv put`), with medium confidence.
//! - Key names are checked whole and by their last `.`/`:`/`/` segment
//!   (`auth.rootPassword`).
//! - Header values: credential header names (`Authorization`, `X-Api-Key`,
//!   ...) report the value after a scheme (`Bearer`, `Basic`, `Token`, ...);
//!   `Cookie` headers and `cookie` args report pairs with credential names;
//!   `body` args report form (`a=b&c=d`) and JSON (`"k": "v"`) pairs with
//!   credential names.
//! - `connect:<syntax>` parsers: `uri` (userinfo), `libpq_keyvalue`
//!   (`password=`, or a URI), `jdbc`, `oracle_userpass` (`user/pass@db`),
//!   `impacket_target`, `cvs_pserver`, `azure_kv` and `ado_net`
//!   (`;`-separated keys ending in password/pwd/key/secret/signature/token),
//!   `sas_url` (`sig=`). Unknown syntaxes yield nothing.
//! - stdin sinks whose `note` mentions `sql_statements` are left to the SQL
//!   rules. `chpasswd` payloads are `user:pass` (secret after `:`).
//! - Spans: exact when the secret is a contiguous unescaped slice of the
//!   input; otherwise the span of the whole enclosing word (or, for strings
//!   recursed into, the whole outer argument).
//!
//! # Not implemented
//!
//! - `sql_statements` bodies and heredoc bodies of SQL clients (regex/SQL
//!   rules run on the same text).
//! - Command substitution `$(..)` is not recursed into.
//! - `env:` lists entries with a `(connect:uri)` note are treated as plain
//!   credential names.
//! - Notes with tool-specific conditions (`ConvertTo-SecureString` only with
//!   `-AsPlainText`, `pulumi config set` without `--secret`, SNMP `public`
//!   as default credential) are not modelled.

pub mod lexer;
pub mod values;

mod index;

use std::cell::RefCell;
use std::ops::Range;

use agentleaks_analyzers::filter::{Verdict, adjust_severity, check_value, clean_value, host_of};
use agentleaks_core::{
    Candidate, Category, Confidence, Context, Routed, Secret, SecretKind, Severity,
};
use agentleaks_spec::{ArgForm, ArgKind, CliArg, Position, Spec, SpecRegex};

use index::{Index, NAME_MAX, StrMode, norm_key};
use lexer::{Lexed, Word, json_decode, lex, looks_json_escaped};
use values::Cred;

pub const RULE_ENV_PREFIX: &str = "shell.env-prefix";
pub const RULE_CLI_ARG: &str = "shell.cli-arg";
pub const RULE_PATTERN: &str = "shell.pattern";
pub const RULE_KEYVALUE_ARG: &str = "shell.keyvalue-arg";
pub const RULE_STDIN_PIPE: &str = "shell.stdin-pipe";

/// Maximum wrapper nesting (`sudo bash -c 'ssh h "mysql -px"'`).
pub const MAX_DEPTH: u8 = 4;

#[derive(Debug, thiserror::Error)]
pub enum ShellError {
    #[error("shell analyzer: invalid catalogue: {0}")]
    Catalogue(String),
}

/// The shell-command analyzer. Build once per spec; `analyze` is `&self` and
/// thread-safe (scratch buffers are thread-local).
#[derive(Debug)]
pub struct ShellAnalyzer<'s> {
    spec: &'s Spec,
    ix: Index,
}

#[derive(Debug, Default)]
struct Scratch {
    decoded: String,
    table: Vec<usize>,
    pool: Vec<Lexed>,
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch::default());
}

/// Maps spans of a frame's text to spans of the top-level (decoded) text.
#[derive(Debug, Clone, Copy)]
enum Map {
    Offset(usize),
    Fixed(usize, usize),
}

impl Map {
    fn apply(self, r: Range<usize>) -> Range<usize> {
        match self {
            Map::Offset(o) => r.start + o..r.end + o,
            Map::Fixed(a, b) => a..b,
        }
    }
}

/// A text being analyzed: the top-level input or a string recursed into.
#[derive(Debug, Clone, Copy)]
struct Frame<'t> {
    text: &'t str,
    map: Map,
    depth: u8,
}

struct St<'s, 'o> {
    out: &'o mut Vec<Candidate<'s>>,
    /// JSON decode table (decoded byte -> input byte), if decoded.
    table: Option<&'o [usize]>,
    pool: &'o mut Vec<Lexed>,
}

impl St<'_, '_> {
    fn to_input(&self, r: Range<usize>) -> Range<usize> {
        match self.table {
            Some(t) if !t.is_empty() => {
                let last = t.len() - 1;
                t[r.start.min(last)]..t[r.end.min(last)]
            }
            _ => r,
        }
    }
}

/// Where a value comes from, to compute its span.
#[derive(Debug, Clone, Copy)]
enum Loc<'w> {
    /// A word; `base` is its unquoted value.
    Word(&'w Lexed, &'w Word),
    /// The frame text itself; `base` is the frame text.
    Text,
}

#[derive(Debug, Clone, Copy)]
struct Src<'a> {
    base: &'a str,
    loc: Loc<'a>,
}

/// Per-candidate metadata.
#[derive(Debug, Clone, Copy)]
struct Meta<'a> {
    rule: &'static str,
    cat: Category,
    conf: Confidence,
    tool: Option<&'a str>,
    host: Option<&'a str>,
    user: Option<&'a str>,
}

/// What a wrapper wraps.
#[derive(Debug, Clone)]
enum Inner {
    /// `cmd[i..]` is a command.
    Argv(usize),
    /// `cmd[i]` (the byte range of its value) is a command string.
    Str(usize, Range<usize>),
    /// Every non-flag word from `cmd[i..]` is a command string.
    StrEach(usize),
}

/// Tools matched for a command: indices and the number of name words.
struct Tools {
    ids: [usize; 4],
    n: usize,
    consumed: usize,
}

impl Tools {
    fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.ids[..self.n].iter().copied()
    }
}

impl<'s> ShellAnalyzer<'s> {
    pub fn new(spec: &'s Spec) -> Result<Self, ShellError> {
        Ok(ShellAnalyzer {
            spec,
            ix: Index::build(spec).map_err(ShellError::Catalogue)?,
        })
    }

    /// Analyze `input.text` (one or more shell commands) and append
    /// candidates whose spans are byte ranges in `input.text`.
    pub fn analyze(&self, input: &Routed<'_>, out: &mut Vec<Candidate<'s>>) {
        let text = strip_glob(&input.text);
        SCRATCH.with(|s| match s.try_borrow_mut() {
            Ok(mut s) => self.run(text, &mut s, out),
            Err(_) => self.run(text, &mut Scratch::default(), out),
        });
    }

    fn run(&self, text: &str, sc: &mut Scratch, out: &mut Vec<Candidate<'s>>) {
        let first = out.len();
        let Scratch {
            decoded,
            table,
            pool,
        } = sc;
        let json = looks_json_escaped(text);
        let top: &str = if json {
            json_decode(text, decoded, table);
            decoded
        } else {
            text
        };
        let mut st = St {
            out,
            table: json.then_some(&table[..]),
            pool,
        };
        self.frame(
            &mut st,
            Frame {
                text: top,
                map: Map::Offset(0),
                depth: 0,
            },
        );
        dedup(out, first);
    }

    fn frame(&self, st: &mut St<'s, '_>, fr: Frame<'_>) {
        if fr.depth > MAX_DEPTH {
            return;
        }
        let d = usize::from(fr.depth);
        if st.pool.len() <= d {
            st.pool.resize_with(d + 1, Lexed::default);
        }
        let mut lx = std::mem::take(&mut st.pool[d]);
        lex(fr.text, &mut lx);
        for ci in 0..lx.cmds.len() {
            let ws = lx.cmd_words(&lx.cmds[ci]);
            self.command(st, fr, &lx, ws, fr.depth);
            self.stdin_pipe(st, fr, &lx, ci);
        }
        st.pool[d] = lx;
    }

    // ------------------------------------------------------------------
    // One simple command
    // ------------------------------------------------------------------

    fn command(&self, st: &mut St<'s, '_>, fr: Frame<'_>, lx: &Lexed, ws: &[Word], depth: u8) {
        let mut i = 0;
        while i < ws.len() && is_keyword(lx.val(&ws[i])) {
            i += 1;
        }
        let env_start = i;
        if self.spec.shell.env_prefix {
            while i < ws.len() && assignment(lx.val(&ws[i])).is_some() {
                i += 1;
            }
        }
        let cmd = &ws[i..];
        let tools = self.resolve(lx, cmd);
        let (host, user) = context(lx, ws);
        let mut kb = [0u8; NAME_MAX];
        let name = cmd.first().and_then(|w| norm_key(lx.val(w), &mut kb));
        let tool_name = tools
            .iter()
            .next()
            .map(|t| self.spec.cli_tools[t].tool.as_str())
            .or(name);
        let meta = Meta {
            rule: RULE_ENV_PREFIX,
            cat: Category::EnvAssignment,
            conf: Confidence::High,
            tool: tool_name,
            host,
            user,
        };
        for w in &ws[env_start..i] {
            self.env_assign(st, fr, lx, w, &tools, meta);
        }
        let Some(name) = name else { return };
        if matches!(
            name,
            "export" | "declare" | "typeset" | "local" | "readonly" | "set"
        ) {
            for w in &cmd[1..] {
                if assignment(lx.val(w)).is_some() {
                    self.env_assign(st, fr, lx, w, &tools, meta);
                }
            }
            return;
        }

        let wrapped = if depth < MAX_DEPTH {
            self.wrapper(lx, cmd, name)
        } else {
            None
        };
        let outer = &cmd[..wrapped.as_ref().map_or(cmd.len(), |(end, _)| *end)];
        let meta = Meta {
            rule: RULE_CLI_ARG,
            cat: Category::CliArgument,
            ..meta
        };
        for t in tools.iter() {
            let m = Meta {
                tool: Some(self.spec.cli_tools[t].tool.as_str()),
                ..meta
            };
            self.knowledge_base(st, fr, lx, outer, tools.consumed, t, m);
        }
        self.keyvalue_tools(
            st,
            fr,
            lx,
            outer,
            name,
            Meta {
                rule: RULE_KEYVALUE_ARG,
                ..meta
            },
        );

        match wrapped {
            Some((_, Inner::Argv(s))) => self.command(st, fr, lx, &cmd[s..], depth + 1),
            Some((_, Inner::Str(k, r))) => {
                if let Some(f) = inner_frame(fr, lx, &cmd[k], r, depth + 1) {
                    self.frame(st, f);
                }
            }
            Some((_, Inner::StrEach(s))) => {
                for w in &cmd[s..] {
                    if !is_flag(lx.val(w)) {
                        let r = 0..lx.val(w).len();
                        if let Some(f) = inner_frame(fr, lx, w, r, depth + 1) {
                            self.frame(st, f);
                        }
                    }
                }
            }
            None => {}
        }
    }

    /// Tools whose name (or multi-word alias) starts `cmd`; longest match wins.
    fn resolve(&self, lx: &Lexed, cmd: &[Word]) -> Tools {
        let mut t = Tools {
            ids: [0; 4],
            n: 0,
            consumed: 0,
        };
        let mut buf = [0u8; NAME_MAX];
        let Some(first) = cmd.first().and_then(|w| norm_key(lx.val(w), &mut buf)) else {
            return t;
        };
        let Some(entries) = self.ix.tools.get(first) else {
            return t;
        };
        for (rest, id) in entries {
            let ok = rest.len() < cmd.len()
                && rest
                    .iter()
                    .zip(&cmd[1..])
                    .all(|(r, w)| r.eq_ignore_ascii_case(lx.val(w)));
            if !ok {
                continue;
            }
            let len = 1 + rest.len();
            if len > t.consumed {
                t.consumed = len;
                t.n = 0;
            }
            if len == t.consumed && t.n < t.ids.len() && !t.ids[..t.n].contains(id) {
                t.ids[t.n] = *id;
                t.n += 1;
            }
        }
        t
    }

    fn env_assign(
        &self,
        st: &mut St<'s, '_>,
        fr: Frame<'_>,
        lx: &Lexed,
        w: &Word,
        tools: &Tools,
        m: Meta<'_>,
    ) {
        let v = lx.val(w);
        let Some((name, value)) = assignment(v) else {
            return;
        };
        let src = Src {
            base: v,
            loc: Loc::Word(lx, w),
        };
        let in_tool_env = tools.iter().any(|t| {
            self.ix.tool_env[t]
                .iter()
                .any(|e| match e.strip_suffix('*') {
                    Some(p) => starts_with_ci(name, p),
                    None => e.eq_ignore_ascii_case(name),
                })
        });
        if self.spec.credential_names.is_credential_name(name) {
            self.emit(st, fr, src, Cred::bare(value), name_kind(name), m);
        } else if in_tool_env {
            if name.to_ascii_uppercase().contains("USER") {
                if let Some(c) = values::userpass(value, ":") {
                    self.emit(st, fr, src, c, SecretKind::Password, m);
                }
            } else {
                self.emit(st, fr, src, Cred::bare(value), name_kind(name), m);
            }
        }
    }

    // ------------------------------------------------------------------
    // Wrappers
    // ------------------------------------------------------------------

    /// If `cmd` is a wrapper, the end of its own arguments and what it wraps.
    fn wrapper(&self, lx: &Lexed, cmd: &[Word], name: &str) -> Option<(usize, Inner)> {
        let val = |k: usize| cmd.get(k).map_or("", |w| lx.val(w));
        let n = cmd.len();

        for sa in &self.ix.string_args {
            let Some(c) = sa
                .cmd
                .iter()
                .filter(|(f, _)| f == name)
                .find_map(|(_, rest)| match_words(lx, &cmd[1..], rest).map(|k| k + 1))
            else {
                continue;
            };
            let mut start = c;
            if !sa.sub.is_empty() {
                let after = sa.sub.iter().find_map(|s| find_seq(lx, &cmd[c..], s))?;
                start = c + after;
            }
            match sa.mode {
                StrMode::Flag => {
                    let j = (start..n).find(|&k| sa.flags.iter().any(|f| flag_match(val(k), f)))?;
                    if j + 1 >= n {
                        return None;
                    }
                    return Some((j, tail(lx, cmd, j + 1)));
                }
                StrMode::AfterHost => {
                    let mut k = start;
                    while k < n {
                        let v = val(k);
                        if v == "--" {
                            k += 1;
                            break;
                        }
                        if is_flag(v) {
                            let takes = v.len() == 2
                                && b"BbcDEeFIiJLlmOoPpQRSWw".contains(&v.as_bytes()[1]);
                            k += if takes { 2 } else { 1 };
                            continue;
                        }
                        break;
                    }
                    if k + 1 >= n {
                        return None;
                    }
                    return Some((k + 1, tail(lx, cmd, k + 1)));
                }
                StrMode::All => {
                    if !sa.sub.is_empty() {
                        // tmux send-keys -t target 'cmd' Enter
                        let mut k = start;
                        while k < n && is_flag(val(k)) {
                            k += if val(k).len() == 2 { 2 } else { 1 };
                        }
                        return (k < n).then_some((start, Inner::StrEach(k)));
                    }
                    if start >= n {
                        return None;
                    }
                    return Some((start, tail(lx, cmd, start)));
                }
            }
        }

        for a in self.ix.after_dd.iter().filter(|a| a.cmd == name) {
            let Some(after) = sub_match(lx, &cmd[1..], &a.sub).map(|k| k + 1) else {
                continue;
            };
            match &a.flag {
                Some(f) => {
                    for k in after..n {
                        let v = val(k);
                        if v == f && k + 1 < n {
                            let r = command_param(lx.val(&cmd[k + 1]));
                            return Some((k, Inner::Str(k + 1, r)));
                        }
                        if let Some(rest) =
                            v.strip_prefix(f.as_str()).and_then(|r| r.strip_prefix('='))
                        {
                            let off = v.len() - rest.len();
                            let r = command_param(rest);
                            return Some((k, Inner::Str(k, r.start + off..r.end + off)));
                        }
                    }
                }
                None => {
                    if let Some(p) = (after..n).find(|&k| val(k) == "--")
                        && p + 1 < n
                    {
                        return Some((p, Inner::Argv(p + 1)));
                    }
                }
            }
        }

        for c in self.ix.container.iter().filter(|c| c.cmd == name) {
            let Some(mut k) = sub_match(lx, &cmd[1..], &c.sub).map(|k| k + 1) else {
                continue;
            };
            while k < n && is_flag(val(k)) {
                k += if container_flag_takes_value(val(k)) {
                    2
                } else {
                    1
                };
            }
            // k = container/image name
            if k + 1 < n {
                return Some((k + 1, Inner::Argv(k + 1)));
            }
            return None;
        }

        if let Some(entries) = self.ix.passthrough.get(name) {
            let c = entries
                .iter()
                .filter_map(|rest| match_words(lx, &cmd[1..], rest).map(|k| k + 1))
                .max()?;
            let mut first_plain = None;
            for k in c..n {
                let v = val(k);
                if v == "--" {
                    return (k + 1 < n).then_some((k, Inner::Argv(k + 1)));
                }
                if is_flag(v) {
                    continue;
                }
                first_plain.get_or_insert(k);
                let mut b = [0u8; NAME_MAX];
                let known = norm_key(v, &mut b).is_some_and(|key| self.ix.known.contains(key));
                if known || assignment(v).is_some() {
                    return Some((k, Inner::Argv(k)));
                }
            }
            // `watch -n 5 'mysql -px'`: a last argument with spaces is a command string.
            if n > c && val(n - 1).contains(' ') {
                return Some((n - 1, Inner::Str(n - 1, 0..val(n - 1).len())));
            }
            return first_plain.map(|k| (k, Inner::Argv(k)));
        }
        None
    }

    // ------------------------------------------------------------------
    // Knowledge base
    // ------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn knowledge_base(
        &self,
        st: &mut St<'s, '_>,
        fr: Frame<'_>,
        lx: &Lexed,
        cmd: &[Word],
        consumed: usize,
        t: usize,
        m: Meta<'_>,
    ) {
        let tool = &self.spec.cli_tools[t];
        let rest = cmd.get(consumed..).unwrap_or(&[]);
        let ci = self.ix.tool_ci[t];
        for (ai, arg) in tool.args.iter().enumerate() {
            let region = match &arg.subcommand {
                None => rest,
                Some(subs) => match subs.as_slice().iter().find_map(|s| sub_match(lx, rest, s)) {
                    Some(k) => &rest[k..],
                    None => continue,
                },
            };
            let kind = arg.kind.clone().unwrap_or(ArgKind::Password);
            if let Some(p) = &arg.pattern {
                self.pattern(
                    st,
                    fr,
                    cmd,
                    p,
                    &kind,
                    Meta {
                        rule: RULE_PATTERN,
                        ..m
                    },
                );
                continue;
            }
            if kind == ArgKind::None {
                continue;
            }
            let any = self.ix.any_name[t][ai];
            match arg.form {
                Some(ArgForm::Positional) => {
                    self.positional(st, fr, lx, region, arg, &kind, any, m)
                }
                Some(ArgForm::None) | None => {}
                Some(form) => {
                    if let Some(flag) = &arg.flag {
                        let ci = ci || flag.starts_with('/');
                        self.flagged(st, fr, lx, region, flag, form, ci, &kind, any, m);
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn flagged(
        &self,
        st: &mut St<'s, '_>,
        fr: Frame<'_>,
        lx: &Lexed,
        region: &[Word],
        flag: &str,
        form: ArgForm,
        ci: bool,
        kind: &ArgKind,
        any: bool,
        m: Meta<'_>,
    ) {
        use ArgForm as F;
        let eq = |a: &str, b: &str| {
            if ci {
                a.eq_ignore_ascii_case(b)
            } else {
                a == b
            }
        };
        let pre = |v: &str| -> bool {
            v.len() >= flag.len() && v.is_char_boundary(flag.len()) && eq(&v[..flag.len()], flag)
        };
        for (k, w) in region.iter().enumerate() {
            let v = lx.val(w);
            let src = Src {
                base: v,
                loc: Loc::Word(lx, w),
            };
            if matches!(
                form,
                F::Separate | F::AttachedOrSeparate | F::EqualsOrSeparate
            ) && eq(v, flag)
            {
                if let Some(nw) = region.get(k + 1) {
                    let nv = lx.val(nw);
                    if !is_flag(nv) {
                        let nsrc = Src {
                            base: nv,
                            loc: Loc::Word(lx, nw),
                        };
                        self.value(st, fr, nsrc, nv, kind, any, m);
                    }
                }
                continue;
            }
            if !pre(v) || v.len() == flag.len() {
                continue;
            }
            let rest = &v[flag.len()..];
            match form {
                F::Equals | F::EqualsOrSeparate => {
                    let value = if flag.ends_with('=') {
                        Some(rest)
                    } else {
                        rest.strip_prefix('=')
                    };
                    if let Some(value) = value {
                        self.value(st, fr, src, value, kind, any, m);
                    }
                }
                F::Attached | F::AttachedOrSeparate => {
                    self.value(st, fr, src, rest, kind, any, m);
                }
                F::Colon => {
                    let value = if flag.ends_with(':') {
                        Some(rest)
                    } else {
                        rest.strip_prefix(':')
                    };
                    if let Some(value) = value {
                        self.value(st, fr, src, value, kind, any, m);
                    }
                }
                F::Separate | F::Positional | F::None => {}
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn positional(
        &self,
        st: &mut St<'s, '_>,
        fr: Frame<'_>,
        lx: &Lexed,
        region: &[Word],
        arg: &CliArg,
        kind: &ArgKind,
        any: bool,
        m: Meta<'_>,
    ) {
        let region = match &arg.flag {
            Some(f) => match region.iter().position(|w| flag_match(lx.val(w), f)) {
                Some(k) => &region[k + 1..],
                None => return,
            },
            None => region,
        };
        let pos = || region.iter().filter(|w| !is_flag(lx.val(w)));
        let Some(position) = arg.position else { return };
        let plain = matches!(
            kind,
            ArgKind::Password | ArgKind::Token | ArgKind::Key | ArgKind::Passphrase
        );
        let m = Meta {
            conf: if position == Position::Any && !matches!(kind, ArgKind::Connect(_)) {
                Confidence::Medium
            } else {
                Confidence::High
            },
            ..m
        };
        let one = |st: &mut St<'s, '_>, w: &Word| {
            let v = lx.val(w);
            if plain && assignment_like(v) {
                return;
            }
            let src = Src {
                base: v,
                loc: Loc::Word(lx, w),
            };
            self.value(st, fr, src, v, kind, any, m);
        };
        if *kind == ArgKind::KeyValuePair {
            let words: Vec<&Word> = pos().collect();
            let pair = |st: &mut St<'s, '_>, j: usize| {
                let (Some(nw), Some(vw)) = (words.get(j), words.get(j + 1)) else {
                    return;
                };
                let name = lx.val(nw);
                if name.contains('=') {
                    return; // handled as a single NAME=VAL word
                }
                let v = lx.val(vw);
                let src = Src {
                    base: v,
                    loc: Loc::Word(lx, vw),
                };
                self.named(st, fr, src, name, v, any, m);
            };
            let single = |st: &mut St<'s, '_>, j: usize| {
                if let Some(w) = words.get(j)
                    && lx.val(w).contains('=')
                {
                    let v = lx.val(w);
                    let src = Src {
                        base: v,
                        loc: Loc::Word(lx, w),
                    };
                    self.value(st, fr, src, v, &ArgKind::KeyValue, any, m);
                }
            };
            match position {
                Position::Index(n) => {
                    let n = n as usize;
                    if n >= 2 {
                        pair(st, n - 2);
                        single(st, n - 2);
                    }
                    single(st, n - 1);
                }
                Position::Last => {
                    if words.len() >= 2 {
                        pair(st, words.len() - 2);
                    }
                }
                Position::Any => {
                    for j in 0..words.len() {
                        single(st, j);
                        pair(st, j);
                    }
                }
            }
            return;
        }
        match position {
            Position::Index(n) => {
                if let Some(w) = pos().nth((n as usize).saturating_sub(1)) {
                    one(st, w);
                }
            }
            Position::Last => {
                if let Some(w) = pos().next_back() {
                    one(st, w);
                }
            }
            Position::Any => {
                for w in pos() {
                    one(st, w);
                }
            }
        }
    }

    /// A `pattern` entry: regex over the command's text in the frame.
    fn pattern(
        &self,
        st: &mut St<'s, '_>,
        fr: Frame<'_>,
        cmd: &[Word],
        re: &SpecRegex,
        kind: &ArgKind,
        m: Meta<'_>,
    ) {
        let (Some(a), Some(b)) = (cmd.first(), cmd.last()) else {
            return;
        };
        let range = a.raw.start..b.raw.end;
        let Some(hay) = fr.text.get(range.clone()) else {
            return;
        };
        let src = Src {
            base: fr.text,
            loc: Loc::Text,
        };
        for caps in re.captures_iter(hay) {
            if let Some(g) = caps.name(agentleaks_spec::SECRET_GROUP) {
                let s = &fr.text[range.start + g.start()..range.start + g.end()];
                self.value(st, fr, src, s, kind, false, m);
            }
        }
    }

    // ------------------------------------------------------------------
    // keyvalue_arg_tools
    // ------------------------------------------------------------------

    fn keyvalue_tools(
        &self,
        st: &mut St<'s, '_>,
        fr: Frame<'_>,
        lx: &Lexed,
        cmd: &[Word],
        name: &str,
        m: Meta<'_>,
    ) {
        let kv = ArgKind::KeyValue;
        for t in self.ix.kv_tools.iter().filter(|t| t.cmd == name) {
            let Some(after) = sub_match(lx, &cmd[1..], &t.sub).map(|k| k + 1) else {
                continue;
            };
            let region = &cmd[after..];
            match t.flag.as_deref() {
                None => {
                    for w in region.iter().filter(|w| !is_flag(lx.val(w))) {
                        let v = lx.val(w);
                        if assignment_like(v) {
                            self.value(
                                st,
                                fr,
                                Src {
                                    base: v,
                                    loc: Loc::Word(lx, w),
                                },
                                v,
                                &kv,
                                false,
                                m,
                            );
                        }
                    }
                }
                Some("--") => {
                    if let Some(p) = region.iter().position(|w| lx.val(w) == "--") {
                        for w in &region[p + 1..] {
                            let v = lx.val(w);
                            let s = v.trim_start_matches('-');
                            if assignment_like(s) {
                                self.value(
                                    st,
                                    fr,
                                    Src {
                                        base: v,
                                        loc: Loc::Word(lx, w),
                                    },
                                    s,
                                    &kv,
                                    false,
                                    m,
                                );
                            }
                        }
                    }
                }
                Some(f) => {
                    let short = f.len() == 2 && !f.starts_with("--");
                    for (k, w) in region.iter().enumerate() {
                        let v = lx.val(w);
                        let src = Src {
                            base: v,
                            loc: Loc::Word(lx, w),
                        };
                        if v == f {
                            if let Some(nw) = region.get(k + 1) {
                                let nv = lx.val(nw);
                                self.value(
                                    st,
                                    fr,
                                    Src {
                                        base: nv,
                                        loc: Loc::Word(lx, nw),
                                    },
                                    nv,
                                    &kv,
                                    false,
                                    m,
                                );
                            }
                        } else if let Some(rest) = v.strip_prefix(f) {
                            let value = match rest.strip_prefix('=') {
                                Some(r) if assignment_like(r) || !short => Some(r),
                                _ if short => Some(rest),
                                _ => None,
                            };
                            if let Some(value) = value {
                                self.value(st, fr, src, value, &kv, false, m);
                            }
                        }
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // stdin pipelines
    // ------------------------------------------------------------------

    fn stdin_pipe(&self, st: &mut St<'s, '_>, fr: Frame<'_>, lx: &Lexed, ci: usize) {
        let c = &lx.cmds[ci];
        let mut ws = lx.cmd_words(c);
        while ws.first().is_some_and(|w| assignment(lx.val(w)).is_some()) {
            ws = &ws[1..];
        }
        let mut kb = [0u8; NAME_MAX];
        let Some(name) = ws.first().and_then(|w| norm_key(lx.val(w), &mut kb)) else {
            return;
        };
        let Some(sink) = self.ix.sinks.iter().find(|s| {
            !s.skip
                && s.cmd
                    .iter()
                    .any(|(f, sub)| f == name && sub_match(lx, &ws[1..], sub).is_some())
                && (s.flags.is_empty() || s.flags.iter().any(|f| has_seq(lx, ws, f)))
                && s.arg
                    .as_ref()
                    .is_none_or(|a| ws.iter().any(|w| lx.val(w) == a))
        }) else {
            return;
        };
        let tools = self.resolve(lx, ws);
        let tool = tools
            .iter()
            .next()
            .map(|t| self.spec.cli_tools[t].tool.as_str())
            .or(Some(name));
        let (host, user) = context(lx, ws);
        let m = Meta {
            rule: RULE_STDIN_PIPE,
            cat: Category::CliStdin,
            conf: Confidence::High,
            tool,
            host,
            user,
        };
        let kind = if sink.token {
            SecretKind::Token
        } else {
            SecretKind::Password
        };

        // Payload: the sink's own here-string/heredoc, or the previous command.
        let mut payload: Option<(Src<'_>, &str)> = c.stdin.as_ref().map(|w| {
            let v = lx.val(w);
            (
                Src {
                    base: v,
                    loc: Loc::Word(lx, w),
                },
                v,
            )
        });
        if payload.is_none() && c.piped && ci > 0 {
            let prev = &lx.cmds[ci - 1];
            let pws = lx.cmd_words(prev);
            let mut pb = [0u8; NAME_MAX];
            let src_name = pws.first().and_then(|w| norm_key(lx.val(w), &mut pb));
            if let Some(src_name) = src_name.filter(|s| self.ix.sources.contains(*s)) {
                payload = if src_name == "cat" {
                    prev.stdin.as_ref().map(|w| {
                        let v = lx.val(w);
                        (
                            Src {
                                base: v,
                                loc: Loc::Word(lx, w),
                            },
                            v,
                        )
                    })
                } else {
                    source_args(fr, lx, &pws[1..], src_name == "printf")
                };
            }
        }
        let Some((src, text)) = payload else { return };
        for line in text.split('\n') {
            let line = line.trim();
            let line = line.strip_suffix("\\n").unwrap_or(line).trim_end();
            if line.is_empty() {
                continue;
            }
            if sink.userpass {
                if let Some(c) = values::userpass(line, ":") {
                    self.emit(st, fr, src, c, kind, m);
                }
                continue;
            }
            self.emit(st, fr, src, Cred::bare(line), kind, m);
            break;
        }
    }

    // ------------------------------------------------------------------
    // Values
    // ------------------------------------------------------------------

    /// Interpret `v` (a subslice of `src.base`) according to `kind`.
    #[allow(clippy::too_many_arguments)]
    fn value(
        &self,
        st: &mut St<'s, '_>,
        fr: Frame<'_>,
        src: Src<'_>,
        v: &str,
        kind: &ArgKind,
        any: bool,
        m: Meta<'_>,
    ) {
        use ArgKind as K;
        match kind {
            K::Password => self.emit(st, fr, src, Cred::bare(v), SecretKind::Password, m),
            K::Passphrase => self.emit(st, fr, src, Cred::bare(v), SecretKind::Passphrase, m),
            K::Token => self.emit(st, fr, src, Cred::bare(v), SecretKind::Token, m),
            K::Key => self.emit(st, fr, src, Cred::bare(v), SecretKind::Key, m),
            K::UserPass(sep) => {
                if let Some(c) = values::userpass(v, sep) {
                    self.emit(st, fr, src, c, SecretKind::Password, m);
                }
            }
            K::Prefixed(p) => {
                if v.len() > p.len()
                    && v.is_char_boundary(p.len())
                    && v[..p.len()].eq_ignore_ascii_case(p)
                {
                    self.emit(
                        st,
                        fr,
                        src,
                        Cred::bare(&v[p.len()..]),
                        SecretKind::Password,
                        m,
                    );
                }
            }
            K::Connect(syntax) => self.connect(st, fr, src, v, syntax, m),
            K::KeyValue | K::KeyValuePair => {
                values::keyvalue_list(v, |name, val| self.named(st, fr, src, name, val, any, m));
                if let Some(c) = values::uri(v) {
                    self.emit(st, fr, src, c, SecretKind::Password, m);
                }
            }
            K::Header => {
                if let Some((n, hv)) = values::header(v) {
                    self.header(st, fr, src, n, hv, m);
                }
            }
            K::HeaderOrItem => match values::httpie_item(v) {
                Some((":", n, hv)) => self.header(st, fr, src, n, hv, m),
                Some((_, n, iv)) => self.named(st, fr, src, n, iv, false, m),
                None => {}
            },
            K::HeaderHashtable => {
                values::hashtable(v, |n, hv| self.header(st, fr, src, n, hv, m));
            }
            K::Body => {
                let t = v.trim_start();
                if t.starts_with('{') || t.starts_with('[') {
                    values::json_pairs(v, |n, bv| self.named(st, fr, src, n, bv, false, m));
                } else {
                    values::pairs(v, '&', |n, bv| self.named(st, fr, src, n, bv, false, m));
                }
            }
            K::Cookie => values::pairs(v, ';', |n, cv| self.named(st, fr, src, n, cv, false, m)),
            K::None => {}
        }
    }

    /// A `name`/`value` pair: reported when the name is a credential name,
    /// when the value is a credential header or URI, or when `any` is set.
    #[allow(clippy::too_many_arguments)]
    fn named(
        &self,
        st: &mut St<'s, '_>,
        fr: Frame<'_>,
        src: Src<'_>,
        name: &str,
        value: &str,
        any: bool,
        m: Meta<'_>,
    ) {
        let name = values::unquote(name.trim());
        if self.is_cred_name(name) {
            self.emit(st, fr, src, Cred::bare(value), name_kind(name), m);
        } else if let Some((hn, hv)) = values::header(values::unquote(value.trim()))
            && self.spec.credential_names.is_credential_name(hn)
        {
            self.header(st, fr, src, hn, hv, m);
        } else if any && !self.spec.credential_names.is_excluded(name) {
            let m = Meta {
                conf: Confidence::Medium,
                ..m
            };
            self.emit(st, fr, src, Cred::bare(value), SecretKind::Credential, m);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn header(
        &self,
        st: &mut St<'s, '_>,
        fr: Frame<'_>,
        src: Src<'_>,
        name: &str,
        value: &str,
        m: Meta<'_>,
    ) {
        if name.eq_ignore_ascii_case("cookie") {
            values::pairs(value, ';', |n, cv| self.named(st, fr, src, n, cv, false, m));
            return;
        }
        if !self.spec.credential_names.is_credential_name(name) {
            return;
        }
        match values::auth_scheme(value) {
            Some(("basic", c)) => self.emit(st, fr, src, Cred::bare(c), SecretKind::Credential, m),
            Some((_, c)) => self.emit(st, fr, src, Cred::bare(c), SecretKind::Token, m),
            None => self.emit(st, fr, src, Cred::bare(value), SecretKind::Token, m),
        }
    }

    fn connect(
        &self,
        st: &mut St<'s, '_>,
        fr: Frame<'_>,
        src: Src<'_>,
        v: &str,
        syntax: &str,
        m: Meta<'_>,
    ) {
        let cred = match syntax {
            "uri" => values::uri(v),
            "libpq_keyvalue" => values::libpq(v),
            "jdbc" => values::jdbc(v),
            "oracle_userpass" => values::oracle(v),
            "impacket_target" => values::impacket(v),
            "cvs_pserver" => values::cvs_pserver(v),
            "sas_url" => values::sas_url(v),
            "azure_kv" | "ado_net" => {
                values::semicolon_pairs(v, |k, val| {
                    if values::is_connstring_secret_key(k) || self.is_cred_name(k) {
                        self.emit(st, fr, src, Cred::bare(val), SecretKind::Credential, m);
                    }
                });
                None
            }
            _ => None,
        };
        if let Some(c) = cred {
            self.emit(st, fr, src, c, SecretKind::Password, m);
        }
    }

    fn is_cred_name(&self, name: &str) -> bool {
        let cn = &self.spec.credential_names;
        if cn.is_credential_name(name) {
            return true;
        }
        match name.rfind(['.', ':', '/']) {
            Some(k) if k + 1 < name.len() => {
                !cn.is_excluded(name) && cn.is_credential_name(&name[k + 1..])
            }
            _ => false,
        }
    }

    /// Filter a credential and push a candidate. `c.secret` must be a
    /// subslice of `src.base`.
    fn emit(
        &self,
        st: &mut St<'s, '_>,
        fr: Frame<'_>,
        src: Src<'_>,
        c: Cred<'_>,
        kind: SecretKind,
        m: Meta<'_>,
    ) {
        let v = strip_stray_quotes(clean_value(c.secret));
        let ml = &self.spec.value_filters.min_length;
        let min = match kind {
            SecretKind::Token => ml.token,
            SecretKind::Key | SecretKind::Hash => ml.key,
            _ => ml.password,
        };
        let (v, default) = match check_value(self.spec, v, min) {
            Verdict::Keep(v) => (v, false),
            Verdict::Default(v) => (v, true),
            Verdict::Drop => return,
        };
        let base = src.base.as_ptr() as usize;
        let at = v.as_ptr() as usize;
        if at < base || at + v.len() > base + src.base.len() {
            return; // not a subslice: cannot locate it
        }
        let off = at - base;
        let span = match src.loc {
            Loc::Word(lx, w) => match lx.locate(w, off, v.len()) {
                Some(s) => s..s + v.len(),
                None => w.raw.clone(),
            },
            Loc::Text => off..off + v.len(),
        };
        let span = st.to_input(fr.map.apply(span));
        let host = c.host.or(m.host).map(host_of).filter(|h| !h.is_empty());
        let user = c.user.or(m.user);
        st.out.push(Candidate {
            rule_id: m.rule,
            category: m.cat,
            kind: if default {
                SecretKind::DefaultCredential
            } else {
                kind
            },
            severity: adjust_severity(self.spec, Severity::High, host, default),
            confidence: m.conf,
            secret: Secret::new(v),
            span,
            context: Context {
                tool: m.tool.map(str::to_owned),
                host: host.map(str::to_owned),
                user: user.map(str::to_owned),
                ..Context::default()
            },
        });
    }
}

// ----------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------

/// Allow-rule glob suffixes: `npm test:*`, `git log *`.
fn strip_glob(t: &str) -> &str {
    let s = t.trim_end();
    s.strip_suffix(":*")
        .or_else(|| s.strip_suffix(" *"))
        .unwrap_or(t)
}

/// Drop candidates with a span already reported by this analyzer.
fn dedup(out: &mut Vec<Candidate<'_>>, first: usize) {
    let mut k = first;
    while k < out.len() {
        let dup = out[first..k].iter().any(|c| c.span == out[k].span);
        if dup {
            out.remove(k);
        } else {
            k += 1;
        }
    }
}

fn is_keyword(v: &str) -> bool {
    matches!(
        v,
        "!" | "{" | "}" | "(" | ")" | "if" | "then" | "else" | "elif" | "do" | "while" | "until"
    )
}

/// `NAME=value` with a shell identifier as NAME.
fn assignment(v: &str) -> Option<(&str, &str)> {
    let (name, value) = v.split_once('=')?;
    let mut b = name.bytes();
    let first = b.next()?;
    ((first.is_ascii_alphabetic() || first == b'_')
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'_'))
    .then_some((name, value))
}

/// `name=...` with a dotted/dashed identifier as name (`db.password=x`).
fn assignment_like(v: &str) -> bool {
    match v.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && name.as_bytes()[0].is_ascii_alphabetic()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-' | b':'))
        }
        None => false,
    }
}

fn is_flag(v: &str) -> bool {
    v.len() > 1 && v.starts_with('-')
}

/// `v` is `flag`, or a short-option cluster containing it (`-lc` for `-c`).
fn flag_match(v: &str, flag: &str) -> bool {
    if v.eq_ignore_ascii_case(flag) && (flag.starts_with('/') || flag.len() > 2 || v == flag) {
        return true;
    }
    let fb = flag.as_bytes();
    fb.len() == 2
        && fb[0] == b'-'
        && fb[1].is_ascii_alphabetic()
        && v.len() > 2
        && v.starts_with('-')
        && !v.starts_with("--")
        && v.bytes().skip(1).all(|c| c.is_ascii_alphabetic())
        && v.bytes().skip(1).any(|c| c == fb[1])
}

fn starts_with_ci(s: &str, p: &str) -> bool {
    s.len() >= p.len() && s.is_char_boundary(p.len()) && s[..p.len()].eq_ignore_ascii_case(p)
}

/// The words of `rest` start with `words` (ASCII-case-insensitive); returns
/// how many were consumed.
fn match_words(lx: &Lexed, rest: &[Word], words: &[String]) -> Option<usize> {
    (words.len() <= rest.len()
        && words
            .iter()
            .zip(rest)
            .all(|(a, w)| a.eq_ignore_ascii_case(lx.val(w))))
    .then_some(words.len())
}

/// Index after the space-separated word sequence `seq` found anywhere in `ws`.
fn find_seq(lx: &Lexed, ws: &[Word], seq: &str) -> Option<usize> {
    let n = seq.split_whitespace().count();
    (0..ws.len()).find_map(|s| {
        let ok = n > 0
            && s + n <= ws.len()
            && seq
                .split_whitespace()
                .zip(&ws[s..])
                .all(|(a, w)| a.eq_ignore_ascii_case(lx.val(w)));
        ok.then_some(s + n)
    })
}

fn has_seq(lx: &Lexed, ws: &[Word], seq: &[String]) -> bool {
    if let [one] = seq {
        return ws
            .iter()
            .any(|w| flag_match(lx.val(w), one) || lx.val(w) == one);
    }
    (0..ws.len())
        .any(|s| s + seq.len() <= ws.len() && seq.iter().zip(&ws[s..]).all(|(a, w)| a == lx.val(w)))
}

/// Subcommand scoping: `sub` (space-separated words) must be the first
/// non-flag words of `rest`, or start at the second non-flag word when the
/// first one directly follows a flag (`kubectl -n prod create secret`).
/// Returns the index in `rest` just after the subcommand. An empty `sub`
/// matches at 0.
fn sub_match(lx: &Lexed, rest: &[Word], sub: &str) -> Option<usize> {
    let n = sub.split_whitespace().count();
    if n == 0 {
        return Some(0);
    }
    if sub.starts_with('-') {
        return find_seq(lx, rest, sub);
    }
    let mut nf = rest
        .iter()
        .enumerate()
        .filter(|(_, w)| !is_flag(lx.val(w)))
        .map(|(k, _)| k);
    let first = nf.next()?;
    let second = nf.next();
    let at = |s: usize| {
        (s + n <= rest.len()
            && sub
                .split_whitespace()
                .zip(&rest[s..])
                .all(|(a, w)| a.eq_ignore_ascii_case(lx.val(w))))
        .then_some(s + n)
    };
    if let Some(k) = at(first) {
        return Some(k);
    }
    match second {
        Some(s) if s == first + 1 && first > 0 && !lx.val(&rest[first - 1]).contains('=') => at(s),
        _ => None,
    }
}

/// After a wrapper, the command is one string (`bash -c 'x' arg0`) or argv
/// (`cmd /c mysql -px`).
fn tail(lx: &Lexed, cmd: &[Word], s: usize) -> Inner {
    let v = lx.val(&cmd[s]);
    if s + 1 == cmd.len() || v.contains([' ', '\t', '\n', ';', '|', '&']) {
        Inner::Str(s, 0..v.len())
    } else {
        Inner::Argv(s)
    }
}

/// `commands=["mysql -px"]` (aws ssm) -> the range of `mysql -px`.
fn command_param(v: &str) -> Range<usize> {
    let mut s = v;
    s = s.strip_prefix("commands=").unwrap_or(s);
    s = s.trim();
    s = s.strip_prefix('[').unwrap_or(s);
    s = s.strip_suffix(']').unwrap_or(s);
    s = values::unquote(s.trim());
    let off = s.as_ptr() as usize - v.as_ptr() as usize;
    off..off + s.len()
}

fn container_flag_takes_value(v: &str) -> bool {
    if v.contains('=') {
        return false;
    }
    if let Some(long) = v.strip_prefix("--") {
        return !matches!(
            long,
            "rm" | "privileged"
                | "init"
                | "interactive"
                | "tty"
                | "detach"
                | "read-only"
                | "no-deps"
                | "service-ports"
                | "use-aliases"
                | "no-TTY"
                | "quiet"
                | "sig-proxy"
                | "no-healthcheck"
        );
    }
    // Short options: clusters are self-contained; -i/-t/-d/-P/-T are booleans.
    v.len() == 2 && !matches!(v.as_bytes()[1], b'i' | b't' | b'd' | b'P' | b'T' | b'q')
}

/// The frame for a command string inside word `w` (value range `r`).
fn inner_frame<'a>(
    fr: Frame<'_>,
    lx: &'a Lexed,
    w: &Word,
    r: Range<usize>,
    depth: u8,
) -> Option<Frame<'a>> {
    let text = lx.val(w).get(r.clone())?;
    let map = match (lx.locate(w, r.start, r.len()), fr.map) {
        (Some(s), Map::Offset(o)) => Map::Offset(o + s),
        (_, m) => {
            let f = m.apply(w.raw.clone());
            Map::Fixed(f.start, f.end)
        }
    };
    Some(Frame { text, map, depth })
}

/// Payload of `echo`/`printf`/`yes` arguments.
fn source_args<'a>(
    fr: Frame<'a>,
    lx: &'a Lexed,
    args: &'a [Word],
    printf: bool,
) -> Option<(Src<'a>, &'a str)> {
    let mut args = args;
    if !printf {
        while args.first().is_some_and(|w| {
            let v = lx.val(w);
            v.len() > 1
                && v.starts_with('-')
                && v[1..].bytes().all(|c| matches!(c, b'n' | b'e' | b'E'))
        }) {
            args = &args[1..];
        }
    } else if args.first().is_some_and(|w| lx.val(w).contains('%')) {
        args = &args[1..];
        args = &args[..args.len().min(1)];
    }
    match args {
        [] => None,
        [w] => {
            let v = lx.val(w);
            Some((
                Src {
                    base: v,
                    loc: Loc::Word(lx, w),
                },
                v,
            ))
        }
        [a, .., b] => {
            let t = fr.text.get(a.raw.start..b.raw.end)?;
            Some((
                Src {
                    base: fr.text,
                    loc: Loc::Text,
                },
                t,
            ))
        }
    }
}

fn strip_stray_quotes(v: &str) -> &str {
    let b = v.as_bytes();
    match (b.first(), b.last()) {
        (Some(b'"' | b'\''), Some(l)) if b[0] != *l => v[1..].trim(),
        (Some(f), Some(b'"' | b'\'')) if *f != b[b.len() - 1] => v[..v.len() - 1].trim(),
        _ => v,
    }
}

/// Secret kind (and hence minimum length) from a credential name.
fn name_kind(name: &str) -> SecretKind {
    let has = |p: &str| {
        name.as_bytes()
            .windows(p.len())
            .any(|w| w.eq_ignore_ascii_case(p.as_bytes()))
    };
    if has("pass") || has("pwd") || has("secret") {
        SecretKind::Password
    } else if has("token") {
        SecretKind::Token
    } else if has("key") {
        SecretKind::Key
    } else {
        SecretKind::Credential
    }
}

/// Host and user from common flags, URLs and `user@host` arguments.
/// Never returns a value containing `:`, `%` or `,` as user, so a
/// `user:pass` argument cannot leak into the context.
fn context<'a>(lx: &'a Lexed, ws: &'a [Word]) -> (Option<&'a str>, Option<&'a str>) {
    let mut host = None;
    let mut user = None;
    let safe_user =
        |u: &'a str| (!u.is_empty() && !u.contains([':', '%', ',', '/', '='])).then_some(u);
    for (k, w) in ws.iter().enumerate() {
        let v = lx.val(w);
        let next = ws.get(k + 1).map(|w| lx.val(w)).filter(|n| !is_flag(n));
        match v {
            "-h" | "--host" | "--hostname" | "-host" | "--server" => host = host.or(next),
            "-u" | "-U" | "--user" | "--username" | "-l" | "--login" | "-user" => {
                user = user.or(next.and_then(safe_user));
            }
            _ => {}
        }
        if let Some(h) = v.strip_prefix("--host=") {
            host = host.or(Some(h));
        }
        if let Some(u) = v
            .strip_prefix("--user=")
            .or_else(|| v.strip_prefix("--username="))
        {
            user = user.or(safe_user(u));
        }
        if host.is_none() {
            if let Some(p) = v.find("://") {
                host = Some(&v[p + 3..]);
            } else if !is_flag(v)
                && let Some((u, h)) = v.split_once('@')
                && !u.is_empty()
                && !h.is_empty()
                && !v.contains(['/', '=', ' ', '\\'])
                && !h.contains('@')
                && !u.contains(':')
            {
                host = Some(h);
                user = user.or(safe_user(u));
            }
        }
    }
    (host, user)
}

#[cfg(test)]
mod tests;
