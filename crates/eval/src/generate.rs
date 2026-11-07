//! Deterministic synthetic corpus: realistic agent files (allow rules,
//! transcripts, MCP configs, `.env`, skills, YAML/TOML configs) filled from
//! [`crate::templates`] with values in several styles. Every value is
//! invented and matches no vendor format.
//!
//! Value styles and what the label says:
//!
//! | style | example | password slot | token/key slot |
//! |---|---|---|---|
//! | `random` | `Kq7#vR2mLp9x` | positive | positive |
//! | `word` | `SunflowerHarbor42!` | positive | optional |
//! | `placeholder` | `changeme` | optional (D60 reports passwords) | negative |
//! | `reference` | `$DB_PASSWORD`, `<password>` | negative | negative |

use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context as _, bail};

use crate::corpus::{LABELS_FILE, Label, Labels, Provenance};
use crate::rng::Rng;
use crate::templates::{self as t, K};

/// Marks a directory as a generated corpus that may be overwritten.
pub const MARKER: &str = ".eval-corpus";

#[derive(Debug, Clone, Copy)]
pub struct GenOptions {
    pub seed: u64,
    /// Cases per file type.
    pub scale: usize,
    /// Entries per file (relative size, 1..=4; 1 is the quick corpus).
    pub density: usize,
}

impl Default for GenOptions {
    fn default() -> Self {
        GenOptions {
            seed: 20261107,
            scale: 24,
            density: 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Style {
    Random,
    Word,
    Placeholder,
    Reference,
}

impl Style {
    pub fn as_str(self) -> &'static str {
        match self {
            Style::Random => "random",
            Style::Word => "word",
            Style::Placeholder => "placeholder",
            Style::Reference => "reference",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    Pos,
    Optional,
    Neg,
}

/// A generated value. No `Debug`: it is a (synthetic) secret.
#[derive(Clone)]
struct Val {
    /// The value as the program sees it (label value).
    raw: String,
    /// Shell-ready (quoted when needed) for `{S}` slots.
    shell: String,
    style: Style,
    expect: Expect,
}

const VENDOR_PREFIXES: &[&str] = &[
    "ghp", "gho", "ghs", "ghu", "ghr", "github", "glpat", "gldt", "sk", "xox", "akia", "asia",
    "aiza", "ya29", "eyj", "npm", "pypi", "hf", "dop", "shp", "sg.", "rk_", "pk_", "whsec",
];

fn shell_quote(v: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c);
    if !v.is_empty() && v.chars().all(safe) {
        v.to_owned()
    } else {
        format!("'{v}'")
    }
}

fn random_pw(r: &mut Rng, uri: bool) -> String {
    const L: &str = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
    const D: &str = "23456789";
    let sym = if uri { "-_.~" } else { "!#%^*-_+=.," };
    let n = r.range(10, 18);
    let mut s = String::with_capacity(n);
    s.push(r.char_of(&L[23..])); // upper case first
    s.push(r.char_of(&L[..23]));
    s.push(r.char_of(D));
    while s.len() < n {
        match r.below(10) {
            0..=4 => s.push(r.char_of(L)),
            5..=7 => s.push(r.char_of(D)),
            _ => s.push(r.char_of(sym)),
        }
    }
    s
}

fn random_token(r: &mut Rng, key: bool) -> String {
    const A: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    loop {
        let n = if key { 40 } else { r.range(28, 44) };
        let mut s = String::with_capacity(n);
        s.push(r.char_of(&A[..26]));
        while s.len() < n {
            if key && r.chance(5) {
                s.push(if r.chance(50) { '/' } else { '+' });
            } else if !key && s.len().is_multiple_of(12) && r.chance(30) {
                s.push(if r.chance(50) { '-' } else { '.' });
            } else {
                s.push(r.char_of(A));
            }
        }
        let low = s.to_ascii_lowercase();
        let has_digit = s.bytes().any(|b| b.is_ascii_digit());
        if has_digit && !VENDOR_PREFIXES.iter().any(|p| low.starts_with(p)) {
            return s;
        }
    }
}

fn word_value(r: &mut Rng, k: K) -> String {
    let w1 = *r.pick(t::WORDS);
    let w2 = *r.pick(t::WORDS);
    let cap = |w: &str| {
        let mut c = w.chars();
        c.next()
            .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
            .unwrap_or_default()
    };
    let uri = k == K::UriPw;
    match r.below(4) {
        0 => format!("{}{}{}", cap(w1), cap(w2), r.range(10, 99)),
        1 if !uri => format!("{}{}!", cap(w1), r.range(2019, 2027)),
        2 => format!("{w1}-{w2}-{}", r.range(1, 9)),
        _ if !uri => format!("{}{}{}#", cap(w1), w2, r.range(1, 9)),
        _ => format!("{}{}{}", cap(w1), w2, r.range(100, 999)),
    }
}

fn pick_style(r: &mut Rng) -> Style {
    match r.below(100) {
        0..=44 => Style::Random,
        45..=64 => Style::Word,
        65..=74 => Style::Placeholder,
        _ => Style::Reference,
    }
}

/// A value for slot domain `k`; `raw_slot` = inserted raw (`{s}`, or
/// config files) rather than shell-quoted.
fn value(r: &mut Rng, k: K, raw_slot: bool) -> Val {
    let style = pick_style(r);
    let pw = matches!(k, K::Pw | K::UriPw);
    let (raw, shell, expect) = match style {
        Style::Random => {
            let v = match k {
                K::Pw => random_pw(r, false),
                K::UriPw => random_pw(r, true),
                K::Tok => random_token(r, false),
                K::Key => random_token(r, true),
            };
            (v.clone(), shell_quote(&v), Expect::Pos)
        }
        Style::Word => {
            let v = word_value(r, k);
            let e = if pw { Expect::Pos } else { Expect::Optional };
            (v.clone(), shell_quote(&v), e)
        }
        Style::Placeholder => {
            let v = (*r.pick(t::PLACEHOLDERS)).to_owned();
            let e = if pw { Expect::Optional } else { Expect::Neg };
            (v.clone(), shell_quote(&v), e)
        }
        Style::Reference => {
            if raw_slot {
                let v = (*r.pick(t::CONFIG_REFERENCES)).to_owned();
                (v.clone(), v, Expect::Neg)
            } else {
                let v = (*r.pick(t::REFERENCES)).to_owned();
                (v.clone(), v, Expect::Neg)
            }
        }
    };
    Val {
        raw,
        shell,
        style,
        expect,
    }
}

fn fill_ctx(r: &mut Rng, tpl: &str) -> String {
    let mut s = tpl.to_owned();
    for (slot, list) in [
        ("{H}", t::HOSTS),
        ("{U}", t::USERS),
        ("{DB}", t::DBS),
        ("{N}", t::NAMES),
    ] {
        while s.contains(slot) {
            let v = *r.pick(list);
            s = s.replacen(slot, v, 1);
        }
    }
    s
}

/// A filled template: text plus the label it needs.
struct Filled {
    text: String,
    template: String,
    label: Option<Pending>,
}

struct Pending {
    secret: String,
    category: &'static str,
    rule: Option<&'static str>,
    style: Style,
    optional: bool,
}

impl Filled {
    fn neg(text: String, template: &str) -> Self {
        Filled {
            text,
            template: template.to_owned(),
            label: None,
        }
    }
}

fn pending(v: &Val, category: &'static str, rule: Option<&'static str>) -> Option<Pending> {
    (v.expect != Expect::Neg).then(|| Pending {
        secret: v.raw.clone(),
        category,
        rule,
        style: v.style,
        optional: v.expect == Expect::Optional,
    })
}

fn pos_command(r: &mut Rng, filter: impl Fn(&str) -> bool) -> Filled {
    loop {
        let &(id, tpl, k, how) = r.pick(t::POS_COMMANDS);
        if !filter(tpl) {
            continue;
        }
        let raw_slot = tpl.contains("{s}");
        let v = value(r, k, raw_slot);
        let text = fill_ctx(r, tpl)
            .replace("{S}", &v.shell)
            .replace("{s}", &v.raw);
        return Filled {
            text,
            template: format!("cmd.{id}@{}", v.style.as_str()),
            label: pending(&v, how.category(), how.rule()),
        };
    }
}

fn neg_command(r: &mut Rng, filter: impl Fn(&str) -> bool) -> Filled {
    loop {
        let &(id, tpl) = r.pick(t::NEG_COMMANDS);
        if filter(tpl) {
            return Filled::neg(fill_ctx(r, tpl), &format!("neg.{id}"));
        }
    }
}

fn command(r: &mut Rng, pos_pct: u32) -> Filled {
    if r.chance(pos_pct) {
        pos_command(r, |_| true)
    } else {
        neg_command(r, |_| true)
    }
}

/// A config entry: (name, value, filled label info). `category` is the
/// label category for positive names.
fn config_entry(r: &mut Rng, pos_pct: u32) -> (String, Val, String) {
    if r.chance(pos_pct) {
        let &(name, k) = r.pick(t::POS_CONFIG_NAMES);
        let v = value(r, k, true);
        let tpl = format!("cfg.{name}@{}", v.style.as_str());
        (name.to_owned(), v, tpl)
    } else {
        let &(id, name, value) = r.pick(t::NEG_CONFIG);
        let raw = fill_ctx(r, value);
        let v = Val {
            shell: raw.clone(),
            raw,
            style: Style::Random,
            expect: Expect::Neg,
        };
        (name.to_owned(), v, format!("neg.{id}"))
    }
}

// ---------------------------------------------------------------------------
// File and case builders
// ---------------------------------------------------------------------------

struct FileB {
    path: String,
    text: String,
    line: usize,
}

struct CaseB {
    name: String,
    files: Vec<FileB>,
    labels: Labels,
}

impl CaseB {
    fn new(name: String) -> Self {
        CaseB {
            name,
            files: Vec::new(),
            labels: Labels::default(),
        }
    }

    fn file(&mut self, path: &str) -> usize {
        self.files.push(FileB {
            path: path.to_owned(),
            text: String::new(),
            line: 1,
        });
        self.files.len() - 1
    }

    /// Append `text` (one or more lines) to file `f`; labels the secret on
    /// the line that contains it.
    fn put(&mut self, f: usize, text: &str, template: Option<&str>, label: Option<Pending>) {
        let fb = &mut self.files[f];
        let start = fb.line;
        let n = text.split('\n').count();
        if let Some(tpl) = template {
            self.labels.provenance.push(Provenance {
                file: fb.path.clone(),
                line: start,
                lines: n,
                template: tpl.to_owned(),
            });
        }
        if let Some(p) = label {
            let off = text
                .split('\n')
                .position(|l| l.contains(p.secret.as_str()))
                .unwrap_or(0);
            self.labels.labels.push(Label {
                file: fb.path.clone(),
                line: Some(start + off),
                secret: Some(p.secret),
                secret_blake3: None,
                category: p.category.to_owned(),
                rule: p.rule.map(str::to_owned),
                style: Some(p.style.as_str().to_owned()),
                template: template.map(str::to_owned),
                optional: p.optional,
            });
        }
        fb.text.push_str(text);
        fb.text.push('\n');
        fb.line += n;
    }

    fn plain(&mut self, f: usize, text: &str) {
        self.put(f, text, None, None);
    }

    fn filled(&mut self, f: usize, x: Filled, render: impl Fn(&str) -> String) {
        let text = render(&x.text);
        // The label value appears in the rendered text as-is unless JSON
        // escaping changed it; locate it by the escaped form then.
        self.put(f, &text, Some(&x.template), x.label);
    }

    fn write(&self, root: &Path) -> anyhow::Result<usize> {
        let dir = root.join(&self.name);
        let mut bytes = 0;
        for f in &self.files {
            let p = dir.join(&f.path);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&p, &f.text).with_context(|| format!("write {}", p.display()))?;
            bytes += f.text.len();
        }
        std::fs::create_dir_all(&dir)?;
        let labels = serde_json::to_string_pretty(&self.labels)?;
        std::fs::write(dir.join(LABELS_FILE), labels + "\n")?;
        Ok(bytes)
    }
}

fn js(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_default()
}

/// YAML scalar: plain when safe, double-quoted otherwise.
fn yaml(s: &str) -> String {
    let safe = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./-@".contains(c))
        && !s.starts_with(['-', '@', '.']);
    if safe { s.to_owned() } else { js(s) }
}

fn dotenv(s: &str) -> String {
    let safe = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_./:@-+=,".contains(c));
    if safe { s.to_owned() } else { js(s) }
}

/// Comma-separate JSON array/object entry lines.
fn comma(i: usize, n: usize) -> &'static str {
    if i + 1 < n { "," } else { "" }
}

// ---------------------------------------------------------------------------
// Case kinds
// ---------------------------------------------------------------------------

fn n(opts: &GenOptions, base: usize) -> usize {
    (base * opts.density.clamp(1, 4)).div_ceil(2).max(2)
}

fn case_allow(r: &mut Rng, name: String, o: &GenOptions) -> CaseB {
    let mut c = CaseB::new(name);
    let f = c.file(".claude/settings.local.json");
    c.plain(f, "{\n  \"permissions\": {\n    \"allow\": [");
    let k = n(o, 16);
    for i in 0..k {
        let x = command(r, 55);
        let glob = !x.text.contains('|') && r.chance(10);
        c.filled(f, x, |cmd| {
            let inner = if glob {
                format!("Bash({cmd}:*)")
            } else {
                format!("Bash({cmd})")
            };
            format!("      {}{}", js(&inner), comma(i, k))
        });
    }
    c.plain(f, "    ],\n    \"deny\": []\n  },\n  \"env\": {");
    let k = n(o, 4);
    for i in 0..k {
        let (name, v, tpl) = config_entry(r, 50);
        let label = pending(&v, "env_assignment", None);
        let line = format!("    {}: {}{}", js(&name), js(&v.raw), comma(i, k));
        c.put(f, &line, Some(&tpl), label);
    }
    c.plain(f, "  }\n}");

    let f = c.file(".cursor/cli.json");
    c.plain(f, "{\n  \"permissions\": {\n    \"allow\": [");
    let k = n(o, 6);
    for i in 0..k {
        let x = command(r, 50);
        c.filled(f, x, |cmd| {
            format!("      {}{}", js(&format!("Shell({cmd})")), comma(i, k))
        });
    }
    c.plain(f, "    ]\n  }\n}");
    c
}

fn case_transcript(r: &mut Rng, name: String, o: &GenOptions) -> CaseB {
    let mut c = CaseB::new(name);
    let proj = *r.pick(t::NAMES);
    let f = c.file(&format!(
        "home/.claude/projects/-home-dev-{proj}/{:08x}-session.jsonl",
        r.next_u64() as u32
    ));
    let k = n(o, 24);
    for i in 0..k {
        match r.below(10) {
            0..=1 => {
                if r.chance(25) {
                    let &(id, tpl, kk) = r.pick(t::POS_PROSE);
                    let v = value(r, kk, true);
                    let text = fill_ctx(r, tpl).replace("{s}", &v.raw);
                    let x = Filled {
                        text,
                        template: format!("prose.{id}@{}", v.style.as_str()),
                        label: pending(&v, "natural_language", None),
                    };
                    c.filled(f, x, |p| {
                        format!(
                            r#"{{"type": "user", "message": {{"role": "user", "content": {}}}}}"#,
                            js(p)
                        )
                    });
                } else {
                    let &(id, p) = r.pick(t::NEG_PROSE);
                    let x = Filled::neg(fill_ctx(r, p), &format!("neg.{id}"));
                    c.filled(f, x, |p| {
                        format!(
                            r#"{{"type": "user", "message": {{"role": "user", "content": {}}}}}"#,
                            js(p)
                        )
                    });
                }
            }
            2..=6 => {
                let x = command(r, 55);
                c.filled(f, x, |cmd| {
                    format!(
                        r#"{{"type": "assistant", "message": {{"role": "assistant", "content": [{{"type": "tool_use", "id": "toolu_{i:04}", "name": "Bash", "input": {{"command": {}, "description": "Run the command"}}}}]}}}}"#,
                        js(cmd)
                    )
                });
            }
            7..=8 => {
                let (id, out) = if r.chance(50) {
                    let &(id, code) = r.pick(t::NEG_CODE);
                    (id, code.to_owned())
                } else {
                    let &(id, y) = r.pick(t::NEG_YAML);
                    (id, y.to_owned())
                };
                let x = Filled::neg(out, &format!("neg.{id}"));
                c.filled(f, x, |o| {
                    format!(
                        r#"{{"type": "user", "message": {{"role": "user", "content": [{{"type": "tool_result", "tool_use_id": "toolu_{i:04}", "content": {}}}]}}}}"#,
                        js(o)
                    )
                });
            }
            _ => {
                let &(id, p) = r.pick(t::NEG_PROSE);
                let x = Filled::neg(fill_ctx(r, p), &format!("neg.{id}"));
                c.filled(f, x, |p| {
                    format!(
                        r#"{{"type": "assistant", "message": {{"role": "assistant", "content": [{{"type": "text", "text": {}}}]}}}}"#,
                        js(p)
                    )
                });
            }
        }
    }
    c
}

fn case_mcp(r: &mut Rng, name: String, o: &GenOptions) -> CaseB {
    let mut c = CaseB::new(name);
    let path = if r.chance(50) {
        ".mcp.json"
    } else {
        ".cursor/mcp.json"
    };
    let f = c.file(path);
    c.plain(f, "{\n  \"mcpServers\": {");
    let k = n(o, 3);
    for i in 0..k {
        let srv = format!("{}-{}", r.pick(t::NAMES), i);
        c.plain(f, &format!("    {}: {{", js(&srv)));
        match r.below(4) {
            0 => {
                // stdio server with env
                c.plain(
                    f,
                    "      \"command\": \"npx\",\n      \"args\": [\"-y\", \"@acme/mcp-server\"],\n      \"env\": {",
                );
                let m = r.range(2, 4);
                for j in 0..m {
                    let (name, v, tpl) = config_entry(r, 55);
                    let label = pending(&v, "env_assignment", None);
                    let line = format!("        {}: {}{}", js(&name), js(&v.raw), comma(j, m));
                    c.put(f, &line, Some(&tpl), label);
                }
                c.plain(f, "      }");
            }
            1 => {
                // http server with headers
                let host = *r.pick(t::HOSTS);
                c.plain(
                    f,
                    &format!("      \"type\": \"http\",\n      \"url\": \"https://{host}/mcp\",\n      \"headers\": {{"),
                );
                let v = value(r, K::Tok, true);
                let (hname, hval, tpl) = if r.chance(60) {
                    (
                        "Authorization",
                        format!("Bearer {}", v.raw),
                        format!("mcp.header-bearer@{}", v.style.as_str()),
                    )
                } else {
                    (
                        "X-Api-Key",
                        v.raw.clone(),
                        format!("mcp.header-api-key@{}", v.style.as_str()),
                    )
                };
                let label = pending(&v, "http", None);
                c.put(
                    f,
                    &format!("        {}: {},", js(hname), js(&hval)),
                    Some(&tpl),
                    label,
                );
                c.put(
                    f,
                    "        \"Accept\": \"text/event-stream\"",
                    Some("neg.mcp.header-accept"),
                    None,
                );
                c.plain(f, "      }");
            }
            2 => {
                // credentials in args
                c.plain(f, "      \"command\": \"npx\",\n      \"args\": [");
                c.plain(f, "        \"-y\",\n        \"@acme/mcp-postgres\",");
                let v = value(r, K::UriPw, true);
                let host = *r.pick(t::HOSTS);
                let user = *r.pick(t::USERS);
                let db = *r.pick(t::DBS);
                let label = pending(&v, "connection_string", None);
                c.put(
                    f,
                    &format!(
                        "        {},",
                        js(&format!("postgresql://{user}:{}@{host}:5432/{db}", v.raw))
                    ),
                    Some(&format!("mcp.args-uri@{}", v.style.as_str())),
                    label,
                );
                let v = value(r, K::Key, true);
                let label = pending(&v, "cli_argument", None);
                c.put(f, "        \"--api-key\",", None, None);
                c.put(
                    f,
                    &format!("        {}", js(&v.raw)),
                    Some(&format!("mcp.args-api-key@{}", v.style.as_str())),
                    label,
                );
                c.plain(f, "      ]");
            }
            _ => {
                // key in the URL query
                let v = value(r, K::Key, true);
                let host = *r.pick(t::HOSTS);
                let label = pending(&v, "http", None);
                c.put(
                    f,
                    &format!(
                        "      \"url\": {}",
                        js(&format!("https://{host}/sse?api_key={}", v.raw))
                    ),
                    Some(&format!("mcp.url-query@{}", v.style.as_str())),
                    label,
                );
            }
        }
        c.plain(f, &format!("    }}{}", comma(i, k)));
    }
    c.plain(f, "  }\n}");
    c
}

fn case_dotenv(r: &mut Rng, name: String, o: &GenOptions) -> CaseB {
    let mut c = CaseB::new(name);
    let path = *r.pick(&[".env", "home/.codex/.env", "services/api/.env"]);
    let f = c.file(path);
    c.plain(f, "# local development settings (do not commit)");
    let k = n(o, 10);
    for _ in 0..k {
        if r.chance(12) {
            let v = value(r, K::UriPw, true);
            let host = *r.pick(t::HOSTS);
            let user = *r.pick(t::USERS);
            let db = *r.pick(t::DBS);
            let label = pending(&v, "connection_string", None);
            c.put(
                f,
                &format!("DATABASE_URL=postgres://{user}:{}@{host}:5432/{db}", v.raw),
                Some(&format!("env.database-url@{}", v.style.as_str())),
                label,
            );
            continue;
        }
        let (name, v, tpl) = config_entry(r, 50);
        let label = pending(&v, "env_assignment", None);
        c.put(f, &format!("{name}={}", dotenv(&v.raw)), Some(&tpl), label);
    }
    c
}

fn case_skill(r: &mut Rng, name: String, o: &GenOptions) -> CaseB {
    let mut c = CaseB::new(name);
    let skill = format!("{}-ops", r.pick(t::NAMES));
    let f = c.file(&format!(".claude/skills/{skill}/SKILL.md"));
    c.plain(
        f,
        &format!(
            "---\nname: {skill}\ndescription: Operational runbook for {skill}. Use when deploying or debugging.\n---\n\n# {skill}\n"
        ),
    );
    let sections = n(o, 3);
    for _ in 0..sections {
        let &(id, p) = r.pick(t::NEG_PROSE);
        let x = Filled::neg(fill_ctx(r, p), &format!("neg.{id}"));
        c.filled(f, x, str::to_owned);
        c.plain(f, "\n```bash");
        for _ in 0..r.range(2, 4) {
            let x = command(r, 50);
            c.filled(f, x, str::to_owned);
        }
        c.plain(f, "```\n");
        if r.chance(50) {
            c.plain(f, "```yaml");
            for _ in 0..r.range(2, 3) {
                let (name, v, tpl) = config_entry(r, 50);
                let label = pending(&v, "config_key", None);
                c.put(f, &format!("{name}: {}", yaml(&v.raw)), Some(&tpl), label);
            }
            c.plain(f, "```\n");
        }
        if r.chance(30) {
            let &(id, tpl, kk) = r.pick(t::POS_PROSE);
            let v = value(r, kk, true);
            let text = fill_ctx(r, tpl).replace("{s}", &v.raw);
            let x = Filled {
                text,
                template: format!("prose.{id}@{}", v.style.as_str()),
                label: pending(&v, "natural_language", None),
            };
            c.filled(f, x, str::to_owned);
            c.plain(f, "");
        }
    }
    let &(id, code) = r.pick(t::NEG_CODE);
    let ext = match id {
        "code.py-env" => "py",
        "code.sh-refs" => "sh",
        "code.go-struct" => "go",
        "code.iam-json" => "json",
        _ => "ts",
    };
    let g = c.file(&format!(".claude/skills/{skill}/scripts/helper.{ext}"));
    c.put(g, code.trim_end(), Some(&format!("neg.{id}")), None);
    let &(id, y) = r.pick(t::NEG_YAML);
    let g = c.file(&format!(".claude/skills/{skill}/templates/manifest.yaml"));
    c.put(g, y.trim_end(), Some(&format!("neg.{id}")), None);
    c
}

fn case_yaml(r: &mut Rng, name: String, o: &GenOptions) -> CaseB {
    let mut c = CaseB::new(name);
    let f = c.file("home/.continue/config.yaml");
    c.plain(
        f,
        "name: Local Assistant\nversion: 1.0.0\nschema: v1\nmodels:",
    );
    for i in 0..n(o, 2) {
        let host = *r.pick(t::HOSTS);
        c.plain(
            f,
            &format!(
                "  - name: acme-large-{i}\n    provider: openai\n    model: acme-large-2\n    apiBase: https://{host}/v1"
            ),
        );
        let v = value(r, K::Key, true);
        let label = pending(&v, "config_key", None);
        c.put(
            f,
            &format!("    apiKey: {}", yaml(&v.raw)),
            Some(&format!("yaml.continue-apikey@{}", v.style.as_str())),
            label,
        );
        c.put(
            f,
            "    defaultCompletionOptions:\n      maxTokens: 4096\n      contextLength: 128000",
            Some("neg.yaml.max-tokens"),
            None,
        );
    }
    let f = c.file("home/.config/goose/config.yaml");
    c.plain(
        f,
        "GOOSE_PROVIDER: openai\nGOOSE_MODEL: acme-large-2\nextensions:",
    );
    for i in 0..n(o, 2) {
        c.plain(
            f,
            &format!(
                "  {}-{i}:\n    type: stdio\n    cmd: npx\n    args: [\"-y\", \"@acme/mcp-server\"]\n    envs:",
                r.pick(t::NAMES)
            ),
        );
        for _ in 0..r.range(1, 3) {
            let (name, v, tpl) = config_entry(r, 55);
            let label = pending(&v, "env_assignment", None);
            c.put(
                f,
                &format!("      {name}: {}", yaml(&v.raw)),
                Some(&tpl),
                label,
            );
        }
    }
    let f = c.file(".github/workflows/copilot-setup-steps.yml");
    let &(id, y) = r.pick(t::NEG_YAML);
    c.put(f, y.trim_end(), Some(&format!("neg.{id}")), None);
    let f = c.file("home/.aider.conf.yml");
    let v = value(r, K::Key, true);
    let label = pending(&v, "config_key", None);
    c.put(
        f,
        "model: acme-large-2\nauto-commits: false\nmap-tokens: 2048",
        Some("neg.yaml.aider-options"),
        None,
    );
    c.put(
        f,
        &format!("openai-api-key: {}", yaml(&v.raw)),
        Some(&format!("yaml.aider-api-key@{}", v.style.as_str())),
        label,
    );
    c
}

/// Templates without quotes or operators: their words are the argv.
fn plain_cmd(tpl: &str) -> bool {
    !tpl.contains(['"', '\'', '|', '>', '<', '\\'].as_slice())
}

/// A command as a Codex `prefix_rule` argv list (values unquoted).
fn argv_command(r: &mut Rng) -> Filled {
    let argv = |r: &mut Rng, tpl: &str, v: Option<&Val>| -> String {
        let words: Vec<String> = tpl
            .split(' ')
            .map(|w| {
                let w = fill_ctx(r, w);
                let w = match v {
                    Some(v) => w.replace("{S}", &v.raw).replace("{s}", &v.raw),
                    None => w,
                };
                js(&w)
            })
            .collect();
        words.join(", ")
    };
    loop {
        if r.chance(55) {
            let &(id, tpl, k, how) = r.pick(t::POS_COMMANDS);
            if !plain_cmd(tpl) {
                continue;
            }
            let v = value(r, k, true);
            if v.raw.contains(' ') {
                continue; // one argv word
            }
            return Filled {
                text: argv(r, tpl, Some(&v)),
                template: format!("cmd.{id}@{}", v.style.as_str()),
                label: pending(&v, how.category(), how.rule()),
            };
        }
        let &(id, tpl) = r.pick(t::NEG_COMMANDS);
        if plain_cmd(tpl) {
            return Filled::neg(argv(r, tpl, None), &format!("neg.{id}"));
        }
    }
}

fn case_codex(r: &mut Rng, name: String, o: &GenOptions) -> CaseB {
    let mut c = CaseB::new(name);
    let f = c.file("home/.codex/rules/default.rules");
    for _ in 0..n(o, 6) {
        let x = argv_command(r);
        c.filled(f, x, |argv| {
            format!("prefix_rule(pattern=[{argv}], decision=\"allow\")")
        });
    }
    let f = c.file("home/.codex/config.toml");
    c.plain(
        f,
        "model = \"acme-large-2\"\napproval_policy = \"on-request\"\n",
    );
    for i in 0..n(o, 2) {
        c.plain(
            f,
            &format!(
                "[mcp_servers.{}-{i}]\ncommand = \"npx\"\nargs = [\"-y\", \"@acme/mcp-server\"]\n\n[mcp_servers.{0}-{i}.env]",
                r.pick(t::NAMES)
            ),
        );
        for _ in 0..r.range(1, 3) {
            let (name, v, tpl) = config_entry(r, 55);
            let label = pending(&v, "env_assignment", None);
            c.put(f, &format!("{name} = {}", js(&v.raw)), Some(&tpl), label);
        }
        c.plain(f, "");
    }
    c
}

type Kind = fn(&mut Rng, String, &GenOptions) -> CaseB;

pub const KINDS: &[&str] = &[
    "allow",
    "transcript",
    "mcp",
    "dotenv",
    "skill",
    "yaml",
    "codex",
];

fn kind_fn(k: &str) -> Kind {
    match k {
        "allow" => case_allow,
        "transcript" => case_transcript,
        "mcp" => case_mcp,
        "dotenv" => case_dotenv,
        "skill" => case_skill,
        "yaml" => case_yaml,
        _ => case_codex,
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct GenStats {
    pub cases: usize,
    pub files: usize,
    pub bytes: usize,
    pub labels: usize,
}

/// Write the corpus into `dir` (created; an existing generated corpus is
/// replaced, any other non-empty directory is refused).
pub fn generate(dir: &Path, o: &GenOptions) -> anyhow::Result<GenStats> {
    if dir.exists() {
        let empty = std::fs::read_dir(dir)?.next().is_none();
        if !empty && !dir.join(MARKER).exists() {
            bail!(
                "{} exists and is not a generated corpus (no {MARKER}); refusing to overwrite",
                dir.display()
            );
        }
        if !empty {
            std::fs::remove_dir_all(dir)?;
        }
    }
    std::fs::create_dir_all(dir)?;
    let mut info = String::new();
    let _ = writeln!(
        info,
        "generated by `cargo run -p eval -- gen` (seed {}, scale {}, density {}); safe to delete",
        o.seed, o.scale, o.density
    );
    std::fs::write(dir.join(MARKER), info)?;

    let root = Rng::new(o.seed);
    let mut st = GenStats::default();
    for kind in KINDS {
        for i in 0..o.scale.max(1) {
            let name = format!("{kind}-{i:03}");
            let mut r = root.fork(&name);
            let case = kind_fn(kind)(&mut r, name, o);
            st.bytes += case.write(dir)?;
            st.cases += 1;
            st.files += case.files.len();
            st.labels += case.labels.labels.len();
        }
    }
    Ok(st)
}
