//! A forgiving POSIX-ish shell lexer.
//!
//! It turns command text into words and simple commands. Each word keeps its
//! raw byte span in the input, and its value is recorded as segments: runs of
//! bytes copied verbatim from the input ([`Seg`]). A part of the value inside
//! one segment maps back to its exact input position ([`Lexed::locate`]);
//! quotes and escapes only split segments.
//!
//! Handled: single and double quotes, ANSI-C `$'..'`, `$".."`, backslash
//! escapes and line continuations, `$(..)`, `${..}` and backticks (kept as part
//! of the word), comments, the operators `&& || ; | |& &` and newlines,
//! redirections (dropped, including their target and leading fd numbers),
//! here-strings `<<<` and heredoc bodies (`<<EOF`, `<<'EOF'`, `<<-EOF`), which
//! become the command's [`Cmd::stdin`].
//!
//! The lexer never panics: it only slices the input at ASCII delimiters or
//! the end, which are always char boundaries.

use std::ops::Range;

/// One shell word.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Word {
    /// Span in the lexed text, including quotes.
    pub raw: Range<usize>,
    /// Span of the unquoted value in [`Lexed::buf`].
    pub val: Range<usize>,
    /// Range into [`Lexed::segs`].
    pub segs: Range<usize>,
}

/// A run of value bytes copied verbatim from the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seg {
    /// Start in [`Lexed::buf`].
    pub val: usize,
    /// Start in the lexed text.
    pub raw: usize,
    pub len: usize,
}

/// A simple command: words up to the next operator.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cmd {
    /// Range into [`Lexed::words`].
    pub words: Range<usize>,
    /// A here-string word or heredoc body fed to the command's stdin.
    pub stdin: Option<Word>,
    /// The previous command's output is piped into this one (`|`, `|&`).
    pub piped: bool,
}

/// Lexer output; reusable across calls to avoid allocations.
#[derive(Debug, Default)]
pub struct Lexed {
    /// Unquoted word values, concatenated.
    pub buf: String,
    pub words: Vec<Word>,
    pub cmds: Vec<Cmd>,
    pub segs: Vec<Seg>,
}

impl Lexed {
    pub fn clear(&mut self) {
        self.buf.clear();
        self.words.clear();
        self.cmds.clear();
        self.segs.clear();
    }

    /// Input offset of `len` value bytes at offset `off` of the word's value,
    /// if they were copied verbatim from one contiguous run of the input.
    pub fn locate(&self, w: &Word, off: usize, len: usize) -> Option<usize> {
        let abs = w.val.start + off;
        self.segs
            .get(w.segs.clone())?
            .iter()
            .find(|g| g.val <= abs && abs + len <= g.val + g.len)
            .map(|g| g.raw + (abs - g.val))
    }

    /// Unquoted value of a word.
    pub fn val(&self, w: &Word) -> &str {
        self.buf.get(w.val.clone()).unwrap_or("")
    }

    pub fn cmd_words(&self, c: &Cmd) -> &[Word] {
        self.words.get(c.words.clone()).unwrap_or(&[])
    }
}

struct Lx<'t, 'o> {
    text: &'t str,
    b: &'t [u8],
    i: usize,
    out: &'o mut Lexed,
    cur_start: usize,
    cur_stdin: Option<Word>,
    cur_piped: bool,
    cur_heredoc: bool,
    /// Segments before this index belong to earlier words.
    seg_floor: usize,
    /// (command index, delimiter span in buf, strip leading tabs)
    pending: Vec<(usize, Range<usize>, bool)>,
}

/// Lex `text` into `out` (cleared first).
pub fn lex(text: &str, out: &mut Lexed) {
    out.clear();
    let mut lx = Lx {
        text,
        b: text.as_bytes(),
        i: 0,
        out,
        cur_start: 0,
        cur_stdin: None,
        cur_piped: false,
        cur_heredoc: false,
        seg_floor: 0,
        pending: Vec::new(),
    };
    lx.run();
}

impl Lx<'_, '_> {
    fn peek(&self, k: usize) -> u8 {
        self.b.get(self.i + k).copied().unwrap_or(0)
    }

    fn close(&mut self, next_piped: bool) {
        let end = self.out.words.len();
        if end > self.cur_start || self.cur_stdin.is_some() || self.cur_heredoc {
            self.out.cmds.push(Cmd {
                words: self.cur_start..end,
                stdin: self.cur_stdin.take(),
                piped: self.cur_piped,
            });
        }
        self.cur_start = end;
        self.cur_piped = next_piped;
        self.cur_heredoc = false;
    }

    fn skip_blanks(&mut self) {
        while matches!(self.peek(0), b' ' | b'\t' | b'\r') {
            self.i += 1;
        }
    }

    fn run(&mut self) {
        while self.i < self.b.len() {
            match self.b[self.i] {
                b' ' | b'\t' | b'\r' => self.i += 1,
                b'\\' if self.peek(1) == b'\n' => self.i += 2,
                b'#' => {
                    while self.i < self.b.len() && self.b[self.i] != b'\n' {
                        self.i += 1;
                    }
                }
                b'\n' => {
                    self.close(false);
                    self.i += 1;
                    self.read_heredocs();
                }
                b';' => {
                    self.close(false);
                    self.i += if self.peek(1) == b';' { 2 } else { 1 };
                }
                b'&' => match self.peek(1) {
                    b'&' => {
                        self.close(false);
                        self.i += 2;
                    }
                    b'>' => {
                        self.i += if self.peek(2) == b'>' { 3 } else { 2 };
                        self.discard_target();
                    }
                    _ => {
                        self.close(false);
                        self.i += 1;
                    }
                },
                b'|' => match self.peek(1) {
                    b'|' => {
                        self.close(false);
                        self.i += 2;
                    }
                    b'&' => {
                        self.close(true);
                        self.i += 2;
                    }
                    _ => {
                        self.close(true);
                        self.i += 1;
                    }
                },
                b'<' => {
                    if self.peek(1) == b'<' && self.peek(2) == b'<' {
                        self.i += 3;
                        self.skip_blanks();
                        if let Some(w) = self.word() {
                            self.cur_stdin = Some(w);
                        }
                    } else if self.peek(1) == b'<' {
                        self.i += 2;
                        let strip = self.peek(0) == b'-';
                        if strip {
                            self.i += 1;
                        }
                        self.skip_blanks();
                        if let Some(w) = self.word() {
                            self.pending.push((self.out.cmds.len(), w.val, strip));
                            self.cur_heredoc = true;
                        }
                    } else {
                        self.i += if matches!(self.peek(1), b'>' | b'&') {
                            2
                        } else {
                            1
                        };
                        self.discard_target();
                    }
                }
                b'>' => {
                    self.i += if matches!(self.peek(1), b'>' | b'|' | b'&') {
                        2
                    } else {
                        1
                    };
                    self.discard_target();
                }
                _ => {
                    let Some(w) = self.word() else {
                        // Defensive: never loop without progress.
                        self.i += 1;
                        continue;
                    };
                    // `2>file`, `2>&1`: the digits are an fd, not an argument.
                    let fd = matches!(self.peek(0), b'<' | b'>')
                        && w.raw.end - w.raw.start <= 2
                        && self.b[w.raw.clone()].iter().all(u8::is_ascii_digit);
                    if fd {
                        self.drop_word(&w);
                    } else {
                        self.out.words.push(w);
                    }
                }
            }
        }
        self.close(false);
    }

    fn drop_word(&mut self, w: &Word) {
        self.out.buf.truncate(w.val.start);
        self.out.segs.truncate(w.segs.start);
    }

    /// Drop the target word of a redirection.
    fn discard_target(&mut self) {
        self.skip_blanks();
        if let Some(w) = self.word() {
            self.drop_word(&w);
        }
    }

    /// Read pending heredoc bodies starting at the current line.
    fn read_heredocs(&mut self) {
        let pending = std::mem::take(&mut self.pending);
        for (cmd, delim, strip) in pending {
            let body_start = self.i;
            let mut body_end = self.b.len();
            let mut next = self.b.len();
            let mut pos = self.i;
            while pos < self.b.len() {
                let line_end =
                    memchr::memchr(b'\n', &self.b[pos..]).map_or(self.b.len(), |k| pos + k);
                let mut line = &self.text[pos..line_end];
                line = line.strip_suffix('\r').unwrap_or(line);
                if strip {
                    line = line.trim_start_matches('\t');
                }
                if Some(line) == self.out.buf.get(delim.clone()) {
                    body_end = pos.saturating_sub(1).max(body_start);
                    next = (line_end + 1).min(self.b.len());
                    break;
                }
                pos = line_end + 1;
            }
            let vs = self.out.buf.len();
            let ss = self.out.segs.len();
            self.seg_floor = ss;
            self.push_raw(body_start, body_end);
            let w = Word {
                raw: body_start..body_end,
                val: vs..self.out.buf.len(),
                segs: ss..self.out.segs.len(),
            };
            if let Some(c) = self.out.cmds.get_mut(cmd) {
                c.stdin = Some(w);
            }
            self.i = next;
        }
    }

    /// Lex one word at `self.i`. `None` if no word starts here.
    fn word(&mut self) -> Option<Word> {
        let start = self.i;
        let vstart = self.out.buf.len();
        let seg_start = self.out.segs.len();
        self.seg_floor = seg_start;
        let len = self.b.len();
        while self.i < len {
            let c = self.b[self.i];
            match c {
                b' ' | b'\t' | b'\r' | b'\n' | b';' | b'&' | b'|' | b'<' | b'>' => break,
                b'\'' => {
                    let s = self.i + 1;
                    let e = find(self.b, s, b'\'');
                    self.push_raw(s, e);
                    self.i = (e + 1).min(len);
                }
                b'"' => {
                    self.i += 1;
                    self.double_quoted();
                }
                b'\\' => {
                    if self.peek(1) == b'\n' {
                        self.i += 2;
                    } else if self.peek(1).is_ascii_alphanumeric() {
                        // `C:\Tools\x.exe`: in bash `\T` is just `T`, but a
                        // literal backslash is far more likely a Windows path.
                        self.push_raw(self.i, self.i + 2);
                        self.i += 2;
                    } else if self.i + 1 < len {
                        let cl = char_len(self.text, self.i + 1);
                        self.push_raw(self.i + 1, self.i + 1 + cl);
                        self.i += 1 + cl;
                    } else {
                        self.push_raw(self.i, self.i + 1);
                        self.i += 1;
                    }
                }
                b'$' => match self.peek(1) {
                    b'\'' => {
                        self.i += 2;
                        self.ansi_c();
                    }
                    b'"' => {
                        self.i += 2;
                        self.double_quoted();
                    }
                    b'(' => {
                        let e = balanced(self.b, self.i + 1, b'(', b')');
                        self.push_raw(self.i, e);
                        self.i = e;
                    }
                    b'{' => {
                        let e = balanced(self.b, self.i + 1, b'{', b'}');
                        self.push_raw(self.i, e);
                        self.i = e;
                    }
                    _ => {
                        self.push_raw(self.i, self.i + 1);
                        self.i += 1;
                    }
                },
                b'`' => {
                    let e = find_unescaped(self.b, self.i + 1, b'`');
                    let e = (e + 1).min(len);
                    self.push_raw(self.i, e);
                    self.i = e;
                }
                _ => {
                    let s = self.i;
                    while self.i < len
                        && !matches!(
                            self.b[self.i],
                            b' ' | b'\t'
                                | b'\r'
                                | b'\n'
                                | b';'
                                | b'&'
                                | b'|'
                                | b'<'
                                | b'>'
                                | b'\''
                                | b'"'
                                | b'\\'
                                | b'$'
                                | b'`'
                        )
                    {
                        self.i += 1;
                    }
                    self.push_raw(s, self.i);
                }
            }
        }
        if self.i == start {
            return None;
        }
        let vend = self.out.buf.len();
        Some(Word {
            raw: start..self.i,
            val: vstart..vend,
            segs: seg_start..self.out.segs.len(),
        })
    }

    /// Copy `text[s..e]` into the value and record (or extend) a segment.
    /// Segments are only extended within the current word (`seg_floor`).
    fn push_raw(&mut self, s: usize, e: usize) {
        let e = e.min(self.b.len());
        if s >= e {
            return;
        }
        // s and e sit on ASCII delimiters or the end; `get` guards anyway.
        let Some(t) = self.text.get(s..e) else {
            return;
        };
        let at = self.out.buf.len();
        self.out.buf.push_str(t);
        let own = self.out.segs.len() > self.seg_floor;
        match self.out.segs.last_mut() {
            Some(g) if own && g.raw + g.len == s && g.val + g.len == at => {
                g.len += e - s;
            }
            _ => self.out.segs.push(Seg {
                val: at,
                raw: s,
                len: e - s,
            }),
        }
    }

    fn push_char(&mut self, c: char) {
        self.out.buf.push(c);
    }

    /// Body of `".."` (opening quote consumed); stops after the closing quote.
    fn double_quoted(&mut self) {
        let len = self.b.len();
        let mut s = self.i;
        while self.i < len {
            match self.b[self.i] {
                b'"' => {
                    self.push_raw(s, self.i);
                    self.i += 1;
                    return;
                }
                b'\\' => match self.peek(1) {
                    b'"' | b'\\' | b'$' | b'`' => {
                        self.push_raw(s, self.i);
                        self.push_raw(self.i + 1, self.i + 2);
                        self.i += 2;
                        s = self.i;
                    }
                    b'\n' => {
                        self.push_raw(s, self.i);
                        self.i += 2;
                        s = self.i;
                    }
                    _ => self.i += 1,
                },
                _ => self.i += 1,
            }
        }
        self.push_raw(s, len);
    }

    /// Body of `$'..'` (opener consumed); stops after the closing quote.
    fn ansi_c(&mut self) {
        let len = self.b.len();
        let mut s = self.i;
        while self.i < len {
            match self.b[self.i] {
                b'\'' => {
                    self.push_raw(s, self.i);
                    self.i += 1;
                    return;
                }
                b'\\' if self.i + 1 < len => {
                    self.push_raw(s, self.i);
                    self.i += 1;
                    let e = self.b[self.i];
                    self.i += 1;
                    let simple = match e {
                        b'n' => Some('\n'),
                        b't' => Some('\t'),
                        b'r' => Some('\r'),
                        b'a' => Some('\x07'),
                        b'b' => Some('\x08'),
                        b'e' | b'E' => Some('\x1b'),
                        b'f' => Some('\x0c'),
                        b'v' => Some('\x0b'),
                        b'\\' => Some('\\'),
                        b'\'' => Some('\''),
                        b'"' => Some('"'),
                        b'?' => Some('?'),
                        _ => None,
                    };
                    if let Some(c) = simple {
                        self.push_char(c);
                    } else if e == b'x' {
                        let v = self.hex(2);
                        self.push_char(v.map_or('\u{fffd}', byte_char));
                    } else if e == b'u' || e == b'U' {
                        let v = self.hex(if e == b'u' { 4 } else { 8 });
                        self.push_char(v.and_then(char::from_u32).unwrap_or('\u{fffd}'));
                    } else if e.is_ascii_digit() && e < b'8' {
                        let mut v = u32::from(e - b'0');
                        for _ in 0..2 {
                            match self.peek(0) {
                                d @ b'0'..=b'7' => {
                                    v = v * 8 + u32::from(d - b'0');
                                    self.i += 1;
                                }
                                _ => break,
                            }
                        }
                        self.push_char(byte_char(v));
                    } else if e == b'c' && self.i < len {
                        let ctl = self.b[self.i];
                        self.i += 1;
                        self.push_char(byte_char(u32::from(ctl & 0x1f)));
                    } else {
                        // Unknown escape: keep the backslash and the char.
                        self.push_char('\\');
                        self.i -= 1;
                    }
                    s = self.i;
                }
                _ => self.i += 1,
            }
        }
        self.push_raw(s, len);
    }

    fn hex(&mut self, max: usize) -> Option<u32> {
        let mut v: u32 = 0;
        let mut n = 0;
        while n < max {
            let Some(d) = (self.peek(0) as char).to_digit(16) else {
                break;
            };
            v = v.wrapping_mul(16).wrapping_add(d);
            self.i += 1;
            n += 1;
        }
        (n > 0).then_some(v)
    }
}

fn byte_char(v: u32) -> char {
    if v < 0x80 {
        char::from_u32(v).unwrap_or('\u{fffd}')
    } else {
        '\u{fffd}'
    }
}

/// Byte length of the char starting at `i` (1 if `i` is not a boundary).
fn char_len(text: &str, i: usize) -> usize {
    text.get(i..)
        .and_then(|t| t.chars().next())
        .map_or(1, char::len_utf8)
}

/// Index of the next `c` at or after `from`, or the end.
fn find(b: &[u8], from: usize, c: u8) -> usize {
    if from >= b.len() {
        return b.len();
    }
    memchr::memchr(c, &b[from..]).map_or(b.len(), |k| from + k)
}

fn find_unescaped(b: &[u8], mut i: usize, c: u8) -> usize {
    while i < b.len() {
        if b[i] == b'\\' {
            i += 2;
            continue;
        }
        if b[i] == c {
            return i;
        }
        i += 1;
    }
    b.len()
}

/// End (exclusive) of a balanced `open..close` group starting at `i` (which
/// holds `open`), skipping quoted parts. The end of input if unbalanced.
fn balanced(b: &[u8], mut i: usize, open: u8, close: u8) -> usize {
    let mut depth = 0usize;
    while i < b.len() {
        let c = b[i];
        if c == b'\\' {
            i += 2;
            continue;
        }
        if c == b'\'' {
            i = find(b, i + 1, b'\'') + 1;
            continue;
        }
        if c == b'"' {
            i = find_unescaped(b, i + 1, b'"') + 1;
            continue;
        }
        if c == open {
            depth += 1;
        } else if c == close {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return i + 1;
            }
        }
        i += 1;
    }
    b.len()
}

/// Heuristic: the text is the content of a JSON string (no bare `"`, but
/// JSON escapes such as `\"`, `\\` or `\n`).
pub fn looks_json_escaped(t: &str) -> bool {
    let b = t.as_bytes();
    let mut i = 0;
    let mut escapes = false;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                if matches!(b.get(i + 1), Some(b'"' | b'\\' | b'n' | b't' | b'r' | b'u')) {
                    escapes = true;
                }
                i += 2;
            }
            b'"' => return false,
            _ => i += 1,
        }
    }
    escapes
}

/// Decode JSON string escapes. `map[i]` is the input offset of the char that
/// produced decoded byte `i`; `map[out.len()]` is `text.len()`. So a decoded
/// span `a..b` (on char boundaries) maps to `map[a]..map[b]` in the input.
pub fn json_decode(text: &str, out: &mut String, map: &mut Vec<usize>) {
    out.clear();
    map.clear();
    let b = text.as_bytes();
    let mut i = 0;
    let push = |out: &mut String, map: &mut Vec<usize>, c: char, at: usize| {
        let n = c.len_utf8();
        out.push(c);
        map.extend(std::iter::repeat_n(at, n));
    };
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            let simple = match b[i + 1] {
                b'"' => Some('"'),
                b'\\' => Some('\\'),
                b'/' => Some('/'),
                b'b' => Some('\x08'),
                b'f' => Some('\x0c'),
                b'n' => Some('\n'),
                b'r' => Some('\r'),
                b't' => Some('\t'),
                _ => None,
            };
            if let Some(c) = simple {
                push(out, map, c, i);
                i += 2;
                continue;
            }
            if b[i + 1] == b'u'
                && let Some(hi) = hex4(b, i + 2)
            {
                let mut c = char::from_u32(hi);
                let mut n = 6;
                if (0xD800..0xDC00).contains(&hi)
                    && b.get(i + 6) == Some(&b'\\')
                    && b.get(i + 7) == Some(&b'u')
                    && let Some(lo) = hex4(b, i + 8)
                    && (0xDC00..0xE000).contains(&lo)
                {
                    c = char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00));
                    n = 12;
                }
                push(out, map, c.unwrap_or('\u{fffd}'), i);
                i += n;
                continue;
            }
        }
        let cl = char_len(text, i);
        if let Some(s) = text.get(i..i + cl) {
            out.push_str(s);
            map.extend(i..i + cl);
        }
        i += cl;
    }
    map.push(text.len());
}

fn hex4(b: &[u8], i: usize) -> Option<u32> {
    let s = b.get(i..i + 4)?;
    let mut v = 0;
    for &c in s {
        v = v * 16 + (c as char).to_digit(16)?;
    }
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(text: &str) -> Vec<Vec<String>> {
        let mut lx = Lexed::default();
        lex(text, &mut lx);
        lx.cmds
            .iter()
            .map(|c| {
                lx.cmd_words(c)
                    .iter()
                    .map(|w| lx.val(w).to_owned())
                    .collect()
            })
            .collect()
    }

    #[test]
    fn quoting() {
        assert_eq!(
            words(r#"a 'b c' "d \"e\" \$f" g\ h $'i\tj\x41' $"k""#),
            vec![vec!["a", "b c", "d \"e\" $f", "g h", "i\tjA", "k"]]
        );
        assert_eq!(words(r#"x"y"'z'"#), vec![vec!["xyz"]]);
        assert_eq!(words("a\\\nb"), vec![vec!["ab"]]);
        assert_eq!(words("''"), vec![vec![""]]);
    }

    #[test]
    fn operators_split_commands() {
        assert_eq!(
            words("a && b || c ; d | e |& f & g\nh"),
            vec![
                vec!["a"],
                vec!["b"],
                vec!["c"],
                vec!["d"],
                vec!["e"],
                vec!["f"],
                vec!["g"],
                vec!["h"]
            ]
        );
        let mut lx = Lexed::default();
        lex("a | b |& c && d", &mut lx);
        let piped: Vec<bool> = lx.cmds.iter().map(|c| c.piped).collect();
        assert_eq!(piped, vec![false, true, true, false]);
    }

    #[test]
    fn substitutions_stay_in_one_word() {
        assert_eq!(
            words("X=$(cat f | tr -d ')') Y=${A:-b c} Z=`a;b` w"),
            vec![vec![
                "X=$(cat f | tr -d ')')",
                "Y=${A:-b c}",
                "Z=`a;b`",
                "w"
            ]]
        );
    }

    #[test]
    fn redirections_are_dropped() {
        assert_eq!(
            words("cmd a > out.txt 2>&1 b < in 2>/dev/null &>log c >> x"),
            vec![vec!["cmd", "a", "b", "c"]]
        );
    }

    #[test]
    fn comments() {
        assert_eq!(words("a b # c d\ne#f"), vec![vec!["a", "b"], vec!["e#f"]]);
    }

    #[test]
    fn here_string_and_heredoc() {
        let mut lx = Lexed::default();
        let t = "docker login --password-stdin <<< 'Pw9x'";
        lex(t, &mut lx);
        let st = lx.cmds[0].stdin.clone().unwrap();
        assert_eq!(lx.val(&st), "Pw9x");
        assert_eq!(lx.locate(&st, 0, 4).map(|s| &t[s..s + 4]), Some("Pw9x"));

        let t = "cat <<'EOF' | sudo -S true\nline1\nline2\nEOF\nnext arg";
        lex(t, &mut lx);
        assert_eq!(lx.cmds.len(), 3);
        let body = lx.cmds[0].stdin.clone().unwrap();
        assert_eq!(lx.val(&body), "line1\nline2");
        assert_eq!(&t[body.raw.clone()], "line1\nline2");
        assert_eq!(lx.locate(&body, 6, 5).map(|s| &t[s..s + 5]), Some("line2"));
        assert_eq!(lx.val(&lx.cmd_words(&lx.cmds[2])[1]), "arg");

        let t = "cat <<-END\n\tbody\n\tEND\n";
        lex(t, &mut lx);
        assert_eq!(lx.val(lx.cmds[0].stdin.as_ref().unwrap()), "\tbody");
    }

    #[test]
    fn exact_spans() {
        let t = r#"a 'Qw7!x' "p q" b"cd" --o='v w' \$x $'\tz' C:\T"#;
        let mut lx = Lexed::default();
        lex(t, &mut lx);
        let w = &lx.words;
        let at =
            |k: usize, off: usize, len: usize| lx.locate(&w[k], off, len).map(|s| &t[s..s + len]);
        assert_eq!(at(1, 0, 5), Some("Qw7!x"));
        assert_eq!(at(2, 0, 3), Some("p q"));
        assert_eq!(at(3, 1, 2), Some("cd")); // inside one segment
        assert_eq!(at(3, 0, 3), None); // spans the quote
        assert_eq!(lx.val(&w[4]), "--o=v w");
        assert_eq!(at(4, 4, 3), Some("v w"));
        assert_eq!(lx.val(&w[5]), "$x");
        assert_eq!(at(5, 0, 2), Some("$x")); // escape: the value byte is still verbatim
        assert_eq!(at(6, 0, 2), None); // decoded
        assert_eq!(at(6, 1, 1), Some("z"));
        assert_eq!(lx.val(&w[7]), "C:\\T");
        assert_eq!(&t[w[3].raw.clone()], r#"b"cd""#);
    }

    #[test]
    fn json_escaped() {
        let raw = r#"psql -c \"select 1\" -d x\\y"#;
        assert!(looks_json_escaped(raw));
        assert!(!looks_json_escaped(r#"psql -c "select 1""#));
        assert!(!looks_json_escaped("plain"));
        let (mut s, mut m) = (String::new(), Vec::new());
        json_decode(raw, &mut s, &mut m);
        assert_eq!(s, r#"psql -c "select 1" -d x\y"#);
        assert_eq!(m.len(), s.len() + 1);
        let a = s.find("select").unwrap();
        assert_eq!(&raw[m[a]..m[a + 8]], "select 1");
        json_decode(r#"é😀\u12"#, &mut s, &mut m);
        assert_eq!(s, "é😀\\u12");
    }

    #[test]
    fn never_panics_on_odd_input() {
        let mut lx = Lexed::default();
        for t in [
            "\\",
            "'",
            "\"",
            "$'",
            "$'\\",
            "$'\\x",
            "$'\\u12345678'",
            "$(",
            "${",
            "`",
            "<<",
            "<<<",
            "<<-",
            ">",
            "2>",
            "a\\é",
            "$'\\cé'",
            "é'é",
            "<<E\nE",
            "<<E",
            "a <<<",
            "\"\\",
            "$\"",
        ] {
            lex(t, &mut lx);
        }
    }
}
