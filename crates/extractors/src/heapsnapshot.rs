//! V8 heap snapshots (`*.heapsnapshot`): the `strings` table only.
//!
//! A snapshot is one JSON object (`{"snapshot": {...}, "nodes": [...],
//! "edges": [...], ..., "strings": [...]}`) that can be hundreds of MB.
//! It is streamed: every top-level value except `strings` is skipped with
//! a byte-level scanner (no tree is built), and each string of the table
//! is decoded into one reused buffer and handed to the caller with its
//! index. Memory is bounded by the longest string kept (`max_len`).

use std::io::{self, BufRead};

/// Why a snapshot could not be read. Static text only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub &'static str);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Error {}

/// File name suffix of heap snapshots.
pub fn is_heapsnapshot(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.to_ascii_lowercase().ends_with(".heapsnapshot")
}

/// What [`strings`] read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    /// Strings in the table.
    pub strings: usize,
    /// Strings longer than `max_len` (not delivered).
    pub too_long: usize,
}

/// Call `f(index, string)` for every entry of the snapshot's `strings`
/// table. Strings longer than `max_len` bytes (UTF-8) are skipped and
/// counted. Reading stops after the table.
pub fn strings<R: BufRead>(
    r: R,
    max_len: usize,
    f: &mut dyn FnMut(usize, &str),
) -> Result<Summary, Error> {
    let mut s = Scanner {
        r,
        buf: Vec::new(),
        max_len,
    };
    s.ws()?;
    s.expect(b'{')?;
    loop {
        s.ws()?;
        match s.next()? {
            b'}' => return Err(Error("no strings table")),
            b'"' => {}
            _ => return Err(Error("not a heap snapshot")),
        }
        let is_strings = s.string(Some(16))? && s.buf == b"strings";
        s.ws()?;
        s.expect(b':')?;
        s.ws()?;
        if is_strings {
            return s.table(f);
        }
        s.skip_value()?;
        s.ws()?;
        match s.next()? {
            b',' => {}
            b'}' => return Err(Error("no strings table")),
            _ => return Err(Error("malformed JSON")),
        }
    }
}

struct Scanner<R> {
    r: R,
    buf: Vec<u8>,
    max_len: usize,
}

fn io_err(_: io::Error) -> Error {
    Error("read error")
}

impl<R: BufRead> Scanner<R> {
    fn peek(&mut self) -> Result<Option<u8>, Error> {
        Ok(self.r.fill_buf().map_err(io_err)?.first().copied())
    }

    fn next(&mut self) -> Result<u8, Error> {
        let b = self.peek()?.ok_or(Error("truncated snapshot"))?;
        self.r.consume(1);
        Ok(b)
    }

    fn expect(&mut self, want: u8) -> Result<(), Error> {
        if self.next()? == want {
            Ok(())
        } else {
            Err(Error("malformed JSON"))
        }
    }

    fn ws(&mut self) -> Result<(), Error> {
        loop {
            let chunk = self.r.fill_buf().map_err(io_err)?;
            let n = chunk
                .iter()
                .take_while(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
                .count();
            let all = n == chunk.len() && n > 0;
            self.r.consume(n);
            if !all {
                return Ok(());
            }
        }
    }

    /// Skip one JSON value (the opening byte not yet consumed). Arrays of
    /// numbers (`nodes`, `edges`) are skipped a buffer at a time.
    fn skip_value(&mut self) -> Result<(), Error> {
        let mut depth = 0usize;
        loop {
            let chunk = self.r.fill_buf().map_err(io_err)?;
            if chunk.is_empty() {
                return Err(Error("truncated snapshot"));
            }
            // Fast path: everything up to the next quote or bracket.
            let n = chunk
                .iter()
                .position(|b| matches!(b, b'"' | b'[' | b']' | b'{' | b'}' | b','))
                .unwrap_or(chunk.len());
            if n > 0 {
                self.r.consume(n);
                continue;
            }
            match chunk[0] {
                b'"' => {
                    self.r.consume(1);
                    self.string(Some(0))?;
                }
                b'[' | b'{' => {
                    self.r.consume(1);
                    depth += 1;
                }
                b']' | b'}' => {
                    if depth == 0 {
                        return Ok(()); // ends a scalar; the caller checks it
                    }
                    self.r.consume(1);
                    depth -= 1;
                }
                _ => {
                    // `,`: ends a scalar at depth 0.
                    if depth == 0 {
                        return Ok(());
                    }
                    self.r.consume(1);
                }
            }
            if depth == 0 {
                return Ok(());
            }
        }
    }

    /// Read a string body (after the opening quote) into `buf`, keeping at
    /// most `keep` bytes (`None`: `max_len`). Returns whether it fit.
    fn string(&mut self, keep: Option<usize>) -> Result<bool, Error> {
        let keep = keep.unwrap_or(self.max_len);
        self.buf.clear();
        let mut fits = true;
        loop {
            let chunk = self.r.fill_buf().map_err(io_err)?;
            if chunk.is_empty() {
                return Err(Error("truncated snapshot"));
            }
            let n = chunk
                .iter()
                .position(|&b| b == b'"' || b == b'\\')
                .unwrap_or(chunk.len());
            if fits {
                if self.buf.len() + n <= keep {
                    self.buf.extend_from_slice(&chunk[..n]);
                } else {
                    fits = false;
                }
            }
            let stop = chunk.get(n).copied();
            self.r.consume(n);
            match stop {
                None => continue,
                Some(b'"') => {
                    self.r.consume(1);
                    return Ok(fits);
                }
                Some(_) => {
                    self.r.consume(1);
                    let c = self.escape()?;
                    if fits {
                        let mut tmp = [0u8; 4];
                        let e = c.encode_utf8(&mut tmp).as_bytes();
                        if self.buf.len() + e.len() <= keep {
                            self.buf.extend_from_slice(e);
                        } else {
                            fits = false;
                        }
                    }
                }
            }
        }
    }

    /// One escape sequence after `\`.
    fn escape(&mut self) -> Result<char, Error> {
        Ok(match self.next()? {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let hi = self.hex4()?;
                if (0xD800..0xDC00).contains(&hi) {
                    // A high surrogate: a low one should follow.
                    if self.peek()? == Some(b'\\') {
                        self.r.consume(1);
                        if self.next()? != b'u' {
                            return Ok(char::REPLACEMENT_CHARACTER);
                        }
                        let lo = self.hex4()?;
                        if (0xDC00..0xE000).contains(&lo) {
                            let c = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                            return Ok(char::from_u32(c).unwrap_or(char::REPLACEMENT_CHARACTER));
                        }
                    }
                    char::REPLACEMENT_CHARACTER
                } else {
                    char::from_u32(hi).unwrap_or(char::REPLACEMENT_CHARACTER)
                }
            }
            _ => return Err(Error("bad escape")),
        })
    }

    fn hex4(&mut self) -> Result<u32, Error> {
        let mut v = 0u32;
        for _ in 0..4 {
            let d = (self.next()? as char)
                .to_digit(16)
                .ok_or(Error("bad escape"))?;
            v = v * 16 + d;
        }
        Ok(v)
    }

    /// The `strings` array.
    fn table(&mut self, f: &mut dyn FnMut(usize, &str)) -> Result<Summary, Error> {
        let mut sum = Summary::default();
        self.expect(b'[')?;
        self.ws()?;
        if self.peek()? == Some(b']') {
            return Ok(sum);
        }
        loop {
            self.ws()?;
            self.expect(b'"')?;
            if self.string(None)? {
                f(sum.strings, &String::from_utf8_lossy(&self.buf));
            } else {
                sum.too_long += 1;
            }
            sum.strings += 1;
            self.ws()?;
            match self.next()? {
                b',' => {}
                b']' => return Ok(sum),
                _ => return Err(Error("malformed strings table")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(json: &str, max: usize) -> (Result<Summary, Error>, Vec<(usize, String)>) {
        let mut got = Vec::new();
        // A tiny buffer exercises every chunk boundary.
        let r = io::BufReader::with_capacity(3, json.as_bytes());
        let res = strings(r, max, &mut |i, s| got.push((i, s.to_owned())));
        (res, got)
    }

    #[test]
    fn reads_only_the_strings_table() {
        let snap = r#"{"snapshot":{"meta":{"node_fields":["type","name"],"x":"a\"]}"},"node_count":2},
 "nodes":[9,1,0,3,-1,2.5e3],"edges":[],"trace_tree":[[1,{"a":"}"}]],
 "strings":["<dummy>","sshpass -p Heap9Pw ssh h","esc \"q\" \\ é 😀 \ud800x", ""],
 "after":[1]}"#;
        let (res, got) = run(snap, 1024);
        assert_eq!(
            res,
            Ok(Summary {
                strings: 4,
                too_long: 0
            })
        );
        assert_eq!(got[1], (1, "sshpass -p Heap9Pw ssh h".to_owned()));
        assert_eq!(got[2].1, "esc \"q\" \\ é 😀 \u{FFFD}x");
        assert_eq!(got[3], (3, String::new()));
    }

    #[test]
    fn long_strings_are_skipped_and_counted() {
        let (res, got) = run(r#"{"strings":["short","a much longer string"]}"#, 8);
        assert_eq!(res.unwrap().too_long, 1);
        assert_eq!(got, [(0, "short".to_owned())]);
    }

    #[test]
    fn errors() {
        assert_eq!(run("", 8).0, Err(Error("truncated snapshot")));
        assert_eq!(run("[1]", 8).0, Err(Error("malformed JSON")));
        assert_eq!(
            run(r#"{"nodes":[1,2]}"#, 8).0,
            Err(Error("no strings table"))
        );
        assert_eq!(
            run(r#"{"strings":["a","b"#, 8).0,
            Err(Error("truncated snapshot"))
        );
        assert_eq!(run(r#"{"strings":[1]}"#, 8).0, Err(Error("malformed JSON")));
        assert!(run(r#"{"a":]}"#, 8).0.is_err());
        // Top-level scalars before the table.
        let (res, got) = run(r#"{"n":5, "s":"x}", "t":true ,"strings":["y"]}"#, 8);
        assert_eq!(res.unwrap().strings, 1);
        assert_eq!(got, [(0, "y".to_owned())]);
        assert_eq!(run(r#"{"n":5}"#, 8).0, Err(Error("no strings table")));
    }

    #[test]
    fn heapsnapshot_names() {
        assert!(is_heapsnapshot("x/Heap-2026.heapsnapshot"));
        assert!(!is_heapsnapshot("x/heapsnapshot.json"));
    }
}
