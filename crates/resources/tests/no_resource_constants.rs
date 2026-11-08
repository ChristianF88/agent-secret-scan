//! Lint: resource values (memory sizes, thread counts, cache sizes, batch
//! sizes) come from the resource plan, never from a constant elsewhere
//! (D110).
//!
//! Every crate's non-test source except this one is searched for size
//! literals (`1 << 20`, `64 * 1024`, `65536`), literal rayon batch sizes,
//! literal capacities, regex cache limits and thread counts. Fixed limits
//! that decide findings or guard against hostile input are allowed when
//! the line or the line above says `fixed:` and why. Items under
//! `#[cfg(test)]` are skipped (rustfmt puts an item's closing brace on its
//! own line at the item's indentation, and the gate enforces rustfmt).

use std::path::{Path, PathBuf};

use regex::Regex;

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs")
            && p.file_name().is_some_and(|n| n != "tests.rs")
        {
            out.push(p);
        }
    }
}

/// The lines of `text` outside `#[cfg(test)]` items, with 1-based numbers.
fn non_test_lines(text: &str) -> Vec<(usize, &str)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if line.trim_start().starts_with("#[cfg(test)]") {
            let indent = &line[..line.len() - line.trim_start().len()];
            // Further attributes, then the item.
            i += 1;
            while i < lines.len() && lines[i].trim_start().starts_with("#[") {
                i += 1;
            }
            let item = lines.get(i).map_or("", |l| l.trim_end());
            if !item.ends_with(';') {
                let close = format!("{indent}}}");
                while i < lines.len() && !lines[i].starts_with(&close) {
                    i += 1;
                }
            }
            i += 1;
            continue;
        }
        out.push((i + 1, line));
        i += 1;
    }
    out
}

/// Decimal powers of two from 4096 up (sizes written out).
fn power_of_two_sizes() -> String {
    let n: Vec<String> = (12..=40).map(|k| (1u64 << k).to_string()).collect();
    format!(r"\b({})\b", n.join("|"))
}

#[test]
fn test_items_are_skipped_and_nothing_else() {
    let text = "a\n#[cfg(test)]\nmod t;\nb\n    #[cfg(test)]\n    #[allow(x)]\n    fn f() {\n        x\n    }\n    c\n#[cfg(test)]\nmod tests {\n    fn g() {}\n}\nd\n";
    let kept: Vec<&str> = non_test_lines(text).into_iter().map(|(_, l)| l).collect();
    assert_eq!(kept, ["a", "b", "    c", "d"]);
}

#[test]
fn no_resource_constants_outside_the_plan() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let sizes = power_of_two_sizes();
    let patterns = [
        (r"\b\d+\s*<<\s*[1-3]\d\b", "a size literal"),
        (r"\b1024\s*\*|\*\s*1024\b", "a size literal"),
        (sizes.as_str(), "a size literal"),
        (
            r"with_(min|max)_len\s*\(\s*\d",
            "a literal rayon batch size",
        ),
        (r"with_capacity\s*\(\s*\d", "a literal capacity"),
        (
            r"(dfa_size_limit|cache_capacity)\s*\(\s*\d",
            "a literal regex cache",
        ),
        (
            r"num_threads\s*\(\s*\d|available_parallelism",
            "a thread count",
        ),
        (
            r"MemoryCappedHashmap::new\s*\(\s*\d",
            "a literal object cache",
        ),
        (r"\.chunks\s*\(\s*[A-Z\d]", "a batch size"),
    ]
    .map(|(p, what)| (Regex::new(p).unwrap(), what));
    let digit_separator = Regex::new(r"(\d)_(\d)").unwrap();
    // String contents are data (e.g. generated corpus text), not code.
    let string = Regex::new(r#""(\\.|[^"\\])*""#).unwrap();
    let mut files = Vec::new();
    for c in std::fs::read_dir(&crates).unwrap().flatten() {
        if c.file_name() != "resources" {
            sources(&c.path().join("src"), &mut files);
        }
    }
    assert!(files.len() > 20, "found only {} source files", files.len());
    let mut found = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        let mut previous = "";
        for (n, line) in non_test_lines(&text) {
            let code = string.replace_all(line, "\"\"");
            let code = code.split("//").next().unwrap_or("");
            let code = digit_separator.replace_all(code, "$1$2");
            let code = digit_separator.replace_all(&code, "$1$2");
            let fixed = line.contains("fixed:") || previous.contains("fixed:");
            for (re, what) in &patterns {
                if re.is_match(&code) && !fixed {
                    found.push(format!(
                        "{}:{n}: {what}: {}",
                        f.strip_prefix(&crates).unwrap_or(f).display(),
                        line.trim()
                    ));
                }
            }
            previous = line;
        }
    }
    assert!(
        found.is_empty(),
        "resource values must come from agentleaks_resources::ResourcePlan; \
         a fixed limit that decides findings needs a `fixed:` comment saying why:\n{}",
        found.join("\n")
    );
}
