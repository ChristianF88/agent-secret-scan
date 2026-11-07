//! Precision/recall evaluation of the scan engine on a labelled corpus.
//!
//! # Corpus format
//!
//! ```text
//! <corpus>/<case>/<files...>        scanned exactly like `agent-secret-scan local --all-files`
//! <corpus>/<case>/labels.json       what the files contain (never scanned)
//! ```
//!
//! `labels.json` (schema 1):
//!
//! ```json
//! {
//!   "schema": 1,
//!   "labels": [
//!     {"file": ".claude/settings.local.json", "line": 4, "secret": "Kq7#vR2m",
//!      "category": "cli_argument", "rule": "shell.cli-arg", "style": "random",
//!      "template": "cmd.mysql.attached", "optional": false}
//!   ],
//!   "provenance": [{"file": ".claude/settings.local.json", "line": 5, "lines": 1, "template": "neg.docker-run-port"}]
//! }
//! ```
//!
//! - A label is one expected secret: `file` (relative to the case
//!   directory), `line` (1-based; omit to match any line), and either
//!   `secret` (the raw value; corpora hold invented values only) or
//!   `secret_blake3` (hex BLAKE3 of the value, for sanitised real files).
//!   `category` is required; `rule`, `style` and `template` are optional
//!   and only group the statistics.
//! - `optional: true` marks values that may or may not be reported (for
//!   example placeholder-looking passwords, which D60 reports on purpose):
//!   they count neither as false positive nor as false negative.
//! - `provenance` (optional) names the generator template behind each
//!   line, so false positives can be grouped by what produced them.
//! - Every finding that matches no label is a false positive; every
//!   non-optional label no finding matches is a false negative. A finding
//!   matches a label when the file and line agree and the values are equal
//!   (or, for raw labels, one contains the other: counted as `inexact`).

pub mod corpus;
pub mod generate;
pub mod report;
pub mod rng;
pub mod score;
mod templates;

pub use corpus::{Case, Label, Labels, Provenance};
pub use score::{Counts, Evaluation, evaluate};
