//! Error type. Every URL stored in a variant has been passed through
//! [`crate::redact_url`], and every stderr tail through the same redaction,
//! so `Display` and `Debug` are safe to print.

use std::io;
use std::path::PathBuf;
use std::time::Duration;

/// Why [`crate::mirror_clone`] or [`crate::fetch_blobs`] failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CloneError {
    /// The URL is malformed or unsafe to pass to git.
    #[error("invalid repository URL `{url}`: {reason}")]
    InvalidUrl {
        /// Redacted URL.
        url: String,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// The URL selects a transport outside the allowlist.
    #[error("protocol `{protocol}` is not allowed for `{url}` (allowed: https, ssh, git)")]
    ProtocolNotAllowed {
        /// Redacted URL.
        url: String,
        /// The rejected transport (`ext`, `http`, `file`, ...).
        protocol: String,
    },
    /// [`crate::fetch_blobs`] got an id that is not 40 or 64 hex digits.
    #[error("object id #{index} is not a hex object id")]
    InvalidObjectId {
        /// Position in the given list.
        index: usize,
    },
    /// The git executable could not be started.
    #[error("git executable `{}` not found", binary.display())]
    GitNotFound {
        /// The program that was looked up.
        binary: PathBuf,
    },
    /// The clone ran longer than [`crate::CloneOptions::timeout`].
    #[error("git clone/fetch of `{url}` timed out after {}s", timeout.as_secs_f64())]
    Timeout {
        /// Redacted URL.
        url: String,
        /// The limit that was hit.
        timeout: Duration,
    },
    /// The clone grew beyond [`crate::CloneOptions::max_size_bytes`].
    #[error("git clone/fetch of `{url}` exceeded the size limit of {limit} bytes")]
    SizeLimit {
        /// Redacted URL.
        url: String,
        /// The limit that was hit.
        limit: u64,
    },
    /// [`crate::CloneOptions::cancel`] was set.
    #[error("git clone/fetch of `{url}` was cancelled")]
    Cancelled {
        /// Redacted URL.
        url: String,
    },
    /// git exited unsuccessfully.
    #[error("git failed for `{url}` ({}): {stderr_tail}", status_text(*status))]
    GitFailed {
        /// Redacted URL.
        url: String,
        /// Exit code, `None` if git was killed by a signal.
        status: Option<i32>,
        /// Last part of git's stderr, redacted and stripped of control characters.
        stderr_tail: String,
    },
    /// Creating or removing the temporary directory, or starting git, failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being done.
        context: &'static str,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
}

fn status_text(status: Option<i32>) -> String {
    match status {
        Some(code) => format!("exit code {code}"),
        None => "killed by a signal".to_owned(),
    }
}
