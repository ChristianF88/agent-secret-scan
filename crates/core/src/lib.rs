//! Core types shared by every crate: the severity/confidence/category
//! vocabulary, the data passed between pipeline stages, and [`Secret`].

pub mod dedup;
pub mod lines;
pub mod pipeline;
pub mod secret;

pub use dedup::merge_same_secret;
pub use lines::LineIndex;
pub use pipeline::*;
pub use secret::Secret;

use serde::{Deserialize, Serialize};

/// How bad a finding is. Ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// How sure the rule is that the value is a real credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// Where a secret sits; this is the classification used in reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// A credential argument of a shell command (`sshpass -p x`).
    CliArgument,
    /// A literal piped into a credential-reading command (`echo x | docker login --password-stdin`).
    CliStdin,
    /// `NAME=value` where NAME is a credential name.
    EnvAssignment,
    /// An environment captured by an agent (shell snapshots).
    EnvCapture,
    /// A credential key in a config file.
    ConfigKey,
    /// A credential slot in a connection string.
    ConnectionString,
    /// Authorization headers, cookies, query parameters, request bodies.
    Http,
    /// "the password is ..." in prose.
    NaturalLanguage,
    /// Password hashes (crypt, NTLM, Kerberos).
    PasswordHash,
    /// Other authentication artefacts (OTP seeds, tickets, mnemonics, JWTs).
    AuthArtifact,
    /// `CREATE USER ... IDENTIFIED BY ...` and similar.
    SqlStatement,
    /// A credential file format (`.netrc`, `.pgpass`, docker `auths`).
    CredentialFile,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CliArgument => "cli_argument",
            Self::CliStdin => "cli_stdin",
            Self::EnvAssignment => "env_assignment",
            Self::EnvCapture => "env_capture",
            Self::ConfigKey => "config_key",
            Self::ConnectionString => "connection_string",
            Self::Http => "http",
            Self::NaturalLanguage => "natural_language",
            Self::PasswordHash => "password_hash",
            Self::AuthArtifact => "auth_artifact",
            Self::SqlStatement => "sql_statement",
            Self::CredentialFile => "credential_file",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_by_badness() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Low > Severity::Info);
    }
}
