//! Analyzers turn routed text into candidates, and the filter stage decides
//! which candidates are reported.

pub mod filter;
pub mod keyed;
pub mod regex_rules;

pub use regex_rules::{RegexAnalyzer, Scratch};
