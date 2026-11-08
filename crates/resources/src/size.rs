//! `--max-memory` values and human-readable sizes.

use std::fmt;
use std::str::FromStr;

/// A memory budget as given by the user: bytes, or a percentage of the
/// memory available to the process (the smaller of RAM and the cgroup
/// limit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryLimit {
    Bytes(u64),
    /// 1 to 100.
    Percent(u8),
}

impl FromStr for MemoryLimit {
    type Err = String;

    /// `1073741824`, `512M`, `1.5G`, `2GiB`, `64m`, `25%`. Suffixes K, M,
    /// G, T (optionally followed by `iB` or `B`) are powers of 1024.
    fn from_str(s: &str) -> Result<Self, String> {
        let bad = || {
            format!(
                "invalid size `{s}`: expected bytes, a number with K, M, G or T, or a percentage"
            )
        };
        let t = s.trim();
        if let Some(p) = t.strip_suffix('%') {
            let p: u8 = p.trim().parse().map_err(|_| bad())?;
            if !(1..=100).contains(&p) {
                return Err(format!("invalid size `{s}`: a percentage is 1% to 100%"));
            }
            return Ok(MemoryLimit::Percent(p));
        }
        let digits = t
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(t.len());
        let (num, unit) = t.split_at(digits);
        let shift = match unit.trim().to_ascii_lowercase().as_str() {
            "" | "b" => 0,
            "k" | "kb" | "kib" => 10,
            "m" | "mb" | "mib" => 20,
            "g" | "gb" | "gib" => 30,
            "t" | "tb" | "tib" => 40,
            _ => return Err(bad()),
        };
        let (whole, frac) = num.split_once('.').unwrap_or((num, ""));
        if whole.is_empty() && frac.is_empty() || frac.len() > 6 {
            return Err(bad());
        }
        let parse = |d: &str| -> Result<u128, String> {
            if d.is_empty() {
                Ok(0)
            } else {
                d.parse().map_err(|_| bad())
            }
        };
        let scale = 10u128.pow(frac.len() as u32);
        let bytes = parse(whole)?
            .checked_mul(scale)
            .and_then(|v| v.checked_add(parse(frac).ok()?))
            .and_then(|v| v.checked_mul(1u128 << shift))
            .ok_or_else(bad)?
            / scale;
        u64::try_from(bytes)
            .map(MemoryLimit::Bytes)
            .map_err(|_| bad())
    }
}

/// Bytes shown as B, KiB, MiB, GiB or TiB with one decimal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size(pub u64);

impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
        let mut v = self.0 as f64;
        let mut u = 0;
        while v >= 1024.0 && u + 1 < UNITS.len() {
            v /= 1024.0;
            u += 1;
        }
        if u == 0 {
            write!(f, "{} B", self.0)
        } else {
            write!(f, "{v:.1} {}", UNITS[u])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sizes_and_percentages() {
        let ok = |s: &str| s.parse::<MemoryLimit>().unwrap();
        assert_eq!(ok("1073741824"), MemoryLimit::Bytes(1 << 30));
        assert_eq!(ok("512M"), MemoryLimit::Bytes(512 << 20));
        assert_eq!(ok("512mb"), MemoryLimit::Bytes(512 << 20));
        assert_eq!(ok("2GiB"), MemoryLimit::Bytes(2 << 30));
        assert_eq!(ok("1.5G"), MemoryLimit::Bytes(3 << 29));
        assert_eq!(ok(" 64 k "), MemoryLimit::Bytes(64 << 10));
        assert_eq!(ok(".5T"), MemoryLimit::Bytes(1 << 39));
        assert_eq!(ok("25%"), MemoryLimit::Percent(25));
        for bad in [
            "",
            "M",
            "1.2.3G",
            "12X",
            "0%",
            "101%",
            "-1G",
            "1e9",
            "99999999999T",
        ] {
            assert!(bad.parse::<MemoryLimit>().is_err(), "{bad}");
        }
    }

    #[test]
    fn shows_sizes() {
        assert_eq!(Size(100).to_string(), "100 B");
        assert_eq!(Size(64 << 10).to_string(), "64.0 KiB");
        assert_eq!(Size(3 << 29).to_string(), "1.5 GiB");
    }
}
