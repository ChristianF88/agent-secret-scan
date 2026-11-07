//! A tiny deterministic PRNG (SplitMix64): the corpus must be identical for
//! the same seed on every platform and toolchain, so no external crate.

#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }

    /// An independent stream for `label` (stable when callers are added or
    /// reordered elsewhere).
    pub fn fork(&self, label: &str) -> Rng {
        let mut h = self.0 ^ 0x51_7c_c1_b7_27_22_0a_95;
        for b in label.bytes() {
            h = (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3);
        }
        let mut r = Rng(h);
        r.next_u64();
        r
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n` (`n > 0`).
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    /// Uniform in `lo..=hi`.
    pub fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo + 1)
    }

    /// True with probability `p` percent.
    pub fn chance(&mut self, p: u32) -> bool {
        self.below(100) < p as usize
    }

    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len())]
    }

    /// One char of `alphabet` (ASCII).
    pub fn char_of(&mut self, alphabet: &str) -> char {
        alphabet.as_bytes()[self.below(alphabet.len())] as char
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let mut a = Rng::new(7);
        let mut b = Rng::new(7);
        assert_eq!(a.next_u64(), b.next_u64());
        assert_ne!(a.fork("x").next_u64(), a.fork("y").next_u64());
        assert_eq!(
            Rng::new(1).fork("x").next_u64(),
            Rng::new(1).fork("x").next_u64()
        );
        let mut r = Rng::new(3);
        assert!((0..1000).all(|_| r.range(2, 5) >= 2 && r.range(2, 5) <= 5));
    }
}
