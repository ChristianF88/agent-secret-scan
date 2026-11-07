//! Sorted, compact object-id tables: `hash_len` bytes per id (no enum
//! padding) and a 16-bit fan-out table, so a lookup touches few cache lines.

use gix::hash::{Kind as HashKind, oid};
use rayon::prelude::*;

/// Sorted, deduplicated object ids of one hash kind.
#[derive(Debug)]
pub(crate) struct Ids {
    hash: HashKind,
    width: usize,
    bytes: Vec<u8>,
    /// `fan[k]`: index of the first id whose first two bytes are `>= k`.
    fan: Vec<u32>,
}

impl Ids {
    /// From ids of `hash` kind concatenated in `bytes`, in any order.
    pub(crate) fn new(hash: HashKind, mut bytes: Vec<u8>) -> Ids {
        let width = hash.len_in_bytes();
        match width {
            20 => sort_dedup::<20>(&mut bytes),
            32 => sort_dedup::<32>(&mut bytes),
            _ => {} // gix only knows SHA-1 and SHA-256
        }
        bytes.shrink_to_fit();
        let n = bytes.len() / width;
        let mut fan = vec![0u32; 65_537];
        let mut i = 0usize;
        for (k, slot) in fan.iter_mut().enumerate() {
            while i < n && prefix16(&bytes[i * width..]) < k {
                i += 1;
            }
            *slot = i as u32;
        }
        Ids {
            hash,
            width,
            bytes,
            fan,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len() / self.width
    }

    pub(crate) fn get(&self, i: u32) -> &oid {
        let s = i as usize * self.width;
        oid::from_bytes_unchecked(&self.bytes[s..s + self.width])
    }

    pub(crate) fn find(&self, id: &oid) -> Option<u32> {
        let b = id.as_bytes();
        if b.len() != self.width {
            return None;
        }
        let k = prefix16(b);
        let (mut lo, mut hi) = (self.fan[k] as usize, self.fan[k + 1] as usize);
        while lo < hi {
            let mid = (lo + hi) / 2;
            let s = mid * self.width;
            match self.bytes[s..s + self.width].cmp(b) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(mid as u32),
            }
        }
        None
    }

    pub(crate) fn hash(&self) -> HashKind {
        self.hash
    }
}

fn prefix16(b: &[u8]) -> usize {
    (usize::from(b[0]) << 8) | usize::from(b[1])
}

fn sort_dedup<const N: usize>(bytes: &mut Vec<u8>) {
    let (chunks, _) = bytes.as_chunks_mut::<N>();
    chunks.par_sort_unstable();
    let n = chunks.len();
    let mut w = 0usize;
    for r in 0..n {
        if w == 0 || chunks[r] != chunks[w - 1] {
            chunks[w] = chunks[r];
            w += 1;
        }
    }
    bytes.truncate(w * N);
}
