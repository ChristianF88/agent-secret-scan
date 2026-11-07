//! Byte offset → (line, column) mapping.

/// Line starts of a buffer, built once per item that has findings.
#[derive(Debug, Clone)]
pub struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    pub fn new(data: &[u8]) -> Self {
        let mut starts = Vec::with_capacity(data.len() / 64 + 1);
        starts.push(0);
        starts.extend(memchr::memchr_iter(b'\n', data).map(|i| i + 1));
        LineIndex { starts }
    }

    /// 1-based line and 1-based column (in characters) of a byte offset.
    /// Offsets past the end map to the last position.
    pub fn position(&self, data: &[u8], offset: usize) -> (usize, usize) {
        let offset = offset.min(data.len());
        let line = self.starts.partition_point(|&s| s <= offset); // >= 1
        let start = self.starts[line - 1];
        let col = String::from_utf8_lossy(&data[start..offset])
            .chars()
            .count()
            + 1;
        (line, col)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions() {
        let d = b"ab\ncd\n\nx";
        let ix = LineIndex::new(d);
        assert_eq!(ix.position(d, 0), (1, 1));
        assert_eq!(ix.position(d, 1), (1, 2));
        assert_eq!(ix.position(d, 2), (1, 3)); // the newline itself
        assert_eq!(ix.position(d, 3), (2, 1));
        assert_eq!(ix.position(d, 6), (3, 1));
        assert_eq!(ix.position(d, 7), (4, 1));
        assert_eq!(ix.position(d, 99), (4, 2));
    }

    #[test]
    fn columns_count_characters() {
        let d = "äb=x".as_bytes();
        assert_eq!(LineIndex::new(d).position(d, 4), (1, 4));
    }
}
