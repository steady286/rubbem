pub struct Chunk<I> {
    iter: I,
    chunk_size: usize
}

impl<I> Chunk<I> {
    pub fn new(iter: I, chunk_size: usize) -> Chunk<I>
    {
        assert!(chunk_size > 0);
        Chunk {
            iter: iter,
            chunk_size: chunk_size
        }
    }
}

impl<I> Iterator for Chunk<I> where
    I: Iterator + Sized
{
    type Item = Vec<I::Item>;

    fn next(&mut self) -> Option<Vec<I::Item>> {
        let iter = &mut self.iter;

        let mut chunk: Vec<I::Item> = vec![];
        for _ in 0..self.chunk_size {
            let next = break_on_none!(iter.next());
            chunk.push(next);
        }

        match chunk.len() {
            0 => None,
            _ => Some(chunk)
        }
    }
}

pub trait CreateChunk : Iterator {
    fn chunk(self, chunk_size: usize) -> Chunk<Self> where
        Self: Sized,
    {
        Chunk::new(self, chunk_size)
    }
}

impl<T: ?Sized> CreateChunk for T where T: Iterator { }

#[cfg(test)]
mod tests {
    use super::CreateChunk;

    #[test]
    fn test_get_chunks_exact() {
        let chunks: Vec<Vec<u8>> = (0u8..12).chunk(3).collect();
        assert_eq!(chunks, vec![ vec![0, 1, 2], vec![3, 4, 5], vec![6, 7, 8], vec![9, 10, 11] ])
    }

    #[test]
    fn test_get_chunks_partial() {
        let chunks: Vec<Vec<u8>> = (0u8..11).chunk(3).collect();
        assert_eq!(chunks, vec![ vec![0, 1, 2], vec![3, 4, 5], vec![6, 7, 8], vec![9, 10] ])
    }

    #[test]
    fn test_get_chunks_different_size() {
        let chunks: Vec<Vec<u8>> = (0u8..11).chunk(5).collect();
        assert_eq!(chunks, vec![ vec![0, 1, 2, 3, 4], vec![5, 6, 7, 8, 9], vec![10] ])
    }

    #[test]
    fn test_get_chunks_empty() {
        let chunks: Vec<Vec<u8>> = (0u8..0).chunk(3).collect();
        let expected: Vec<Vec<u8>> = vec![];
        assert_eq!(chunks, expected);
    }
}
