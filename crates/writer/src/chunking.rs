//! Cutting content into chunks (format.md 5.1 and 5.2).
//!
//! A [`Chunker`] says where to cut. The first system has one chunker, [`Fixed`].
//! A chunker that cuts at places that depend on the content can be added later
//! without a change to the rest of the writer (format.md 5.2.4.2).

use nilperit_format::ChunkingProfile;
use std::fmt;
use std::io::{self, Read};

/// The ID of the profile for documents, email and general files (format.md 5.2.4).
pub const PROFILE_DEFAULT: u32 = 1;
/// The ID of the profile for video, photos and archives (format.md 5.2.4).
pub const PROFILE_LARGE: u32 = 2;

/// The name of the algorithm that cuts at a fixed size (format.md 5.2.4.1).
pub const ALGORITHM_FIXED: &str = "fixed";

/// The chunking profiles of a new vault (format.md 5.2.4).
pub fn default_profiles() -> Vec<ChunkingProfile> {
    let fixed = |id, max_size| ChunkingProfile {
        id,
        algorithm: ALGORITHM_FIXED.into(),
        min_size: 0,
        avg_size: 0,
        max_size,
    };
    vec![
        fixed(PROFILE_DEFAULT, 256 * 1024),
        fixed(PROFILE_LARGE, 2 * 1024 * 1024),
    ]
}

/// A chunking profile that this writer cannot use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChunkerError {
    /// The algorithm name is not known to this writer.
    UnknownAlgorithm,
    /// The sizes do not fit the algorithm.
    BadSizes,
}

impl fmt::Display for ChunkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownAlgorithm => f.write_str("the chunking algorithm is not known"),
            Self::BadSizes => f.write_str("the sizes of the chunking profile are not valid"),
        }
    }
}

impl std::error::Error for ChunkerError {}

/// A rule that says where to cut content into chunks.
pub trait Chunker {
    /// The size of the largest chunk. A caller needs a buffer of this size.
    fn max_size(&self) -> usize;

    /// Finds the end of the first chunk in `buffer`, the bytes that are not cut
    /// yet. `end` is true when there are no more bytes after the buffer.
    ///
    /// It returns the length of the chunk, which is at least 1 and at most the
    /// length of the buffer and `max_size`. It returns `None` when it needs more
    /// bytes to decide. It MUST NOT return `None` when the buffer has `max_size`
    /// bytes or more, or when `end` is true and the buffer has bytes.
    fn cut(&self, buffer: &[u8], end: bool) -> Option<usize>;
}

/// Cuts into chunks of one size. The last chunk holds the rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fixed {
    size: usize,
}

impl Fixed {
    /// A chunker for chunks of `size` bytes. The size is not 0.
    pub fn new(size: usize) -> Result<Self, ChunkerError> {
        if size == 0 {
            return Err(ChunkerError::BadSizes);
        }
        Ok(Self { size })
    }

    /// The chunker of a chunking profile of the vault config (format.md 5.2.4.1):
    /// the algorithm `fixed`, the minimum and average size 0, and a maximum size
    /// above 0.
    pub fn from_profile(profile: &ChunkingProfile) -> Result<Self, ChunkerError> {
        if profile.algorithm != ALGORITHM_FIXED {
            return Err(ChunkerError::UnknownAlgorithm);
        }
        if profile.min_size != 0 || profile.avg_size != 0 {
            return Err(ChunkerError::BadSizes);
        }
        let size = usize::try_from(profile.max_size).map_err(|_| ChunkerError::BadSizes)?;
        Self::new(size)
    }
}

impl Chunker for Fixed {
    fn max_size(&self) -> usize {
        self.size
    }

    fn cut(&self, buffer: &[u8], end: bool) -> Option<usize> {
        if buffer.len() >= self.size {
            Some(self.size)
        } else if end && !buffer.is_empty() {
            Some(buffer.len())
        } else {
            None
        }
    }
}

/// Reads from a source and gives the chunks, one by one. It holds at most one
/// chunk of the source in memory.
pub struct ChunkReader<R, C> {
    source: R,
    chunker: C,
    buffer: Vec<u8>,
    end: bool,
}

impl<R: Read, C: Chunker> ChunkReader<R, C> {
    /// Starts to cut the bytes of `source`.
    pub fn new(source: R, chunker: C) -> Self {
        Self {
            source,
            chunker,
            buffer: Vec::new(),
            end: false,
        }
    }

    /// Reads more bytes into the buffer, up to `max_size` bytes in total.
    fn fill(&mut self) -> io::Result<()> {
        let max = self.chunker.max_size();
        let have = self.buffer.len();
        if have >= max {
            // The chunker broke its rule: it did not cut a full buffer.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the chunker did not cut a full buffer",
            ));
        }
        self.buffer.resize(max, 0);
        let read = loop {
            match self.source.read(&mut self.buffer[have..]) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                other => break other,
            }
        };
        match read {
            Ok(count) => {
                self.buffer.truncate(have + count);
                self.end = count == 0;
                Ok(())
            }
            Err(e) => {
                self.buffer.truncate(have);
                Err(e)
            }
        }
    }
}

impl<R: Read, C: Chunker> Iterator for ChunkReader<R, C> {
    type Item = io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(length) = self.chunker.cut(&self.buffer, self.end) {
                let length = length.min(self.buffer.len());
                let chunk = self.buffer[..length].to_vec();
                self.buffer.drain(..length);
                return Some(Ok(chunk));
            }
            if self.end {
                return None;
            }
            if let Err(e) = self.fill() {
                // Stop after an error: the source is in an unknown state.
                self.end = true;
                self.buffer.clear();
                return Some(Err(e));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(length: usize) -> Vec<u8> {
        (0..length).map(|i| (i * 7 + i / 251) as u8).collect()
    }

    fn chunks(source: impl Read, size: usize) -> Vec<Vec<u8>> {
        ChunkReader::new(source, Fixed::new(size).unwrap())
            .map(Result::unwrap)
            .collect()
    }

    #[test]
    fn cuts_like_the_chunks_of_a_slice() {
        // `slice::chunks` is the definition of fixed-size cutting (format.md 5.2.4.1).
        for size in [1, 2, 7, 256] {
            for length in (0..=1030).step_by(if size == 1 { 97 } else { 1 }) {
                let data = data(length);
                let expected: Vec<Vec<u8>> = data.chunks(size).map(<[u8]>::to_vec).collect();
                assert_eq!(
                    chunks(&data[..], size),
                    expected,
                    "size {size} length {length}"
                );
            }
        }
    }

    #[test]
    fn the_cases_of_the_spec() {
        // Content without data has no chunk.
        assert!(chunks(&[][..], 256).is_empty());
        // Content that is not larger than one chunk is one chunk.
        assert_eq!(chunks(&data(10)[..], 256), [data(10)]);
        assert_eq!(chunks(&data(256)[..], 256), [data(256)]);
        // The last chunk holds the rest.
        let sizes: Vec<usize> = chunks(&data(600)[..], 256).iter().map(Vec::len).collect();
        assert_eq!(sizes, [256, 256, 88]);
    }

    /// A source that gives only a few bytes for each read, in a changing pattern.
    struct Trickle<'a> {
        data: &'a [u8],
        step: usize,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.step = self.step % 7 + 1;
            let count = self.step.min(self.data.len()).min(out.len());
            out[..count].copy_from_slice(&self.data[..count]);
            self.data = &self.data[count..];
            Ok(count)
        }
    }

    #[test]
    fn the_chunks_do_not_depend_on_how_the_source_reads() {
        let data = data(1000);
        let trickle = Trickle {
            data: &data,
            step: 0,
        };
        assert_eq!(chunks(trickle, 256), chunks(&data[..], 256));
    }

    #[test]
    fn retries_an_interrupted_read_and_stops_after_an_error() {
        struct Flaky {
            calls: usize,
        }
        impl Read for Flaky {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                self.calls += 1;
                match self.calls {
                    1 => Err(io::ErrorKind::Interrupted.into()),
                    2 => {
                        out[..3].copy_from_slice(b"abc");
                        Ok(3)
                    }
                    _ => Err(io::Error::other("disk")),
                }
            }
        }
        let mut reader = ChunkReader::new(Flaky { calls: 0 }, Fixed::new(8).unwrap());
        // The three bytes are kept in the buffer, then the read fails.
        assert!(reader.next().unwrap().is_err());
        // After an error there are no more chunks, and no partial chunk.
        assert!(reader.next().is_none());
    }

    #[test]
    fn a_chunker_that_never_cuts_is_an_error_and_not_a_loop() {
        struct Never;
        impl Chunker for Never {
            fn max_size(&self) -> usize {
                4
            }
            fn cut(&self, _: &[u8], _: bool) -> Option<usize> {
                None
            }
        }
        let bytes = data(100);
        let mut reader = ChunkReader::new(&bytes[..], Never);
        assert!(reader.next().unwrap().is_err());
        assert!(reader.next().is_none());
    }

    #[test]
    fn the_default_profiles_are_the_profiles_of_the_spec() {
        let profiles = default_profiles();
        let table: Vec<_> = profiles
            .iter()
            .map(|p| {
                (
                    p.id,
                    p.algorithm.as_str(),
                    p.min_size,
                    p.avg_size,
                    p.max_size,
                )
            })
            .collect();
        // Format.md 5.2.4.
        assert_eq!(
            table,
            [(1, "fixed", 0, 0, 262_144), (2, "fixed", 0, 0, 2_097_152)]
        );
        for profile in &profiles {
            assert!(Fixed::from_profile(profile).is_ok());
        }
        assert_eq!(
            Fixed::from_profile(&profiles[0]).unwrap().max_size(),
            262_144
        );
    }

    #[test]
    fn rejects_profiles_that_fixed_cannot_use() {
        let good = default_profiles().remove(0);
        let with = |change: &dyn Fn(&mut ChunkingProfile)| {
            let mut profile = good.clone();
            change(&mut profile);
            Fixed::from_profile(&profile)
        };
        assert_eq!(
            with(&|p| p.algorithm = "fastcdc-2020".into()),
            Err(ChunkerError::UnknownAlgorithm)
        );
        assert_eq!(with(&|p| p.min_size = 1), Err(ChunkerError::BadSizes));
        assert_eq!(with(&|p| p.avg_size = 1), Err(ChunkerError::BadSizes));
        assert_eq!(with(&|p| p.max_size = 0), Err(ChunkerError::BadSizes));
        assert_eq!(Fixed::new(0), Err(ChunkerError::BadSizes));
    }
}
