//! Changing bytes at random, with a generator that anyone can run again.
//!
//! The mutations are the usual ones of a fuzzer: flip a bit, set a byte to a value that is
//! often a boundary, cut, insert, delete, repeat a part, write a size field with a large value,
//! and splice two inputs. The generator is a small xorshift: the same seed gives the same
//! inputs, on every system, so a failure of a test can be run again.

/// A pseudo-random number generator (xorshift64*). It is NOT secure: it is only for tests.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        // A state of 0 would stay 0.
        Self(seed | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A number below `n`. It is 0 when `n` is 0.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }
}

/// The values that are often at the edge of a rule: the sizes of CBOR integers, the signs, and
/// the limits of the integer types.
const BYTES: [u8; 12] = [
    0x00, 0x01, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x7f, 0x80, 0xa0, 0xbf, 0xff,
];
const NUMBERS: [u64; 10] = [
    0,
    1,
    0xff,
    0x100,
    0xffff,
    0x1_0000,
    0x7fff_ffff,
    0xffff_ffff,
    0x1_0000_0000,
    u64::MAX,
];

/// The most bytes that a mutated input has, so that the inputs stay small.
const MAX_LEN: usize = 1 << 16;

/// Changes `input` with one to four mutations. `donors` are other inputs, for splicing.
pub fn mutate(rng: &mut Rng, input: &[u8], donors: &[Vec<u8>]) -> Vec<u8> {
    let mut out = input.to_vec();
    for _ in 0..=rng.below(4) {
        apply(rng, &mut out, donors);
    }
    out.truncate(MAX_LEN);
    out
}

fn apply(rng: &mut Rng, out: &mut Vec<u8>, donors: &[Vec<u8>]) {
    let len = out.len();
    match rng.below(10) {
        0 if len > 0 => {
            let i = rng.below(len);
            out[i] ^= 1 << rng.below(8);
        }
        1 if len > 0 => {
            let i = rng.below(len);
            out[i] = rng.byte();
        }
        2 if len > 0 => {
            let i = rng.below(len);
            out[i] = BYTES[rng.below(BYTES.len())];
        }
        3 => out.truncate(rng.below(len + 1)),
        4 if len > 0 => {
            let start = rng.below(len);
            let end = (start + 1 + rng.below(8)).min(len);
            out.drain(start..end);
        }
        5 => {
            let at = rng.below(len + 1);
            let count = 1 + rng.below(8);
            let bytes: Vec<u8> = (0..count).map(|_| rng.byte()).collect();
            out.splice(at..at, bytes);
        }
        6 if len > 0 => {
            // Repeat a part: a count or a length that is longer than the data.
            let start = rng.below(len);
            let end = (start + 1 + rng.below(16)).min(len);
            let part = out[start..end].to_vec();
            out.splice(end..end, part);
        }
        7 if len > 0 => {
            // A size field with a value at an edge, in the width of an integer.
            let value = NUMBERS[rng.below(NUMBERS.len())];
            let width = [1usize, 2, 4, 8][rng.below(4)].min(len);
            let at = rng.below(len - width + 1);
            let little_endian = value.to_le_bytes();
            let big_endian = value.to_be_bytes();
            for k in 0..width {
                out[at + k] = if rng.below(2) == 0 {
                    little_endian[k]
                } else {
                    big_endian[8 - width + k]
                };
            }
        }
        8 if !donors.is_empty() => {
            // The start of this input and the end of another.
            let donor = &donors[rng.below(donors.len())];
            out.truncate(rng.below(len + 1));
            let from = rng.below(donor.len() + 1);
            out.extend_from_slice(&donor[from..]);
        }
        9 if len > 1 => {
            let (a, b) = (rng.below(len), rng.below(len));
            out.swap(a, b);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_gives_the_same_inputs() {
        let run = |seed| {
            let mut rng = Rng::new(seed);
            (0..50)
                .map(|_| mutate(&mut rng, b"some input of a few bytes", &[b"donor".to_vec()]))
                .collect::<Vec<_>>()
        };
        assert_eq!(run(1), run(1));
        assert_ne!(run(1), run(2));
    }

    #[test]
    fn the_mutations_change_inputs_and_keep_them_small() {
        let mut rng = Rng::new(7);
        let input = vec![0u8; 100];
        let mut changed = 0;
        for _ in 0..1000 {
            let out = mutate(&mut rng, &input, &[]);
            assert!(out.len() <= MAX_LEN);
            changed += usize::from(out != input);
        }
        assert!(changed > 800, "{changed}");
        // An empty input is mutated without a panic, and so is an input of one byte.
        for start in [Vec::new(), vec![1u8]] {
            for _ in 0..1000 {
                mutate(&mut rng, &start, &[Vec::new(), vec![9]]);
            }
        }
    }
}
