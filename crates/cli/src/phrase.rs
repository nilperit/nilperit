//! Getting the recovery phrase.
//!
//! The phrase is never an argument or an environment variable: both can be seen by other
//! users and end up in logs and in shell history. It comes from, in this order:
//!
//! 1. a file that only the user can read (`--phrase-file`);
//! 2. a prompt that does not show what is typed, when the input is a terminal;
//! 3. the input, when it is not a terminal (for example `pass show nilperit | nilperit ls`).
//!
//! The text is wiped from memory when it is not needed any more. An error never repeats
//! what was typed.

use crate::environment::Environment;
use crate::secret_file::{SecretFileError, read_private_text};
use nilperit_crypto::RootSeed;
use std::fmt;
use std::io::{self, BufRead, Read};
use std::path::Path;
use zeroize::Zeroizing;

/// A phrase has 24 words of about 8 characters. This is more than enough.
const MAX_SIZE: u64 = 4 * 1024;

/// The recovery phrase cannot be had.
#[derive(Debug)]
pub enum PhraseError {
    /// No text was given.
    Missing,
    /// The file with the phrase cannot be used.
    File(SecretFileError),
    /// The input or the terminal failed.
    Input(io::ErrorKind),
    /// The text is too long to be a phrase.
    TooLarge,
    /// The text is not a recovery phrase. The text of the error is not the text that was typed.
    Invalid(nilperit_crypto::PhraseError),
}

impl fmt::Display for PhraseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str(
                "no recovery phrase was given: use --phrase-file, pipe it in, or run in a terminal",
            ),
            Self::File(SecretFileError::Permissions) => f.write_str(
                "the file with the recovery phrase can be read by other users: make it private (for example with chmod 600)",
            ),
            Self::File(SecretFileError::Io(kind)) => {
                write!(f, "the file with the recovery phrase cannot be read ({kind:?})")
            }
            Self::File(_) => f.write_str("the file with the recovery phrase is not valid"),
            Self::Input(kind) => write!(f, "the recovery phrase cannot be read ({kind:?})"),
            Self::TooLarge => f.write_str("that is too long to be a recovery phrase"),
            Self::Invalid(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for PhraseError {}

/// Gets the recovery phrase and makes the root seed.
pub fn read_seed(
    file: Option<&Path>,
    env: &Environment,
    stdin: &mut dyn BufRead,
) -> Result<RootSeed, PhraseError> {
    let text: Zeroizing<String> = if let Some(path) = file {
        read_private_text(path, MAX_SIZE).map_err(|e| match e {
            SecretFileError::TooLarge => PhraseError::TooLarge,
            other => PhraseError::File(other),
        })?
    } else if env.interactive {
        Zeroizing::new(
            rpassword::prompt_password("Recovery phrase: ")
                .map_err(|e| PhraseError::Input(e.kind()))?,
        )
    } else {
        let mut text = Zeroizing::new(String::new());
        let size = stdin
            .take(MAX_SIZE)
            .read_to_string(&mut text)
            .map_err(|e| PhraseError::Input(e.kind()))?;
        if size as u64 >= MAX_SIZE {
            return Err(PhraseError::TooLarge);
        }
        text
    };
    parse(&text)
}

/// Makes the root seed from the text of a phrase. Spaces, line breaks and capital letters
/// do not matter: a phrase can be copied from a message or a note.
pub fn parse(text: &str) -> Result<RootSeed, PhraseError> {
    let words: Vec<String> = text.split_whitespace().map(str::to_lowercase).collect();
    let words = Zeroizing::new(words);
    if words.is_empty() {
        return Err(PhraseError::Missing);
    }
    let phrase = Zeroizing::new(words.join(" "));
    RootSeed::from_phrase(&phrase).map_err(PhraseError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The phrase of the root seed `a0 a1 ... bf` (format.md A.9.1).
    const PHRASE: &str = "pass artist pottery enable foil fatigue pencil crystal produce grace hill garage arch sun solution note repeat saddle common install rookie gain wife theme";

    fn seed() -> RootSeed {
        RootSeed::from_bytes(core::array::from_fn(|i| 0xa0 + i as u8))
    }

    #[test]
    fn reads_the_phrase_of_the_appendix() {
        assert_eq!(parse(PHRASE).unwrap().as_bytes(), seed().as_bytes());
    }

    #[test]
    fn spaces_line_breaks_and_capitals_do_not_matter() {
        let messy = format!("  {}\r\n", PHRASE.to_uppercase().replace(' ', " \n  "));
        assert_eq!(parse(&messy).unwrap().as_bytes(), seed().as_bytes());
        assert_eq!(
            parse(&format!("{PHRASE}\n")).unwrap().as_bytes(),
            seed().as_bytes()
        );
    }

    #[test]
    fn what_is_not_a_phrase_is_an_error_that_does_not_repeat_it() {
        assert!(matches!(parse(""), Err(PhraseError::Missing)));
        assert!(matches!(parse(" \n\t "), Err(PhraseError::Missing)));
        // Too few words, a word that is not in the list, and a wrong checksum.
        let short = "pass artist pottery";
        let unknown = PHRASE.replacen("pass", "passs", 1);
        let checksum = PHRASE.replacen("theme", "then", 1);
        for text in [short, &unknown, &checksum] {
            let error = parse(text).unwrap_err().to_string();
            assert!(error.contains("recovery phrase"), "{error}");
            assert!(!error.contains("artist"), "{error}");
            assert!(!error.contains("pottery"), "{error}");
        }
    }

    #[test]
    fn the_input_is_read_when_it_is_not_a_terminal() {
        let env = Environment::default();
        let mut input = std::io::Cursor::new(format!("{PHRASE}\n").into_bytes());
        let read = read_seed(None, &env, &mut input).unwrap();
        assert_eq!(read.as_bytes(), seed().as_bytes());
        let mut empty = std::io::empty();
        assert!(matches!(
            read_seed(None, &env, &mut empty),
            Err(PhraseError::Missing)
        ));
        // Text that is too long is refused, and not read to the end.
        let mut long = std::io::Cursor::new(vec![b'a'; 100_000]);
        assert!(matches!(
            read_seed(None, &env, &mut long),
            Err(PhraseError::TooLarge)
        ));
    }
}
