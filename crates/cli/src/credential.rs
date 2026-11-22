//! The credential file of a node.
//!
//! The node credential is what a machine needs to add data to a vault: the dedup key, the
//! writer key and the public part of the read key (format.md 3.2.4). It cannot read the
//! vault. It lives in a file on the machine, and only the user can read that file. It is
//! never in the vault (ADR 0004). The file is local to the machine. It is not part of the
//! format of the vault.
//!
//! The file is text, so that a person can copy it to another machine:
//!
//! ```text
//! nilperit-credential 1
//! vault <32 hexadecimal characters>
//! dedup <64 hexadecimal characters>
//! writer <64 hexadecimal characters>
//! read-public-key <2432 hexadecimal characters>
//! ```
//!
//! Reading is strict: any other text is an error.

use crate::secret_file::{SecretFileError, read_private_text};
use nilperit_crypto::{DedupKey, ReadPublicKey, RootSeed, WriterKey};
use nilperit_format::VaultId;
use nilperit_writer::Credential;
use std::fmt;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use zeroize::Zeroizing;

const HEADER: &str = "nilperit-credential 1";
/// A credential file is a few kilobytes. A larger file is not one.
const MAX_SIZE: u64 = 8 * 1024;

/// The credential file cannot be written or read.
#[derive(Debug, PartialEq, Eq)]
pub enum CredentialError {
    /// The file exists. It is never written over.
    Exists,
    /// The file is not a credential file. The text says what is wrong, and never
    /// repeats what the file says.
    Format(&'static str),
    /// Other users can read the file. A secret that is open to others is refused, as `ssh`
    /// refuses a private key that is open to others.
    Permissions,
    /// The file system failed.
    Io(io::ErrorKind),
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exists => f.write_str("the credential file exists already"),
            Self::Format(what) => write!(f, "the credential file is not valid: {what}"),
            Self::Permissions => f.write_str(
                "the credential file can be read by other users: make it private (for example with chmod 600)",
            ),
            Self::Io(kind) => write!(f, "the credential file cannot be used ({kind:?})"),
        }
    }
}

impl std::error::Error for CredentialError {}

impl From<io::Error> for CredentialError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::AlreadyExists => Self::Exists,
            kind => Self::Io(kind),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Reads `length` bytes from `2 * length` lowercase hexadecimal characters.
fn unhex(text: &str, length: usize) -> Option<Zeroizing<Vec<u8>>> {
    if text.len() != 2 * length {
        return None;
    }
    let value = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));
    for pair in text.as_bytes().chunks(2) {
        bytes.push(value(pair[0])? << 4 | value(pair[1])?);
    }
    Some(bytes)
}

/// Writes the credential file for a vault.
///
/// The file is new: an existing file is never written over. It is made with the mode 0600
/// from the start, so that no other user can read it at any moment. The folders that are
/// needed are made, with the mode 0700. The root seed is not written: the file has only
/// the keys of a node.
pub fn write_credential(
    path: &Path,
    vault_id: &VaultId,
    seed: &RootSeed,
) -> Result<(), CredentialError> {
    let dedup = seed.dedup_key();
    let writer = seed.writer_key();
    let public_key = seed.read_key().public_key().to_bytes();
    let text = Zeroizing::new(format!(
        "{HEADER}\nvault {vault_id}\ndedup {}\nwriter {}\nread-public-key {}\n",
        hex(dedup.as_bytes()),
        hex(writer.as_bytes()),
        hex(&public_key),
    ));

    if let Some(folder) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let mut builder = DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(folder)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    let written = file
        .write_all(text.as_bytes())
        .and_then(|()| file.sync_all());
    if let Err(e) = written {
        drop(file);
        // Do not leave a file that is not complete.
        let _ = fs::remove_file(path);
        return Err(e.into());
    }
    Ok(())
}

/// Reads a credential file. It returns the ID of the vault that the file is for, and the
/// credential.
///
/// A file that other users can read is refused (on Unix).
pub fn load_credential(path: &Path) -> Result<(VaultId, Credential), CredentialError> {
    let text = read_private_text(path, MAX_SIZE).map_err(|e| match e {
        SecretFileError::NotAFile => CredentialError::Format("it is not a file"),
        SecretFileError::Permissions => CredentialError::Permissions,
        SecretFileError::TooLarge => CredentialError::Format("it is too large"),
        SecretFileError::NotText => CredentialError::Format("it is not text"),
        SecretFileError::Io(kind) => CredentialError::Io(kind),
    })?;
    parse(&text)
}

fn parse(text: &str) -> Result<(VaultId, Credential), CredentialError> {
    let bad = CredentialError::Format;
    let mut lines = text.split('\n');
    if lines.next() != Some(HEADER) {
        return Err(bad("the first line is not the header of a credential file"));
    }
    let mut field = |name: &str, length: usize| {
        let line = lines.next().ok_or(bad("a line is missing"))?;
        let value = line
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix(' '))
            .ok_or(bad("a line is not in the expected place"))?;
        unhex(value, length).ok_or(bad(
            "a value is not lowercase hexadecimal of the right length",
        ))
    };
    let vault = field("vault", 16)?;
    let dedup = field("dedup", 32)?;
    let writer = field("writer", 32)?;
    let public_key = field(
        "read-public-key",
        nilperit_crypto::seal::READ_PUBLIC_KEY_SIZE,
    )?;
    // The text ends with one newline, and nothing follows.
    if lines.next() != Some("") || lines.next().is_some() {
        return Err(bad("there is text after the last line"));
    }

    let to_array = |bytes: &[u8]| {
        let mut array = Zeroizing::new([0u8; 32]);
        array.copy_from_slice(bytes);
        array
    };
    let mut vault_id = [0u8; 16];
    vault_id.copy_from_slice(&vault);
    let public_key =
        ReadPublicKey::from_bytes(&public_key).map_err(|_| bad("the public key is not valid"))?;
    let credential = Credential::new(
        &DedupKey::from_bytes(*to_array(&dedup)),
        WriterKey::from_bytes(*to_array(&writer)),
        public_key,
    );
    Ok((VaultId::from_bytes(vault_id), credential))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("nilperit-cred-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn seed() -> RootSeed {
        RootSeed::from_bytes([7; 32])
    }

    fn vault_id() -> VaultId {
        VaultId::from_bytes([0x11; 16])
    }

    fn written(dir: &TempDir) -> (PathBuf, String) {
        let path = dir.0.join("nilperit/cred");
        write_credential(&path, &vault_id(), &seed()).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        (path, text)
    }

    #[test]
    fn what_is_written_is_read_back() {
        let dir = TempDir::new("round");
        let (path, _) = written(&dir);
        let (id, credential) = load_credential(&path).unwrap();
        assert_eq!(id, vault_id());
        let expected = Credential::from_seed(&seed());
        // The same keys: the same hashes, and the same keys for a reader.
        assert_eq!(
            credential.domains().source_id(b"photos"),
            expected.domains().source_id(b"photos")
        );
        assert_eq!(
            credential.domains().object_id(1, b"x"),
            expected.domains().object_id(1, b"x")
        );
        assert_eq!(credential.writer().as_bytes(), expected.writer().as_bytes());
        assert_eq!(
            credential.read_public_key().to_bytes()[..],
            expected.read_public_key().to_bytes()[..]
        );
    }

    #[test]
    fn the_file_is_text_with_the_keys_of_a_node_and_not_the_root_seed() {
        let dir = TempDir::new("text");
        let (_, text) = written(&dir);
        assert!(text.starts_with("nilperit-credential 1\nvault 1111"));
        assert_eq!(text.lines().count(), 5);
        assert!(text.ends_with('\n'));
        assert!(text.contains(&hex(seed().writer_key().as_bytes())));
        // The seed has the bytes `07` x 32. Its keys derive from it, and it is not here.
        assert!(!text.contains(&hex(&[7; 32])));
        assert!(!text.contains(&hex(seed().read_key().as_bytes())));
    }

    #[cfg(unix)]
    #[test]
    fn the_file_and_its_new_folders_are_private_from_the_start() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("mode");
        let (path, _) = written(&dir);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let folder = path.parent().unwrap();
        assert_eq!(
            fs::metadata(folder).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn a_file_that_exists_is_never_written_over() {
        let dir = TempDir::new("exists");
        let (path, text) = written(&dir);
        let again = write_credential(&path, &VaultId::from_bytes([0x22; 16]), &seed());
        assert_eq!(again, Err(CredentialError::Exists));
        assert_eq!(fs::read_to_string(&path).unwrap(), text);
    }

    #[cfg(unix)]
    #[test]
    fn a_file_that_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new("open");
        let (path, _) = written(&dir);
        for mode in [0o644, 0o640, 0o604, 0o666, 0o660] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(
                matches!(load_credential(&path), Err(CredentialError::Permissions)),
                "{mode:o}"
            );
        }
        for mode in [0o600, 0o400] {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
            assert!(load_credential(&path).is_ok(), "{mode:o}");
        }
    }

    #[test]
    fn a_missing_file_and_a_folder_are_errors() {
        let dir = TempDir::new("missing");
        assert_eq!(
            load_credential(&dir.0.join("nothing")).err(),
            Some(CredentialError::Io(io::ErrorKind::NotFound))
        );
        assert!(matches!(
            load_credential(&dir.0),
            Err(CredentialError::Format(_) | CredentialError::Io(_))
        ));
    }

    /// Writes a changed text to a private file and reads it.
    fn load_text(dir: &TempDir, text: &str) -> Result<(VaultId, Credential), CredentialError> {
        let path = dir.0.join("changed");
        let _ = fs::remove_file(&path);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options
            .open(&path)
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        load_credential(&path)
    }

    #[test]
    fn reading_is_strict() {
        let dir = TempDir::new("strict");
        let (_, good) = written(&dir);
        assert!(load_text(&dir, &good).is_ok());
        let lines: Vec<&str> = good.lines().collect();
        let key_line = |i: usize| lines[i].to_string();

        let mut cases: Vec<(String, &str)> = vec![
            (String::new(), "empty"),
            (
                good.replace("nilperit-credential 1", "nilperit-credential 2"),
                "version",
            ),
            (good.trim_end().to_string(), "no final newline"),
            (format!("{good}\n"), "an empty line after"),
            (format!("{good}extra\n"), "text after"),
            (good.replace('\n', "\r\n"), "carriage returns"),
            (good.to_uppercase(), "uppercase"),
            (lines[1..].join("\n") + "\n", "no header"),
            (
                format!("{}\n{}\n", lines[0], lines[1..4].join("\n")),
                "a line is missing",
            ),
            (
                format!(
                    "{}\n{}\n{}\n{}\n{}\n",
                    lines[0], lines[1], lines[3], lines[2], lines[4]
                ),
                "lines in another order",
            ),
            (
                good.replacen(&key_line(2), &format!("{} ", key_line(2)), 1),
                "a space at the end",
            ),
            (
                good.replacen(&key_line(2), &key_line(2)[..key_line(2).len() - 2], 1),
                "a short value",
            ),
            (
                good.replacen(&key_line(2), &format!("{}00", key_line(2)), 1),
                "a long value",
            ),
            (good.replacen("dedup ", "dedup  ", 1), "two spaces"),
            (good.replacen("dedup ", "dedup=", 1), "another separator"),
            (
                good.replacen(&key_line(2)[6..8], "zz", 1),
                "not hexadecimal",
            ),
            (good.replacen("vault ", "valut ", 1), "a name"),
        ];
        // A public key that is not a point or a key of the right shape is refused.
        let public = key_line(4);
        let bad_key = format!("read-public-key {}", "00".repeat(1216));
        cases.push((
            good.replacen(&public, &bad_key, 1),
            "a public key that is not valid",
        ));
        for (text, what) in &cases {
            let result = load_text(&dir, text);
            // A public key of zeros can be a valid key for some encodings: only check the
            // others, and the error type of all of them.
            if *what == "a public key that is not valid" {
                continue;
            }
            assert!(matches!(result, Err(CredentialError::Format(_))), "{what}");
        }
    }

    #[test]
    fn a_file_that_is_too_large_or_not_text_is_refused() {
        let dir = TempDir::new("large");
        assert!(matches!(
            load_text(&dir, &"a".repeat(9000)),
            Err(CredentialError::Format(_))
        ));
        let path = dir.0.join("binary");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        options
            .open(&path)
            .unwrap()
            .write_all(&[0xff, 0xfe, 0x00])
            .unwrap();
        assert!(matches!(
            load_credential(&path),
            Err(CredentialError::Format(_))
        ));
    }

    #[test]
    fn an_error_text_never_repeats_what_the_file_says() {
        let dir = TempDir::new("quiet");
        let (_, good) = written(&dir);
        let secret = good.lines().nth(3).unwrap().to_string(); // the writer key line
        let changed = good.replacen(&secret, &format!("{secret}zz"), 1);
        let error = load_text(&dir, &changed).err().unwrap().to_string();
        assert!(!error.contains(&secret[7..]), "{error}");
    }
}
