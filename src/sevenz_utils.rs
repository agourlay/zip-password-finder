use crate::finder_errors::FinderError;
use sevenz_rust2::{ArchiveReader, Error as SevenZError, Password};
use std::io::{self, Cursor};
use std::path::Path;
use std::sync::Arc;

// 7z archives start with the 6-byte signature "7z\xBC\xAF\x27\x1C".
const SEVENZ_SIGNATURE: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// Cheap magic-byte check so archive-type routing does not depend on the file
/// extension.
pub fn has_sevenz_signature(bytes: &[u8]) -> bool {
    bytes.len() >= SEVENZ_SIGNATURE.len() && bytes[..SEVENZ_SIGNATURE.len()] == SEVENZ_SIGNATURE
}

/// A 7z archive that has been read into memory and confirmed to be encrypted.
///
/// The whole file is kept in memory (behind an `Arc`) because every candidate
/// re-opens the archive to attempt decryption; loading once and sharing the
/// bytes across workers avoids re-reading the file per password.
pub struct ValidatedSevenZip {
    pub bytes: Arc<Vec<u8>>,
}

/// A wrong-password error is anything the reader raises while decrypting header
/// or content with the wrong key: a bad-password hint, a failed CRC check, or a
/// decode/IO failure on the resulting garbage (the in-memory `Cursor` never
/// produces a genuine IO error). Everything else — an unsupported codec, a
/// malformed container — is a structural problem the caller must surface.
fn is_wrong_password(e: &SevenZError) -> bool {
    matches!(
        e,
        SevenZError::MaybeBadPassword(_)
            | SevenZError::ChecksumVerificationFailed
            | SevenZError::NextHeaderCrcMismatch
            | SevenZError::PasswordRequired
            | SevenZError::Io(_, _)
    )
}

/// Attempt to decrypt `archive_bytes` with `password`.
///
/// Returns `Ok(true)` if the password is correct, `Ok(false)` if it is wrong,
/// and `Err` for a structural problem (unsupported compression method, corrupt
/// container) that no password can resolve.
///
/// Correctness is established by fully reading the first non-empty entry, which
/// forces the AES-256 decrypt plus the stored CRC-32 check; a wrong key yields
/// garbage that fails to decode or fails the checksum. For header-encrypted
/// archives (`-mhe=on`) the wrong key already fails when the reader parses the
/// encrypted metadata, before any entry is read.
pub fn try_password(archive_bytes: &[u8], password: &str) -> Result<bool, SevenZError> {
    let cursor = Cursor::new(archive_bytes);
    let mut reader = match ArchiveReader::new(cursor, Password::from(password)) {
        Ok(reader) => reader,
        Err(e) => {
            return if is_wrong_password(&e) {
                Ok(false)
            } else {
                Err(e)
            };
        }
    };

    // Read the first non-empty entry to force decryption + CRC validation, then
    // stop. Directories and empty files carry no encrypted stream, so they
    // prove nothing about the password.
    let mut checked_content = false;
    let mut entry_verified = false;
    let iter_result = reader.for_each_entries(|entry, rd| {
        if !entry.has_stream() || entry.size() == 0 {
            return Ok(true); // keep looking for a content entry
        }
        checked_content = true;
        let expected = entry.size();
        // Draining the reader decrypts + decompresses the stream. The reader's
        // internal CRC-32 check only fires once the full `expected` size is
        // produced, so both signals matter:
        //   - an error means the decode or the CRC failed  -> wrong password;
        //   - a short read means the wrong key produced garbage that stopped
        //     early, skipping the CRC gate entirely         -> wrong password.
        // Only a complete, error-free read is the right password.
        entry_verified = matches!(io::copy(rd, &mut io::sink()), Ok(n) if n == expected);
        Ok(false) // one content entry is enough
    });

    match iter_result {
        Ok(()) => {
            if checked_content {
                Ok(entry_verified)
            } else {
                // No content entry to validate against. Reaching here means the
                // (possibly encrypted) headers parsed cleanly, which for a
                // header-encrypted archive already implies the right password.
                Ok(true)
            }
        }
        Err(e) => {
            if is_wrong_password(&e) {
                Ok(false)
            } else {
                Err(e)
            }
        }
    }
}

/// Read a `.7z` file into memory and confirm it is a password-protected 7z
/// archive worth attacking.
///
/// Fails if the file is not a 7z container, if it is not encrypted (a random
/// probe password decrypts it), or if it uses a codec this build cannot decode.
pub fn validate_sevenz(file_path: &Path) -> Result<ValidatedSevenZip, FinderError> {
    let bytes = std::fs::read(file_path)?;

    if !has_sevenz_signature(&bytes) {
        return Err(FinderError::InvalidSevenZip {
            message: "not a valid 7z archive (bad signature)".to_string(),
        });
    }

    // Probe with a password that cannot be the real one. If it "succeeds" the
    // archive is not encrypted; a structural error means we could never crack it
    // regardless of password, so surface it now instead of looping forever.
    let probe = "\u{1}zip-password-finder-probe\u{1}";
    match try_password(&bytes, probe) {
        Ok(false) => Ok(ValidatedSevenZip {
            bytes: Arc::new(bytes),
        }),
        Ok(true) => Err(FinderError::InvalidSevenZip {
            message: "archive is not password-protected (nothing to crack)".to_string(),
        }),
        Err(e) => Err(FinderError::InvalidSevenZip {
            message: format!("cannot process this 7z archive: {e}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Both fixtures hold the same payload behind the password "abc":
    // - 3.test.txt.7z: content encrypted, headers in clear (7z -mhe=off)
    // - 3.test.hdr.7z: headers encrypted as well (7z -mhe=on)
    const CONTENT_ENCRYPTED: &str = "test-files/3.test.txt.7z";
    const HEADER_ENCRYPTED: &str = "test-files/3.test.hdr.7z";

    fn read(path: &str) -> Vec<u8> {
        std::fs::read(path).expect("fixture should exist")
    }

    #[test]
    fn correct_password_content_encrypted() {
        assert!(try_password(&read(CONTENT_ENCRYPTED), "abc").unwrap());
    }

    #[test]
    fn correct_password_header_encrypted() {
        assert!(try_password(&read(HEADER_ENCRYPTED), "abc").unwrap());
    }

    #[test]
    fn wrong_password_content_encrypted() {
        assert!(!try_password(&read(CONTENT_ENCRYPTED), "abd").unwrap());
        assert!(!try_password(&read(CONTENT_ENCRYPTED), "ab").unwrap());
        assert!(!try_password(&read(CONTENT_ENCRYPTED), "").unwrap());
    }

    #[test]
    fn wrong_password_header_encrypted() {
        assert!(!try_password(&read(HEADER_ENCRYPTED), "abd").unwrap());
        assert!(!try_password(&read(HEADER_ENCRYPTED), "zzz").unwrap());
    }

    #[test]
    fn no_false_positive_across_numeric_sweep() {
        // Regression: a wrong key can make the decoder stop short of the entry
        // size without erroring, which skips the internal CRC check. "39" was
        // one such value that was wrongly accepted; sweep the whole 2-digit
        // space to guard the size-vs-expected check that fixes it.
        let bytes = read(CONTENT_ENCRYPTED);
        for n in 0..100u32 {
            let pw = format!("{n:02}");
            assert!(
                !try_password(&bytes, &pw).unwrap(),
                "false positive for wrong password {pw:?}"
            );
        }
    }

    #[test]
    fn signature_detection() {
        assert!(has_sevenz_signature(&read(CONTENT_ENCRYPTED)));
        assert!(!has_sevenz_signature(b"PK\x03\x04 not 7z"));
        assert!(!has_sevenz_signature(b"7z")); // too short
    }

    #[test]
    fn validate_accepts_encrypted_archive() {
        assert!(validate_sevenz(Path::new(CONTENT_ENCRYPTED)).is_ok());
        assert!(validate_sevenz(Path::new(HEADER_ENCRYPTED)).is_ok());
    }

    #[test]
    fn validate_rejects_non_sevenz() {
        // a zip fixture is not a 7z archive
        let result = validate_sevenz(Path::new("test-files/3.test.txt.zip"));
        assert!(matches!(result, Err(FinderError::InvalidSevenZip { .. })));
    }
}
