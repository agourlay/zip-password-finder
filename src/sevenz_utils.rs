use crate::finder_errors::FinderError;
use sevenz_rust2::{Archive, ArchiveReader, Error as SevenZError, Password};
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

/// The single entry a candidate is checked against. Verifying one entry proves
/// the key, so we pick the cheapest one to decode (see [`pick_verify_target`]).
#[derive(Clone)]
pub struct VerifyTarget {
    name: String,
    size: u64,
}

/// A 7z archive that has been read into memory and confirmed to be encrypted.
///
/// The whole file is kept in memory (behind an `Arc`) because every candidate
/// re-opens the archive to attempt decryption; loading once and sharing the
/// bytes across workers avoids re-reading the file per password.
pub struct ValidatedSevenZip {
    pub bytes: Arc<Vec<u8>>,
    /// Entry to verify against, chosen from the plaintext headers. `None` when
    /// the headers are encrypted (`-mhe=on`) and cannot be enumerated without
    /// the password — those fall back to the first content entry at read time.
    pub target: Option<VerifyTarget>,
}

/// Choose the cheapest entry to decode when checking a candidate.
///
/// For a non-solid archive each entry sits in its own block, so verifying
/// against the *smallest* entry minimizes the decrypt/decompress work per
/// candidate — important when the archive holds one huge file plus small ones.
/// For a solid archive every entry shares one block and decoding always starts
/// at its head, so the *first* entry is the cheapest to reach and a later,
/// smaller one would cost strictly more.
///
/// Returns `None` if there is no non-empty content entry to check.
fn pick_verify_target(archive: &Archive) -> Option<VerifyTarget> {
    let mut content = archive
        .files
        .iter()
        .filter(|f| f.has_stream() && f.size() > 0);
    let chosen = if archive.is_solid {
        content.next()
    } else {
        content.min_by_key(|f| f.size())
    }?;
    Some(VerifyTarget {
        name: chosen.name().to_string(),
        size: chosen.size(),
    })
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
/// A wrong key yields garbage that fails to decode, fails the stored CRC-32, or
/// stops short of the entry size — all treated as a non-match. For
/// header-encrypted archives (`-mhe=on`) the wrong key already fails when the
/// reader parses the encrypted metadata, before any entry is read.
///
/// When `target` is `Some`, only that entry is decoded (chosen up front to be
/// the cheapest — see [`pick_verify_target`]); otherwise the first content
/// entry is used, which is all that is available for header-encrypted archives.
pub fn try_password(
    archive_bytes: &[u8],
    password: &str,
    target: Option<&VerifyTarget>,
) -> Result<bool, SevenZError> {
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

    match target {
        // Fast path: decode only the pre-selected entry. `read_file` seeks
        // straight to its block (for non-solid archives), so a huge sibling file
        // is never touched. A wrong key errors (decode/CRC) or returns fewer
        // bytes than expected; only a full, error-free read is a match.
        Some(target) => match reader.read_file(&target.name) {
            Ok(data) => Ok(data.len() as u64 == target.size),
            Err(e) => {
                if is_wrong_password(&e) {
                    Ok(false)
                } else {
                    Err(e)
                }
            }
        },
        None => verify_first_content_entry(&mut reader),
    }
}

/// Fallback verification when no target entry was pre-selected (header-encrypted
/// archives): read the first non-empty entry to force decrypt + CRC validation.
fn verify_first_content_entry(
    reader: &mut ArchiveReader<Cursor<&[u8]>>,
) -> Result<bool, SevenZError> {
    let mut checked_content = false;
    let mut entry_verified = false;
    let iter_result = reader.for_each_entries(|entry, rd| {
        if !entry.has_stream() || entry.size() == 0 {
            return Ok(true); // keep looking for a content entry
        }
        checked_content = true;
        let expected = entry.size();
        // The reader's internal CRC-32 check only fires once the full `expected`
        // size is produced, so both signals matter: an error means decode/CRC
        // failure, and a short read means the wrong key produced garbage that
        // stopped early, skipping the CRC gate. Only a complete, error-free read
        // is the right password.
        entry_verified = matches!(io::copy(rd, &mut io::sink()), Ok(n) if n == expected);
        Ok(false) // one content entry is enough
    });

    match iter_result {
        Ok(()) => {
            if checked_content {
                Ok(entry_verified)
            } else {
                // No content entry to validate against. Reaching here means the
                // encrypted headers parsed cleanly, which for a header-encrypted
                // archive already implies the right password.
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

    // Enumerate entries from the (plaintext) headers to pick the cheapest
    // verification target. This fails for header-encrypted archives, which
    // cannot be read without the password — those fall back to the first
    // content entry (`target = None`).
    let target = {
        let mut cursor = Cursor::new(bytes.as_slice());
        match Archive::read(&mut cursor, &Password::empty()) {
            Ok(archive) => pick_verify_target(&archive),
            Err(_) => None,
        }
    };

    // Probe with a password that cannot be the real one. If it "succeeds" the
    // archive is not encrypted; a structural error means we could never crack it
    // regardless of password, so surface it now instead of looping forever.
    let probe = "\u{1}zip-password-finder-probe\u{1}";
    match try_password(&bytes, probe, target.as_ref()) {
        Ok(false) => Ok(ValidatedSevenZip {
            bytes: Arc::new(bytes),
            target,
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

    // A non-solid archive holding a 5-byte file and a ~270 KB file; the target
    // must be the small one so a candidate never decodes the large sibling.
    const MULTI_FILE: &str = "test-files/3.test.multi.7z";

    fn read(path: &str) -> Vec<u8> {
        std::fs::read(path).expect("fixture should exist")
    }

    fn target_for(path: &str) -> Option<VerifyTarget> {
        let bytes = read(path);
        let mut cursor = Cursor::new(bytes.as_slice());
        match Archive::read(&mut cursor, &Password::empty()) {
            Ok(archive) => pick_verify_target(&archive),
            Err(_) => None,
        }
    }

    #[test]
    fn correct_password_content_encrypted() {
        // both with the pre-selected target (fast path) and without (fallback)
        let bytes = read(CONTENT_ENCRYPTED);
        assert!(try_password(&bytes, "abc", target_for(CONTENT_ENCRYPTED).as_ref()).unwrap());
        assert!(try_password(&bytes, "abc", None).unwrap());
    }

    #[test]
    fn correct_password_header_encrypted() {
        // header-encrypted always uses the fallback (target is None)
        assert!(target_for(HEADER_ENCRYPTED).is_none());
        assert!(try_password(&read(HEADER_ENCRYPTED), "abc", None).unwrap());
    }

    #[test]
    fn wrong_password_content_encrypted() {
        let bytes = read(CONTENT_ENCRYPTED);
        let target = target_for(CONTENT_ENCRYPTED);
        for pw in ["abd", "ab", ""] {
            assert!(!try_password(&bytes, pw, target.as_ref()).unwrap());
            assert!(!try_password(&bytes, pw, None).unwrap());
        }
    }

    #[test]
    fn wrong_password_header_encrypted() {
        assert!(!try_password(&read(HEADER_ENCRYPTED), "abd", None).unwrap());
        assert!(!try_password(&read(HEADER_ENCRYPTED), "zzz", None).unwrap());
    }

    #[test]
    fn no_false_positive_across_numeric_sweep() {
        // Regression: a wrong key can make the decoder stop short of the entry
        // size without erroring, which skips the internal CRC check. "39" was
        // one such value that was wrongly accepted; sweep the whole 2-digit
        // space on both verification paths to guard the size-vs-expected check.
        let bytes = read(CONTENT_ENCRYPTED);
        let target = target_for(CONTENT_ENCRYPTED);
        for n in 0..100u32 {
            let pw = format!("{n:02}");
            assert!(
                !try_password(&bytes, &pw, target.as_ref()).unwrap(),
                "false positive (target path) for {pw:?}"
            );
            assert!(
                !try_password(&bytes, &pw, None).unwrap(),
                "false positive (fallback path) for {pw:?}"
            );
        }
    }

    #[test]
    fn target_picks_smallest_non_solid_entry() {
        // large.txt is listed first but small.txt (5 bytes) must be chosen.
        let target = target_for(MULTI_FILE).expect("multi-file archive has a content entry");
        assert_eq!(target.name, "small.txt");
        assert_eq!(target.size, 5);
    }

    #[test]
    fn multi_file_password_check() {
        let bytes = read(MULTI_FILE);
        let target = target_for(MULTI_FILE);
        assert!(try_password(&bytes, "abc", target.as_ref()).unwrap());
        assert!(!try_password(&bytes, "abd", target.as_ref()).unwrap());
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
