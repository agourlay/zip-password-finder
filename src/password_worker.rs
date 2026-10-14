use crate::password_finder::Strategy;
use crate::password_gen::password_generator_iter;
use crate::password_mask::mask_password_iter;
use crate::password_reader::password_dictionary_reader_iter;
use crate::zip_utils::AesInfo;
use either::Either;
use hmac::{Hmac, KeyInit, Mac};
use indicatif::ProgressBar;
use sha1::Sha1;
use std::io::{BufReader, Cursor, Read};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::thread::JoinHandle;
use std::{fs, thread};
use zip::ZipArchive;
use zip::result::ZipError;

pub fn filter_for_worker_index(
    passwords: impl Iterator<Item = Vec<u8>>,
    worker_count: usize,
    index: usize,
) -> impl Iterator<Item = Vec<u8>> {
    if worker_count > 1 {
        Either::Left(passwords.enumerate().filter_map(move |(i, line)| {
            if i % worker_count == index - 1 {
                Some(line)
            } else {
                None
            }
        }))
    } else {
        Either::Right(passwords)
    }
}

/// Derive only the 2-byte WinZip-AES password verifier (the last two bytes of
/// the PBKDF2-HMAC-SHA1 derived key).
///
/// PBKDF2 output blocks are computed independently, and the verifier always sits
/// in the final block, so only that block needs the full 1000-iteration
/// derivation. This avoids materializing the full key (2, 3 or 4 SHA-1 blocks
/// for AES-128/192/256) for the overwhelming majority of candidates, which the
/// cheap verifier comparison then rejects.
fn pbkdf2_aes_verifier(password: &[u8], salt: &[u8], derived_key_len: usize) -> [u8; 2] {
    const H_LEN: usize = 20; // SHA-1 output size
    const ITERATIONS: u32 = 1000;
    // Index (1-based) of the last PBKDF2 block, which holds the verifier.
    let block_index = derived_key_len.div_ceil(H_LEN) as u32;
    // Offset of the verifier within that block.
    let offset = (derived_key_len - 2) - (block_index as usize - 1) * H_LEN;

    // PRF keyed on the password; set up the ipad/opad state once and clone it for
    // every iteration, like the pbkdf2 crate does internally.
    let prf = <Hmac<Sha1> as KeyInit>::new_from_slice(password)
        .expect("HMAC accepts any key length");

    // U_1 = PRF(salt || INT_BE(block_index))
    let mut mac = prf.clone();
    mac.update(salt);
    mac.update(&block_index.to_be_bytes());
    let mut u = mac.finalize().into_bytes();
    let mut t = u; // T = U_1

    // T = U_1 ^ U_2 ^ ... ^ U_c
    for _ in 1..ITERATIONS {
        let mut mac = prf.clone();
        mac.update(&u);
        u = mac.finalize().into_bytes();
        for (t_byte, u_byte) in t.iter_mut().zip(u.iter()) {
            *t_byte ^= *u_byte;
        }
    }

    [t[offset], t[offset + 1]]
}

#[allow(clippy::too_many_arguments)]
pub fn password_checker(
    index: usize,
    worker_count: usize,
    file_path: &Path,
    file_number: usize,
    aes_info: Option<AesInfo>,
    strategy: Strategy,
    send_password_found: SyncSender<String>,
    stop_signal: Arc<AtomicBool>,
    progress_bar: ProgressBar,
) -> JoinHandle<()> {
    let file_path = file_path.to_owned();
    thread::Builder::new()
        .name(format!("worker-{index}"))
        .spawn(move || {
            let batching_delta = worker_count as u64 * 500;
            let first_worker = index == 1;
            let progress_bar_delta = batching_delta * worker_count as u64;
            let passwords_iter = match strategy {
                Strategy::GenPasswords {
                    charset,
                    min_password_len,
                    max_password_len,
                    starting_password,
                } => {
                    // password generator logs its progress, make sure only the first one does
                    let pb = if first_worker {
                        progress_bar.clone()
                    } else {
                        ProgressBar::hidden()
                    };
                    Either::Left(password_generator_iter(
                        charset,
                        min_password_len,
                        max_password_len,
                        starting_password,
                        pb,
                    ))
                }
                Strategy::PasswordFile(dictionary_path) => Either::Right(Either::Left(
                    password_dictionary_reader_iter(dictionary_path),
                )),
                Strategy::MaskGenPasswords { mask } => {
                    Either::Right(Either::Right(mask_password_iter(mask)))
                }
            };
            // Filter passwords by worker index.
            // The iterator type is Either<GenPasswords, Either<Dictionary, Mask>> (nested)
            // to support 3 strategies with zero-cost static dispatch instead of Box<dyn Iterator>.
            // We must apply filter_for_worker_index to all 3 variants via nested map_left/map_right.
            let passwords_iter = passwords_iter
                .map_left(|iter| filter_for_worker_index(iter, worker_count, index))
                .map_right(|either| {
                    either
                        .map_left(|iter| filter_for_worker_index(iter, worker_count, index))
                        .map_right(|iter| filter_for_worker_index(iter, worker_count, index))
                });

            // AES info bindings
            let mut derived_key_len = 0;
            let mut aes_key_length = 0;
            let mut derived_key: Vec<u8> = Vec::new();
            let mut salt: Vec<u8> = Vec::new();
            let mut verification_value: [u8; 2] = [0; 2];
            let mut empty_entry_auth: Option<[u8; 10]> = None;

            // setup file reader depending on the encryption method
            let reader = if let Some(aes_info) = aes_info {
                salt = aes_info.salt;
                verification_value = aes_info.verification_value;
                derived_key_len = aes_info.derived_key_length;
                aes_key_length = aes_info.aes_key_length;
                empty_entry_auth = aes_info.empty_entry_auth;
                derived_key = vec![0; derived_key_len];
                let file = fs::File::open(file_path).expect("File should exist");
                // in case of AES we do not need to access the archive often, a buffer reader is enough
                Either::Left(BufReader::new(file))
            } else {
                let zip_file = fs::read(file_path).expect("File should exist");
                // in case of ZipCrypto, we load the file in memory as it will be accessed on each password
                Either::Right(Cursor::new(zip_file))
            };

            // zip archive
            let mut archive = ZipArchive::new(reader).expect("Archive validated before-hand");
            let mut extraction_buffer = Vec::new();

            // processing loop
            let mut processed_delta: u64 = 0;
            for password_bytes in passwords_iter {
                let mut potential_match = true;
                // process AES KEY
                if derived_key_len != 0 {
                    // Fast pre-filter: the 2-byte verifier is the tail of the
                    // PBKDF2 key, and PBKDF2 blocks are independent, so deriving
                    // just the final block (instead of the whole key) is enough
                    // to reject the ~65 535/65 536 wrong candidates with 2x-4x
                    // less work (AES-128 to AES-256).
                    let verifier = pbkdf2_aes_verifier(&password_bytes, &salt, derived_key_len);
                    potential_match = verification_value == verifier;
                }

                // Empty AES entry: the reader can't authenticate a passing 2-byte
                // verifier because there is no ciphertext, so it would accept 1
                // wrong password in 65 536. Verify the WinZip authentication code
                // (HMAC-SHA1-80 over the empty message) with the derived HMAC key.
                if potential_match && let Some(expected_auth) = empty_entry_auth {
                    // Verifier hit: now derive the whole key for the HMAC auth key.
                    pbkdf2::pbkdf2::<Hmac<Sha1>>(&password_bytes, &salt, 1000, &mut derived_key)
                        .expect("PBKDF2 should not fail");
                    let hmac_key = &derived_key[aes_key_length..aes_key_length * 2];
                    let mac = <Hmac<Sha1> as KeyInit>::new_from_slice(hmac_key)
                        .expect("HMAC accepts any key length");
                    let tag = mac.finalize().into_bytes();
                    if tag[..10] == expected_auth {
                        let password_str = String::from_utf8_lossy(&password_bytes).into_owned();
                        send_password_found
                            .send(password_str)
                            .expect("Send found password should not fail");
                    }
                    potential_match = false; // handled; skip the read-based path below
                }

                // ZipCrypto falls back directly here and will recompute its key for each password
                if potential_match {
                    // From the Rust doc:
                    // This function sometimes accepts wrong password. This is because the ZIP spec only allows us to check for a 1/256 chance that the password is correct.
                    // There are many passwords out there that will also pass the validity checks we are able to perform.
                    // This is a weakness of the ZipCrypto algorithm, due to its fairly primitive approach to cryptography.
                    match archive.by_index_decrypt(file_number, &password_bytes) {
                        // invalid password
                        Err(ZipError::InvalidPassword) => (),
                        // unexpected error - stop worker
                        Err(e) => panic!("Unexpected error {e:?}"),
                        // files in well-formed zip file should have a name
                        Ok(zip) if zip.enclosed_name().is_none() => (),
                        // potential valid password
                        Ok(mut zip) => {
                            // Validate password by reading the zip file to make sure it is not merely a hash collision.
                            let zip_size = zip.size() as usize;
                            extraction_buffer.reserve(zip_size);
                            match zip.read_to_end(&mut extraction_buffer) {
                                Err(_) => (), // password collision - continue
                                Ok(data_read) => {
                                    // if we read all the bytes, we have a match
                                    if data_read == zip_size {
                                        // Convert bytes to String only on success
                                        let password_str =
                                            String::from_utf8_lossy(&password_bytes).into_owned();
                                        // Send password and continue processing while waiting for signal
                                        send_password_found
                                            .send(password_str)
                                            .expect("Send found password should not fail");
                                    }
                                }
                            }
                            extraction_buffer.clear();
                        }
                    }
                }
                processed_delta += 1;
                // do not check internal flags too often
                if processed_delta == batching_delta {
                    // only the first worker should update the progress bar to avoid contention
                    if first_worker {
                        progress_bar.inc(progress_bar_delta);
                    }
                    // check if we should stop
                    if stop_signal.load(Ordering::Relaxed) {
                        if first_worker {
                            let password_display = String::from_utf8_lossy(&password_bytes);
                            progress_bar
                                .println(format!("Last password processed:{password_display}"));
                        }
                        break;
                    }
                    processed_delta = 0;
                }
            }
        })
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn verifier_matches_full_pbkdf2_derivation() {
        // The fast single-block verifier must equal the last two bytes of the
        // full derived key for every AES key length (16/24/32 -> dkLen 34/50/66).
        let salt = b"0123456789abcdef";
        for aes_key_length in [16usize, 24, 32] {
            let derived_key_len = 2 * aes_key_length + 2;
            for password in [b"abc".as_slice(), b"", b"a-longer-password-123"] {
                let mut full = vec![0u8; derived_key_len];
                pbkdf2::pbkdf2::<Hmac<Sha1>>(password, salt, 1000, &mut full).unwrap();
                let expected = [full[derived_key_len - 2], full[derived_key_len - 1]];
                let actual = pbkdf2_aes_verifier(password, salt, derived_key_len);
                assert_eq!(actual, expected, "key_len={aes_key_length} pw={password:?}");
            }
        }
    }

    #[test]
    fn filter_passwords_one_worker() {
        let iter = password_dictionary_reader_iter(PathBuf::from(
            "test-files/generated-passwords-lowercase.txt",
        ));
        let mut filtered = filter_for_worker_index(iter, 1, 1);
        assert_eq!(filtered.next(), Some(b"a".to_vec()));
        assert_eq!(filtered.next(), Some(b"b".to_vec()));
        assert_eq!(filtered.next(), Some(b"c".to_vec()));
        assert_eq!(filtered.next(), Some(b"d".to_vec()));
        assert_eq!(filtered.next(), Some(b"e".to_vec()));
        assert_eq!(filtered.next(), Some(b"f".to_vec()));
        assert_eq!(filtered.next(), Some(b"g".to_vec()));
        assert_eq!(filtered.next(), Some(b"h".to_vec()));
        assert_eq!(filtered.next(), Some(b"i".to_vec()));
        assert_eq!(filtered.next(), Some(b"j".to_vec()));
        assert_eq!(filtered.next(), Some(b"k".to_vec()));
        assert_eq!(filtered.next(), Some(b"l".to_vec()));
    }

    #[test]
    fn filter_passwords_two_workers_index_one() {
        let iter = password_dictionary_reader_iter(PathBuf::from(
            "test-files/generated-passwords-lowercase.txt",
        ));
        let mut filtered = filter_for_worker_index(iter, 2, 1);
        assert_eq!(filtered.next(), Some(b"a".to_vec()));
        //assert_eq!(filtered.next(), Some(b"b".to_vec()));
        assert_eq!(filtered.next(), Some(b"c".to_vec()));
        //assert_eq!(filtered.next(), Some(b"d".to_vec()));
        assert_eq!(filtered.next(), Some(b"e".to_vec()));
        //assert_eq!(filtered.next(), Some(b"f".to_vec()));
        assert_eq!(filtered.next(), Some(b"g".to_vec()));
        //assert_eq!(filtered.next(), Some(b"h".to_vec()));
        assert_eq!(filtered.next(), Some(b"i".to_vec()));
        //assert_eq!(filtered.next(), Some(b"j".to_vec()));
        assert_eq!(filtered.next(), Some(b"k".to_vec()));
        //assert_eq!(filtered.next(), Some(b"l".to_vec()));
    }

    #[test]
    fn filter_passwords_two_workers_index_two() {
        let iter = password_dictionary_reader_iter(PathBuf::from(
            "test-files/generated-passwords-lowercase.txt",
        ));
        let mut filtered = filter_for_worker_index(iter, 2, 2);
        //assert_eq!(filtered.next(), Some(b"a".to_vec()));
        assert_eq!(filtered.next(), Some(b"b".to_vec()));
        //assert_eq!(filtered.next(), Some(b"c".to_vec()));
        assert_eq!(filtered.next(), Some(b"d".to_vec()));
        //assert_eq!(filtered.next(), Some(b"e".to_vec()));
        assert_eq!(filtered.next(), Some(b"f".to_vec()));
        //assert_eq!(filtered.next(), Some(b"g".to_vec()));
        assert_eq!(filtered.next(), Some(b"h".to_vec()));
        //assert_eq!(filtered.next(), Some(b"i".to_vec()));
        assert_eq!(filtered.next(), Some(b"j".to_vec()));
        //assert_eq!(filtered.next(), Some(b"k".to_vec()));
        assert_eq!(filtered.next(), Some(b"l".to_vec()));
    }

    #[test]
    fn filter_passwords_three_workers_index_one() {
        let iter = password_dictionary_reader_iter(PathBuf::from(
            "test-files/generated-passwords-lowercase.txt",
        ));
        let mut filtered = filter_for_worker_index(iter, 3, 1);
        assert_eq!(filtered.next(), Some(b"a".to_vec()));
        //assert_eq!(filtered.next(), Some(b"b".to_vec()));
        //assert_eq!(filtered.next(), Some(b"c".to_vec()));
        assert_eq!(filtered.next(), Some(b"d".to_vec()));
        //assert_eq!(filtered.next(), Some(b"e".to_vec()));
        //assert_eq!(filtered.next(), Some(b"f".to_vec()));
        assert_eq!(filtered.next(), Some(b"g".to_vec()));
        //assert_eq!(filtered.next(), Some(b"h".to_vec()));
        //assert_eq!(filtered.next(), Some(b"i".to_vec()));
        assert_eq!(filtered.next(), Some(b"j".to_vec()));
        //assert_eq!(filtered.next(), Some(b"k".to_vec()));
        //assert_eq!(filtered.next(), Some(b"l".to_vec()));
    }
}
