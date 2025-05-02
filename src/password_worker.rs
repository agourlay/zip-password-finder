use crate::password_finder::Strategy;
use crate::password_gen::password_generator_iter;
use crate::password_reader::password_dictionary_reader_iter;
use crate::zip_utils::AesInfo;
use hmac::Hmac;
use indicatif::ProgressBar;
use sha1::Sha1;
use std::io::{BufReader, Cursor, Read, Seek};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::{fs, thread};
use zip::result::ZipError;
use zip::ZipArchive;

pub fn filter_for_worker_index(
    passwords: Box<dyn Iterator<Item = String>>,
    worker_count: usize,
    index: usize,
) -> Box<dyn Iterator<Item = String>> {
    if worker_count > 1 {
        Box::new(passwords.enumerate().filter_map(move |(i, line)| {
            //eprintln!("thread:{} index:{} word:{} module:{}, pass:{}", index, i, line, i % worker_count, i % worker_count == index - 1);
            if i % worker_count == index - 1 {
                Some(line)
            } else {
                None
            }
        }))
    } else {
        passwords
    }
}

// abstraction for the zip reader
trait ZipReader: Read + Seek {}
impl ZipReader for Cursor<Vec<u8>> {}
impl ZipReader for BufReader<fs::File> {}

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
            let mut passwords_iter: Box<dyn Iterator<Item = String>> = match strategy {
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
                    let iterator = password_generator_iter(
                        &charset,
                        min_password_len,
                        max_password_len,
                        starting_password,
                        pb,
                    );
                    Box::new(iterator)
                }
                Strategy::PasswordFile(dictionary_path) => {
                    let iterator = password_dictionary_reader_iter(&dictionary_path);
                    Box::new(iterator)
                }
            };
            // filter passwords by worker index
            passwords_iter = filter_for_worker_index(passwords_iter, worker_count, index);

            // AES info bindings
            let mut derived_key_len = 0;
            let mut derived_key: Vec<u8> = Vec::new();
            let mut salt: Vec<u8> = Vec::new();
            let mut verification_value: [u8; 2] = [0; 2];

            // setup file reader depending on the encryption method
            let reader: Box<dyn ZipReader> = if let Some(aes_info) = aes_info {
                salt = aes_info.salt;
                verification_value = aes_info.verification_value;
                derived_key_len = aes_info.derived_key_length;
                derived_key = vec![0; derived_key_len];
                let file = fs::File::open(file_path).expect("File should exist");
                // in case of AES we do not need to access the archive often, a buffer reader is enough
                Box::new(BufReader::new(file))
            } else {
                let zip_file = fs::read(file_path).expect("File should exist");
                // in case of ZipCrypto, we load the file in memory as it will be accessed on each password
                Box::new(Cursor::new(zip_file))
            };

            // zip archive
            let mut archive = ZipArchive::new(reader).expect("Archive validated before-hand");
            let mut extraction_buffer = Vec::new();

            // processing loop
            let mut processed_delta: u64 = 0;
            for password in passwords_iter {
                let password_bytes = password.as_bytes();
                let mut potential_match = true;
                // process AES KEY
                if derived_key_len != 0 {
                    // use PBKDF2 with HMAC-Sha1 to derive the key
                    pbkdf2::pbkdf2::<Hmac<Sha1>>(password_bytes, &salt, 1000, &mut derived_key)
                        .expect("PBKDF2 should not fail");
                    let pwd_verify = &derived_key[derived_key_len - 2..];
                    // the last 2 bytes should equal the password verification value
                    potential_match = verification_value == pwd_verify;
                }

                // ZipCrypto falls back directly here and will recompute its key for each password
                if potential_match {
                    // From the Rust doc:
                    // This function sometimes accepts wrong password. This is because the ZIP spec only allows us to check for a 1/256 chance that the password is correct.
                    // There are many passwords out there that will also pass the validity checks we are able to perform.
                    // This is a weakness of the ZipCrypto algorithm, due to its fairly primitive approach to cryptography.
                    match archive.by_index_decrypt(file_number, password_bytes) {
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
                                        // Send password and continue processing while waiting for signal
                                        send_password_found
                                            .send(password.clone())
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
                            progress_bar.println(format!("Last password processed:{password}"));
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
    fn filter_passwords_one_worker() {
        let iter = password_dictionary_reader_iter(&PathBuf::from(
            "test-files/generated-passwords-lowercase.txt",
        ));
        let box_iter = Box::new(iter);
        let mut filtered = filter_for_worker_index(box_iter, 1, 1);
        assert_eq!(filtered.next(), Some("a".into()));
        assert_eq!(filtered.next(), Some("b".into()));
        assert_eq!(filtered.next(), Some("c".into()));
        assert_eq!(filtered.next(), Some("d".into()));
        assert_eq!(filtered.next(), Some("e".into()));
        assert_eq!(filtered.next(), Some("f".into()));
        assert_eq!(filtered.next(), Some("g".into()));
        assert_eq!(filtered.next(), Some("h".into()));
        assert_eq!(filtered.next(), Some("i".into()));
        assert_eq!(filtered.next(), Some("j".into()));
        assert_eq!(filtered.next(), Some("k".into()));
        assert_eq!(filtered.next(), Some("l".into()));
    }

    #[test]
    fn filter_passwords_two_workers_index_one() {
        let iter = password_dictionary_reader_iter(&PathBuf::from(
            "test-files/generated-passwords-lowercase.txt",
        ));
        let box_iter = Box::new(iter);
        let mut filtered = filter_for_worker_index(box_iter, 2, 1);
        assert_eq!(filtered.next(), Some("a".into()));
        //assert_eq!(filtered.next(), Some("b".into()));
        assert_eq!(filtered.next(), Some("c".into()));
        //assert_eq!(filtered.next(), Some("d".into()));
        assert_eq!(filtered.next(), Some("e".into()));
        //assert_eq!(filtered.next(), Some("f".into()));
        assert_eq!(filtered.next(), Some("g".into()));
        //assert_eq!(filtered.next(), Some("h".into()));
        assert_eq!(filtered.next(), Some("i".into()));
        //assert_eq!(filtered.next(), Some("j".into()));
        assert_eq!(filtered.next(), Some("k".into()));
        //assert_eq!(filtered.next(), Some("l".into()));
    }

    #[test]
    fn filter_passwords_two_workers_index_two() {
        let iter = password_dictionary_reader_iter(&PathBuf::from(
            "test-files/generated-passwords-lowercase.txt",
        ));
        let box_iter = Box::new(iter);
        let mut filtered = filter_for_worker_index(box_iter, 2, 2);
        //assert_eq!(filtered.next(), Some("a".into()));
        assert_eq!(filtered.next(), Some("b".into()));
        //assert_eq!(filtered.next(), Some("c".into()));
        assert_eq!(filtered.next(), Some("d".into()));
        //assert_eq!(filtered.next(), Some("e".into()));
        assert_eq!(filtered.next(), Some("f".into()));
        //assert_eq!(filtered.next(), Some("g".into()));
        assert_eq!(filtered.next(), Some("h".into()));
        //assert_eq!(filtered.next(), Some("i".into()));
        assert_eq!(filtered.next(), Some("j".into()));
        //assert_eq!(filtered.next(), Some("k".into()));
        assert_eq!(filtered.next(), Some("l".into()));
    }

    #[test]
    fn filter_passwords_three_workers_index_one() {
        let iter = password_dictionary_reader_iter(&PathBuf::from(
            "test-files/generated-passwords-lowercase.txt",
        ));
        let box_iter = Box::new(iter);
        let mut filtered = filter_for_worker_index(box_iter, 3, 1);
        assert_eq!(filtered.next(), Some("a".into()));
        //assert_eq!(filtered.next(), Some("b".into()));
        //assert_eq!(filtered.next(), Some("c".into()));
        assert_eq!(filtered.next(), Some("d".into()));
        //assert_eq!(filtered.next(), Some("e".into()));
        //assert_eq!(filtered.next(), Some("f".into()));
        assert_eq!(filtered.next(), Some("g".into()));
        //assert_eq!(filtered.next(), Some("h".into()));
        //assert_eq!(filtered.next(), Some("i".into()));
        assert_eq!(filtered.next(), Some("j".into()));
        //assert_eq!(filtered.next(), Some("k".into()));
        //assert_eq!(filtered.next(), Some("l".into()));
    }
}
