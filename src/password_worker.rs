use crate::password_finder::Strategy;
use crate::password_gen::start_password_generation;
use crate::password_reader::start_password_reader;
use crossbeam_channel::Sender;
use indicatif::ProgressBar;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::{fs, thread};

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

pub fn password_checker(
    index: usize,
    worker_count: usize,
    file_path: &Path,
    strategy: Strategy,
    send_password_found: Sender<String>,
    stop_signal: Arc<AtomicBool>,
    progress_bar: ProgressBar,
) -> JoinHandle<()> {
    let file = fs::File::open(file_path).expect("File should exist");
    thread::Builder::new()
        .name(format!("worker-{}", index))
        .spawn(move || {
            let batching_delta = worker_count as u64 * 500;
            let mut passwords_iter: Box<dyn Iterator<Item = String>> = match strategy {
                Strategy::GenPasswords {
                    charset,
                    min_password_len,
                    max_password_len,
                } => {
                    // password generator logs its progress, make sure only the first one does
                    let pb = if index == 1 {
                        progress_bar.clone()
                    } else {
                        ProgressBar::hidden()
                    };
                    let iterator =
                        start_password_generation(&charset, min_password_len, max_password_len, pb);
                    Box::new(iterator)
                }
                Strategy::PasswordFile(dictionary_path) => {
                    let iterator = start_password_reader(&dictionary_path);
                    Box::new(iterator)
                }
            };
            // filter passwords by worker index
            passwords_iter = filter_for_worker_index(passwords_iter, worker_count, index);
            let reader = std::io::BufReader::new(file);
            let mut archive = zip::ZipArchive::new(reader).expect("Archive validated before-hand");
            let mut extraction_buffer = Vec::new();
            let mut processed_delta: u64 = 0;
            for password in passwords_iter {
                // From the Rust doc:
                // This function sometimes accepts wrong password. This is because the ZIP spec only allows us to check for a 1/256 chance that the password is correct.
                // There are many passwords out there that will also pass the validity checks we are able to perform.
                // This is a weakness of the ZipCrypto algorithm, due to its fairly primitive approach to cryptography.
                let res = archive.by_index_decrypt(0, password.as_bytes());
                match res {
                    Ok(Err(_)) => (), // invalid password
                    Ok(Ok(mut zip)) => {
                        // Validate password by reading the zip file to make sure it is not merely a hash collision.
                        extraction_buffer.reserve(zip.size() as usize);
                        match zip.read_to_end(&mut extraction_buffer) {
                            Err(_) => (), // password collision - continue
                            Ok(_) => {
                                // Send password and continue processing while waiting for signal
                                send_password_found
                                    .send(password)
                                    .expect("Send found password should not fail");
                            }
                        }
                        extraction_buffer.clear();
                    }
                    Err(e) => panic!("Unexpected error {:?}", e),
                }
                // having only the first worker handle the progress bar does not seem beneficial
                // however updating in a batch fashion seems to be
                processed_delta += 1;
                if processed_delta == batching_delta {
                    progress_bar.inc(batching_delta);
                    if stop_signal.load(Ordering::Relaxed) {
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
        let iter = start_password_reader(&PathBuf::from(
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
        let iter = start_password_reader(&PathBuf::from(
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
        let iter = start_password_reader(&PathBuf::from(
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
        let iter = start_password_reader(&PathBuf::from(
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
