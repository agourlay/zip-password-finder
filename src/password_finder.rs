use crate::finder_errors::FinderError;
use crate::password_gen::start_password_generation;
use crate::password_reader::start_password_reader;
use crate::password_worker::password_checker;
use crate::{GenPasswords, PasswordFile};
use crossbeam_channel::{Receiver, Sender};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use zip::result::ZipError::UnsupportedArchive;

pub enum Strategy {
    PasswordFile(PathBuf),
    GenPasswords {
        charset_choice: String,
        min_password_len: usize,
        max_password_len: usize,
    },
}

pub fn password_finder(
    zip_path: &str,
    workers: usize,
    strategy: Strategy,
) -> Result<Option<String>, FinderError> {
    let file_path = Path::new(zip_path);
    // Fail early if the zip file is not valid
    validate_zip(file_path)?;

    // Progress bar
    let progress_bar = ProgressBar::new(0);
    let progress_style = ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {wide_bar} {pos}/{len} throughput:{per_sec} (eta:{eta})")
        .expect("Failed to create progress style");
    progress_bar.set_style(progress_style);
    // Refresh terminal 2 times per seconds
    let draw_target = ProgressDrawTarget::stdout_with_hz(2);
    progress_bar.set_draw_target(draw_target);

    // MPMC channel with backpressure
    let (send_password, receive_password): (Sender<String>, Receiver<String>) =
        crossbeam_channel::bounded(workers * 10_000);

    let (send_found_password, receive_found_password): (Sender<String>, Receiver<String>) =
        crossbeam_channel::bounded(1);

    // stop signals to shutdown threads
    let stop_workers_signal = Arc::new(AtomicBool::new(false));
    let stop_gen_signal = Arc::new(AtomicBool::new(false));

    let (total_password_count, password_gen_handle) = match strategy {
        GenPasswords {
            charset_choice,
            min_password_len,
            max_password_len,
        } => {
            let charset_letters = vec![
                'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
                'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            ];
            let charset_uppercase_letters = vec![
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            ];
            let charset_digits = vec!['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
            let charset_punctuations = vec![
                ' ', '-', '=', '!', '@', '#', '$', '%', '^', '&', '*', '_', '+', '<', '>', '/',
                '?', '.', ';', ':', '{', '}',
            ];

            let charset = match charset_choice.as_str() {
                "easy" => vec![charset_letters, charset_uppercase_letters].concat(),
                "medium" => {
                    vec![charset_letters, charset_uppercase_letters, charset_digits].concat()
                }
                "hard" => vec![
                    charset_letters,
                    charset_uppercase_letters,
                    charset_digits,
                    charset_punctuations,
                ]
                .concat(),
                _ => panic!("invalid charset choice"),
            };

            let mut total_password_count = 0;
            let charset_len = charset.len();
            for i in min_password_len..=max_password_len {
                total_password_count += charset_len.pow(i as u32)
            }

            (
                total_password_count,
                start_password_generation(
                    charset,
                    min_password_len,
                    max_password_len,
                    send_password,
                    stop_gen_signal.clone(),
                    progress_bar.clone(),
                ),
            )
        }
        PasswordFile(password_list_path) => {
            let file = BufReader::new(
                File::open(password_list_path.clone()).expect("Unable to open file"),
            );
            let mut total_password_count = 0;
            for _ in file.lines() {
                total_password_count += 1;
            }
            progress_bar.println(format!(
                "Using passwords file reader {:?} with {} lines",
                password_list_path, total_password_count
            ));
            (
                total_password_count,
                start_password_reader(password_list_path, send_password, stop_gen_signal.clone()),
            )
        }
    };

    progress_bar.set_length(total_password_count as u64);

    let mut worker_handles = Vec::with_capacity(workers);

    progress_bar.println(format!("Using {} workers to test passwords", workers));
    for i in 1..=workers {
        let join_handle = password_checker(
            i,
            file_path,
            receive_password.clone(),
            send_found_password.clone(),
            stop_workers_signal.clone(),
            progress_bar.clone(),
        );
        worker_handles.push(join_handle);
    }

    // drop reference in `main` so that it disappears completely with workers for a clean shutdown
    drop(send_found_password);

    match receive_found_password.recv() {
        Ok(password_found) => {
            progress_bar.println(format!("Password found '{}'", password_found));
            // stop generating values first to avoid deadlock on channel
            stop_gen_signal.store(true, Ordering::Relaxed);
            password_gen_handle.join().unwrap();
            // stop workers
            stop_workers_signal.store(true, Ordering::Relaxed);
            for h in worker_handles {
                h.join().unwrap();
            }
            progress_bar.finish_and_clear();
            Ok(Some(password_found))
        }
        Err(_) => {
            progress_bar.println("Password not found :(");
            progress_bar.finish_and_clear();
            Ok(None)
        }
    }
}

// validate that the zip requires a password
fn validate_zip(file_path: &Path) -> Result<(), FinderError> {
    let file = File::open(&file_path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    let zip_result = archive.by_index(0);
    match zip_result {
        Ok(_) => Err(FinderError::invalid_zip_error(
            "the archive is not encrypted".to_string(),
        )),
        Err(UnsupportedArchive(msg)) if msg == "Password required to decrypt file" => Ok(()),
        Err(e) => Err(FinderError::invalid_zip_error(format!(
            "Unexpected error {:?}",
            e
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::max;

    fn find_password_gen(
        path: &str,
        max_password_len: usize,
    ) -> Result<Option<String>, FinderError> {
        let strategy = GenPasswords {
            charset_choice: "easy".to_string(),
            min_password_len: 1,
            max_password_len,
        };
        let workers = max(1, num_cpus::get() - 1);
        password_finder(path, workers, strategy)
    }

    #[test]
    fn find_two_letters_password() {
        let password = find_password_gen("test-files/2.test.txt.zip", 2)
            .unwrap()
            .unwrap();
        assert_eq!(password, "ab");
    }

    #[test]
    fn fail_to_find_two_letters_password() {
        // because max_password_len is 1
        let password = find_password_gen("test-files/2.test.txt.zip", 1).unwrap();
        assert!(password.is_none());
    }

    #[test]
    fn find_three_letters_password() {
        let password = find_password_gen("test-files/3.test.txt.zip", 3)
            .unwrap()
            .unwrap();
        assert_eq!(password, "abc");
    }

    #[test]
    fn fail_to_find_three_letters_password() {
        // because max_password_len is 2
        let password = find_password_gen("test-files/3.test.txt.zip", 2).unwrap();
        assert!(password.is_none());
    }

    // Takes too long on the CI
    //#[test]
    // fn find_four_letters_password() {
    //     let password = find_password_gen("test-files/4.test.txt.zip", 4)
    //         .unwrap()
    //         .unwrap();
    //     assert_eq!(password, "abcd");
    // }
}
