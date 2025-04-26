use crate::finder_errors::FinderError;
use crate::password_gen::password_generator_count;
use crate::password_reader::password_reader_count;
use crate::password_worker::password_checker;
use crate::zip_utils::validate_zip;
use crate::{GenPasswords, PasswordFile};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub enum Strategy {
    PasswordFile(PathBuf),
    GenPasswords {
        charset: Vec<char>,
        min_password_len: usize,
        max_password_len: usize,
    },
}

pub fn password_finder(
    zip_path: &str,
    workers: usize,
    file_number: usize,
    strategy: &Strategy,
    stop_signal: Arc<AtomicBool>,
) -> Result<Option<String>, FinderError> {
    let file_path = Path::new(zip_path);

    // Progress bar
    let progress_bar = ProgressBar::new(0);
    let progress_style = ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {wide_bar} {pos}/{len} throughput:{per_sec} (eta:{eta})")
        .expect("Failed to create progress style");
    progress_bar.set_style(progress_style);
    // Refresh terminal 2 times per seconds
    let draw_target = ProgressDrawTarget::stdout_with_hz(2);
    progress_bar.set_draw_target(draw_target);

    // Fail early if the zip file is not valid
    let validated_zip = validate_zip(file_path, file_number)?;
    match &validated_zip.file_name {
        Some(file_name) => {
            progress_bar.println(format!("Targeting file '{file_name}' within the archive"));
        }
        None => progress_bar.println(format!(
            "Cannot get file name from archive for --fileNumber {file_number}"
        )),
    }

    let aes_info = validated_zip.aes_info;
    match &aes_info {
        Some(aes_info) => progress_bar.println(format!(
            "Archive encrypted with AES{} - expect a long wait time",
            aes_info.aes_key_length * 8
        )),
        None => progress_bar
            .println("Archive encrypted with ZipCrypto - expect a much faster throughput"),
    }

    let (send_found_password, receive_found_password): (SyncSender<String>, Receiver<String>) =
        sync_channel(1);

    let total_password_count = match strategy {
        GenPasswords {
            charset,
            min_password_len,
            max_password_len,
        } => password_generator_count(charset.len(), *min_password_len, *max_password_len),
        PasswordFile(password_list_path) => {
            let total = password_reader_count(password_list_path.clone())?;
            progress_bar.println(format!(
                "Using passwords dictionary {password_list_path:?} with {total} candidates."
            ));
            total
        }
    };

    // set progress bar length according to the total number of passwords
    progress_bar.set_length(total_password_count as u64);

    let mut worker_handles = Vec::with_capacity(workers);

    progress_bar.println(format!("Starting {workers} workers to test passwords"));
    for i in 1..=workers {
        let join_handle = password_checker(
            i,
            workers,
            file_path,
            file_number,
            aes_info.clone(),
            strategy.clone(),
            send_found_password.clone(),
            stop_signal.clone(),
            progress_bar.clone(),
        );
        worker_handles.push(join_handle);
    }

    // drop reference in `main` so that it disappears completely with workers for a clean shutdown
    drop(send_found_password);

    // wait for password to be found
    if let Ok(password_found) = receive_found_password.recv() {
        // stop workers on success
        stop_signal.store(true, Ordering::Relaxed);
        for h in worker_handles {
            h.join().unwrap();
        }
        progress_bar.finish_and_clear();
        Ok(Some(password_found))
    } else {
        // workers are stopped by the signal
        progress_bar.finish_and_clear();
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::charsets;

    fn find_password_gen(
        path: &str,
        max_password_len: usize,
    ) -> Result<Option<String>, FinderError> {
        let strategy = GenPasswords {
            charset: charsets::preset_to_charset("l")?,
            min_password_len: 1,
            max_password_len,
        };
        let workers = num_cpus::get_physical();
        let file_number = 0;
        password_finder(
            path,
            workers,
            file_number,
            &strategy,
            Arc::new(AtomicBool::new(false)),
        )
    }

    fn find_password_dictionary(path: &str) -> Result<Option<String>, FinderError> {
        let strategy = PasswordFile(PathBuf::from(
            "test-files/generated-passwords-lowercase.txt",
        ));
        let workers = num_cpus::get_physical();
        let file_number = 0;
        password_finder(
            path,
            workers,
            file_number,
            &strategy,
            Arc::new(AtomicBool::new(false)),
        )
    }

    #[test]
    fn find_two_letters_password_generated() {
        let password = find_password_gen("test-files/2.test.txt.zip", 2)
            .unwrap()
            .unwrap();
        assert_eq!(password, "ab");
    }

    #[test]
    fn find_two_letters_password_dictionary() {
        let password = find_password_dictionary("test-files/2.test.txt.zip")
            .unwrap()
            .unwrap();
        assert_eq!(password, "ab");
    }

    #[test]
    fn fail_to_find_two_letters_password_generated() {
        // because max_password_len is 1
        let password = find_password_gen("test-files/2.test.txt.zip", 1).unwrap();
        assert!(password.is_none());
    }

    #[test]
    fn find_three_letters_password_generated() {
        let password = find_password_gen("test-files/3.test.txt.zip", 3)
            .unwrap()
            .unwrap();
        assert_eq!(password, "abc");
    }

    #[test]
    fn find_three_letters_password_dictionary() {
        let password = find_password_dictionary("test-files/3.test.txt.zip")
            .unwrap()
            .unwrap();
        assert_eq!(password, "abc");
    }

    #[test]
    fn fail_to_find_three_letters_password_generated() {
        // because max_password_len is 2
        let password = find_password_gen("test-files/3.test.txt.zip", 2).unwrap();
        assert!(password.is_none());
    }

    #[test]
    fn find_four_letters_password_generated() {
        let password = find_password_gen("test-files/4.test.txt.zip", 4)
            .unwrap()
            .unwrap();
        assert_eq!(password, "abcd");
    }
}
