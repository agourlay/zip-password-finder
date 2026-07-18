use crate::finder_errors::FinderError;
use crate::password_finder::Strategy;
use crate::password_finder::Strategy::{GenPasswords, MaskGenPasswords, PasswordFile};
use crate::password_gen::{password_count_already_generated, password_generator_count};
use crate::password_mask::mask_password_count;
use crate::password_reader::password_reader_count;
use crate::sevenz_utils::validate_sevenz;
use crate::sevenz_worker::sevenz_password_checker;
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};

pub fn sevenz_password_finder(
    archive_path: &str,
    workers: usize,
    strategy: &Strategy,
    stop_signal: Arc<AtomicBool>,
) -> Result<Option<String>, FinderError> {
    let file_path = Path::new(archive_path);

    let progress_bar = ProgressBar::new(0);
    let progress_style = ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {wide_bar} {pos}/{len} throughput:{per_sec} (eta:{eta})")
        .expect("Failed to create progress style");
    progress_bar.set_style(progress_style);
    progress_bar.set_draw_target(ProgressDrawTarget::stdout_with_hz(2));

    // Fail early if the archive is not a password-protected 7z we can process.
    let validated = validate_sevenz(file_path)?;
    progress_bar.println(
        "7z archive encrypted with AES-256 - expect a slow throughput (heavy key derivation)",
    );

    let (send_found_password, receive_found_password): (SyncSender<String>, Receiver<String>) =
        sync_channel(1);

    let (total_password_count, skipped) = match strategy {
        GenPasswords {
            charset,
            min_password_len,
            max_password_len,
            starting_password,
        } => {
            let total =
                password_generator_count(charset.len(), *min_password_len, *max_password_len);
            let skip = starting_password.as_ref().map_or(0, |sp| {
                password_count_already_generated(charset, *min_password_len, sp)
            });
            (total, skip)
        }
        PasswordFile(password_list_path) => {
            let total = password_reader_count(password_list_path.clone())?;
            progress_bar.println(format!(
                "Using passwords dictionary {password_list_path:?} with {total} candidates."
            ));
            (total, 0)
        }
        MaskGenPasswords { mask } => {
            let total = mask_password_count(mask);
            progress_bar.println(format!("Using mask attack with {total} candidates."));
            (total, 0)
        }
    };

    progress_bar.set_length(total_password_count as u64);
    progress_bar.set_position(skipped as u64);
    progress_bar.reset_elapsed();

    let mut worker_handles = Vec::with_capacity(workers);
    progress_bar.println(format!("Starting {workers} workers to test passwords"));
    for i in 1..=workers {
        worker_handles.push(sevenz_password_checker(
            i,
            workers,
            validated.bytes.clone(),
            validated.target.clone(),
            strategy.clone(),
            send_found_password.clone(),
            stop_signal.clone(),
            progress_bar.clone(),
        ));
    }

    // drop the main reference so the channel closes once every worker exits
    drop(send_found_password);

    if let Ok(password_found) = receive_found_password.recv() {
        stop_signal.store(true, Ordering::Relaxed);
        for h in worker_handles {
            h.join().unwrap();
        }
        progress_bar.finish_and_clear();
        Ok(Some(password_found))
    } else {
        progress_bar.finish_and_clear();
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::charsets;
    use crate::password_mask::parse_mask;
    use std::path::PathBuf;

    // Password "abc" over the same payload; see sevenz_utils tests for details.
    const CONTENT_ENCRYPTED: &str = "test-files/3.test.txt.7z";
    const HEADER_ENCRYPTED: &str = "test-files/3.test.hdr.7z";

    fn run(path: &str, strategy: Strategy) -> Option<String> {
        // A small fixed worker count keeps the multi-worker path under test
        // without every parallel test function spawning all physical cores and
        // oversubscribing the CPU (7z key derivation is heavy).
        let workers = 2;
        sevenz_password_finder(path, workers, &strategy, Arc::new(AtomicBool::new(false)))
            .expect("finder should not error")
    }

    fn mask(pattern: &str) -> Strategy {
        let mask = parse_mask(pattern, &[None, None, None, None]).unwrap();
        MaskGenPasswords { mask }
    }

    #[test]
    fn find_via_mask_content_encrypted() {
        assert_eq!(
            run(CONTENT_ENCRYPTED, mask("?l?l?l")).as_deref(),
            Some("abc")
        );
    }

    #[test]
    fn find_via_mask_header_encrypted() {
        assert_eq!(
            run(HEADER_ENCRYPTED, mask("?l?l?l")).as_deref(),
            Some("abc")
        );
    }

    #[test]
    fn find_via_generator() {
        // min length 3 so the scan skips the 1- and 2-char space and reaches
        // "abc" quickly; the point is to exercise the GenPasswords path.
        let strategy = GenPasswords {
            charset: charsets::preset_to_charset("l").unwrap(),
            min_password_len: 3,
            max_password_len: 3,
            starting_password: None,
        };
        assert_eq!(run(CONTENT_ENCRYPTED, strategy).as_deref(), Some("abc"));
    }

    #[test]
    fn find_via_dictionary() {
        let strategy = PasswordFile(PathBuf::from("test-files/7z-dict.txt"));
        assert_eq!(run(CONTENT_ENCRYPTED, strategy).as_deref(), Some("abc"));
    }

    #[test]
    fn wrong_charset_does_not_find() {
        // password is alphabetic, digits-only mask cannot match
        assert_eq!(run(CONTENT_ENCRYPTED, mask("?d?d")), None);
    }
}
