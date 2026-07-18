use crate::password_finder::Strategy;
use crate::password_gen::password_generator_iter;
use crate::password_mask::mask_password_iter;
use crate::password_reader::password_dictionary_reader_iter;
use crate::password_worker::filter_for_worker_index;
use crate::sevenz_utils::try_password;
use indicatif::ProgressBar;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::thread;
use std::thread::JoinHandle;

fn passwords_for_strategy(
    strategy: Strategy,
    progress_bar: ProgressBar,
) -> Box<dyn Iterator<Item = Vec<u8>>> {
    match strategy {
        Strategy::GenPasswords {
            charset,
            min_password_len,
            max_password_len,
            starting_password,
        } => Box::new(password_generator_iter(
            charset,
            min_password_len,
            max_password_len,
            starting_password,
            progress_bar,
        )),
        Strategy::PasswordFile(path) => Box::new(password_dictionary_reader_iter(path)),
        Strategy::MaskGenPasswords { mask } => Box::new(mask_password_iter(mask)),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn sevenz_password_checker(
    index: usize,
    worker_count: usize,
    archive_bytes: Arc<Vec<u8>>,
    strategy: Strategy,
    send_password_found: SyncSender<String>,
    stop_signal: Arc<AtomicBool>,
    progress_bar: ProgressBar,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name(format!("7z-worker-{index}"))
        .spawn(move || {
            let first_worker = index == 1;

            // Only the first worker drives the shared progress bar; the password
            // generator logs its own progress, so hide it for the others.
            let generator_pb = if first_worker {
                progress_bar.clone()
            } else {
                ProgressBar::hidden()
            };
            let passwords = passwords_for_strategy(strategy, generator_pb);
            let passwords = filter_for_worker_index(passwords, worker_count, index);

            let mut last_password = String::new();
            for password_bytes in passwords {
                // Each 7z candidate runs a heavy key derivation (~ms), so poll
                // the stop flag every iteration: the atomic load is free next to
                // the KDF, and a coarse check would leave every other worker
                // grinding for seconds after the password is already found or
                // Ctrl-C was pressed.
                if stop_signal.load(Ordering::Relaxed) {
                    if first_worker && !last_password.is_empty() {
                        progress_bar.println(format!("Last password processed:{last_password}"));
                    }
                    break;
                }

                let password = String::from_utf8_lossy(&password_bytes);
                // A structural error cannot happen here: validation already
                // probed the archive and rejected unsupported codecs, so any
                // error at this point is treated as a non-match.
                if matches!(try_password(&archive_bytes, &password), Ok(true)) {
                    send_password_found
                        .send(password.into_owned())
                        .expect("Send found password should not fail");
                    break;
                }

                // Advance the shared bar by one slot per worker each iteration;
                // per-candidate updates are cheap since the draw target is
                // throttled, and they keep the bar moving on slow 7z runs.
                if first_worker {
                    progress_bar.inc(worker_count as u64);
                    last_password = password.into_owned();
                }
            }
        })
        .unwrap()
}
