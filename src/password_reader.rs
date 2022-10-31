use crossbeam_channel::Sender;
use indicatif::ProgressBar;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

pub fn start_password_reader(
    file_path: PathBuf,
    send_password: Sender<String>,
    stop_signal: Arc<AtomicBool>,
    progress_bar: ProgressBar,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name("password-reader".to_string())
        .spawn(move || {
            let file = File::open(file_path).unwrap();
            let reader = BufReader::new(file);
            for line in reader.lines() {
                if stop_signal.load(Ordering::Relaxed) {
                    break;
                } else {
                    // ignore non UTF8 strings
                    if let Ok(password_candidate) = line {
                        match send_password.send(password_candidate) {
                            Ok(_) => {}
                            Err(_) => break, //disconnected
                        }
                        progress_bar.inc(1);
                    }
                }
            }
        })
        .unwrap()
}
