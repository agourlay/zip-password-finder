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
            // compute the number of lines in the file
            let file = File::open(&file_path).expect("Unable to open file");
            let mut reader = BufReader::new(file);
            let mut total_password_count = 0;
            let mut line_buffer = Vec::new();
            loop {
                // count line number without reallocating each line
                // read_until to avoid UTF-8 validation (unlike read_line which produce a String)
                let res = reader
                    .read_until(b'\n', &mut line_buffer)
                    .expect("Unable to read file");
                if res == 0 {
                    // end of file
                    break;
                }
                line_buffer.clear();
                total_password_count += 1;
            }
            progress_bar.println(format!(
                "Using passwords file reader {:?} with {} candidates.",
                file_path, total_password_count
            ));
            progress_bar.set_length(total_password_count as u64);

            // start actual reader
            let file = File::open(&file_path).expect("Unable to open file");
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
