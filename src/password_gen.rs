use crossbeam_channel::Sender;
use indicatif::ProgressBar;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

pub fn start_password_generation(
    charset: Vec<char>,
    min_size: usize,
    max_size: usize,
    send_password: Sender<String>,
    stop_signal: Arc<AtomicBool>,
    progress_bar: ProgressBar,
) -> JoinHandle<()> {
    thread::Builder::new()
        .name("password-gen".to_string())
        .spawn(move || {
            let charset_len = charset.len();
            progress_bar.println(format!("Generating passwords with length from {} to {} for charset with length {}\n{:?}", min_size, max_size, charset_len, charset));
            let charset_first = *charset.first().expect("charset non empty");
            let charset_last = *charset.last().expect("charset non empty");

            let mut password = if min_size == 1 {
                progress_bar.println(format!("Starting search space for password length {} ({} possibilities) ", min_size, charset_len));
                vec![charset_first; 1]
            } else {
                vec![charset_last; min_size - 1]
            };
            let mut current_len = password.len();
            let mut current_index = current_len - 1;
            let mut generated_count = 0;

            while password.len() < max_size + 1 && !stop_signal.load(Ordering::Relaxed) {
                if current_len == current_index + 1 && !password.iter().any(|&c| c != charset_last)
                {
                    // increase length and reset letters
                    current_index += 1;
                    current_len += 1;
                    password =
                        Vec::from_iter(std::iter::repeat(charset_first).take(current_len));

                    let possibilities = charset_len.pow(current_len as u32);
                    progress_bar.println(
                        format!(
                        "Starting search space for password length {} ({} possibilities) ({} passwords generated so far)",
                        current_len, possibilities, generated_count
                    ));
                } else {
                    let current_char = *password.get(current_index).unwrap();
                    if current_char == charset_last {
                        // current char reached the end of the charset, reset current and bump previous
                        let at_prev = password.iter()
                            .rposition(|&c| c != charset_last)
                            .unwrap_or_else(|| panic!("Must find something else than {} in {:?}", charset_last, password));
                        let next_prev = if at_prev == charset_len - 1 {
                            charset.get(charset_len - 1).unwrap()
                        } else {
                            let prev_char = *password.get(at_prev).unwrap();
                            let prev_index_charset =
                                charset.iter().position(|&c| c == prev_char).unwrap();
                            charset.get(prev_index_charset + 1).unwrap()
                        };

                        //println!("need reset char:{}, current-index:{}, prev:{}, next-prev:{}", current_char, current_index, at_prev, next_prev);

                        let mut tmp = Vec::with_capacity(current_len);
                        for (i, x) in password.into_iter().enumerate() {
                            if i == current_index {
                                tmp.push(charset_first)
                            } else if i == at_prev {
                                tmp.push(*next_prev)
                            } else if x == charset_last && i > at_prev {
                                tmp.push(charset_first)
                            } else {
                                tmp.push(x);
                            }
                        }
                        password = tmp;
                    } else {
                        // increment current char
                        let at = charset.iter().position(|&c| c == current_char).unwrap();
                        let next = if at == charset_len - 1 {
                            charset_first
                        } else {
                            *charset.get(at + 1).unwrap()
                        };

                        //println!("in-place char:{}, index in charset:{}", current_char, at);

                        let mut tmp = Vec::with_capacity(current_len);
                        for (i, x) in password.iter().enumerate() {
                            if i == current_index {
                                tmp.push(next)
                            } else {
                                tmp.push(*x);
                            }
                        }
                        password = tmp;
                    }
                }
                let to_push = password.iter().cloned().collect::<String>();
                //println!("push {}", to_push);
                generated_count += 1;
                progress_bar.inc(1);
                send_password.send(to_push).unwrap();
            }
        })
        .unwrap()
}
