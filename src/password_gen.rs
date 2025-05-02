use ahash::AHashMap;
use indicatif::ProgressBar;

// compute the number of passwords to generate for range [min_size, max_size]
pub fn password_generator_count(charset_len: usize, min_size: usize, max_size: usize) -> usize {
    let mut total_password_count = 0;
    for i in min_size..=max_size {
        total_password_count += charset_len.pow(i as u32);
    }
    total_password_count
}

// compute the number of passwords already generated up to `starting_password` with `min_size`
pub fn password_count_already_generated(
    charset: &[char],
    min_size: usize,
    starting_password: &str,
) -> usize {
    let base = charset.len();
    let mut count = 0;

    // Step 1: Count all passwords of shorter lengths
    for len in min_size..starting_password.len() {
        count += base.pow(len as u32);
    }

    // Step 2: Interpret starting_password as a base-N number
    for (i, c) in starting_password.chars().rev().enumerate() {
        let pos = charset.iter().position(|x| *x == c).unwrap();
        count += pos * base.pow(i as u32);
    }

    count + 1 // Include the current password
}

struct PasswordGenerator {
    charset: Vec<char>,
    charset_indices: AHashMap<char, usize>,
    charset_len: usize,
    charset_first: char,
    charset_last: char,
    max_size: usize,
    current_len: usize,
    current_index: usize,
    generated_count: usize,
    total_to_generate: usize,
    password: Vec<char>,
    progress_bar: ProgressBar,
}

impl PasswordGenerator {
    fn new(
        charset: Vec<char>,
        min_size: usize,
        max_size: usize,
        starting_password: Option<String>,
        progress_bar: ProgressBar,
    ) -> Self {
        let charset_len = charset.len();
        let charset_first = *charset.first().expect("charset non empty");
        let charset_last = *charset.last().expect("charset non empty");

        // pre-compute charset indices
        let charset_indices = charset
            .iter()
            .enumerate()
            .map(|(i, c)| (*c, i))
            .collect::<AHashMap<char, usize>>();

        let mut password = vec![charset_first; min_size];
        let mut total_to_generate = password_generator_count(charset_len, min_size, max_size);
        if let Some(starting_password) = starting_password {
            password = starting_password.chars().collect();
            let password_len = password.len();
            let already_generated_count =
                password_count_already_generated(&charset, min_size, &starting_password);
            // decrease number of password to generate
            total_to_generate -= already_generated_count;
            progress_bar.println(format!(
                "Starting search space for password length {password_len} from {starting_password} (skipping {already_generated_count} passwords)"
            ));
        } else {
            // possible passwords at min size
            let possibilities = charset_len.pow(min_size as u32);
            progress_bar.println(format!(
                "Starting search space for password length {min_size} ({possibilities} possibilities)"
            ));
        }

        // init current cursors
        let current_len = password.len();
        let current_index = current_len - 1;

        Self {
            charset,
            charset_indices,
            charset_len,
            charset_first,
            charset_last,
            max_size,
            current_len,
            current_index,
            generated_count: 0,
            total_to_generate,
            password,
            progress_bar,
        }
    }
}

impl Iterator for PasswordGenerator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.password.len() > self.max_size {
            return None;
        }

        // first password
        if self.generated_count == 0 {
            self.generated_count += 1;
            return Some(self.password.iter().collect());
        }

        // end of search space
        if self.generated_count == self.total_to_generate {
            return None;
        }

        // check if we need to increase the length of the password
        if self.current_len == self.current_index + 1
            && !self.password.iter().any(|&c| c != self.charset_last)
        {
            // increase length and reset letters
            self.current_index += 1;
            self.current_len += 1;
            self.password = vec![self.charset_first; self.current_len];
            let possibilities = self.charset_len.pow(self.current_len as u32);
            self.progress_bar.println(
                format!(
                    "Starting search space for password length {} ({} possibilities) ({} passwords generated so far)",
                    self.current_len, possibilities, self.generated_count
                ));
        } else {
            let current_char = *self.password.get(self.current_index).unwrap();
            if current_char == self.charset_last {
                // current char reached the end of the charset, reset current and bump previous
                let at_prev = self
                    .password
                    .iter()
                    .rposition(|&c| c != self.charset_last)
                    .unwrap_or_else(|| {
                        panic!(
                            "Must find something else than {} in {:?}",
                            self.charset_last, self.password
                        )
                    });
                let next_prev = if at_prev == self.charset_len - 1 {
                    self.charset.get(self.charset_len - 1).unwrap()
                } else {
                    let prev_char = *self.password.get(at_prev).unwrap();
                    let prev_index_charset =
                        self.charset.iter().position(|&c| c == prev_char).unwrap();
                    self.charset.get(prev_index_charset + 1).unwrap()
                };

                self.password[self.current_index] = self.charset_first;
                self.password[at_prev] = *next_prev;

                // reset all chars after previous
                for (i, x) in self.password.iter_mut().enumerate() {
                    if *x == self.charset_last && i > at_prev {
                        *x = self.charset_first;
                    }
                }
            } else {
                // hot-path: increment current char (not at the end of charset)
                let at = *self.charset_indices.get(&current_char).unwrap();
                let next = *self.charset.get(at + 1).unwrap();
                self.password[self.current_index] = next;
            }
        }
        self.generated_count += 1;
        // TODO explore using a lending iterator to avoid allocation
        Some(self.password.iter().collect::<String>())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total_to_generate - self.generated_count;
        (remaining, Some(remaining))
    }
}

pub fn password_generator_iter(
    charset: &[char],
    min_size: usize,
    max_size: usize,
    starting_password: Option<String>,
    progress_bar: ProgressBar,
) -> impl Iterator<Item = String> {
    // start generation
    if let Some(starting_password) = &starting_password {
        progress_bar.println(format!(
            "Generating passwords with length from {} to {} starting from {} for charset with length {}\n{}",
            min_size,
            max_size,
            starting_password,
            charset.len(),
            charset.iter().collect::<String>()
        ));
    } else {
        progress_bar.println(format!(
            "Generating passwords with length from {} to {} for charset with length {}\n{}",
            min_size,
            max_size,
            charset.len(),
            charset.iter().collect::<String>()
        ));
    }
    PasswordGenerator::new(
        charset.to_vec(),
        min_size,
        max_size,
        starting_password,
        progress_bar,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::charsets::charset_lowercase_letters;
    use std::fs;

    #[test]
    fn generate_password_max_size_two() {
        let mut iter = password_generator_iter(&['a', 'b', 'c'], 1, 2, None, ProgressBar::hidden());
        assert_eq!(iter.next(), Some("a".into()));
        assert_eq!(iter.next(), Some("b".into()));
        assert_eq!(iter.next(), Some("c".into()));
        assert_eq!(iter.next(), Some("aa".into()));
        assert_eq!(iter.next(), Some("ab".into()));
        assert_eq!(iter.next(), Some("ac".into()));
        assert_eq!(iter.next(), Some("ba".into()));
        assert_eq!(iter.next(), Some("bb".into()));
        assert_eq!(iter.next(), Some("bc".into()));
        assert_eq!(iter.next(), Some("ca".into()));
        assert_eq!(iter.next(), Some("cb".into()));
        assert_eq!(iter.next(), Some("cc".into()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn generate_password_max_size_two_starting_from() {
        let mut iter = password_generator_iter(
            &['a', 'b', 'c'],
            1,
            2,
            Some("bb".to_string()),
            ProgressBar::hidden(),
        );
        assert_eq!(iter.next(), Some("bb".into()));
        assert_eq!(iter.next(), Some("bc".into()));
        assert_eq!(iter.next(), Some("ca".into()));
        assert_eq!(iter.next(), Some("cb".into()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_already_generated_count() {
        let count = password_count_already_generated(&['a', 'b', 'c'], 1, "a");
        assert_eq!(count, 1);
        let count = password_count_already_generated(&['a', 'b', 'c'], 1, "b");
        assert_eq!(count, 2);
        let count = password_count_already_generated(&['a', 'b', 'c'], 1, "c");
        assert_eq!(count, 3);
        let count = password_count_already_generated(&['a', 'b', 'c'], 1, "aa");
        assert_eq!(count, 4);
        let count = password_count_already_generated(&['a', 'b', 'c'], 1, "bb");
        assert_eq!(count, 8);
        let count = password_count_already_generated(&['a', 'b', 'c', 'd'], 1, "abcd");
        assert_eq!(count, 112);
        let charset: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            .chars()
            .collect();
        let count = password_count_already_generated(&charset, 1, "abcd");
        assert_eq!(count, 246_206);
    }

    #[test]
    fn generate_password_min_max_size_two() {
        let mut iter = password_generator_iter(&['a', 'b', 'c'], 2, 2, None, ProgressBar::hidden());
        assert_eq!(iter.next(), Some("aa".into()));
        assert_eq!(iter.next(), Some("ab".into()));
        assert_eq!(iter.next(), Some("ac".into()));
        assert_eq!(iter.next(), Some("ba".into()));
        assert_eq!(iter.next(), Some("bb".into()));
        assert_eq!(iter.next(), Some("bc".into()));
        assert_eq!(iter.next(), Some("ca".into()));
        assert_eq!(iter.next(), Some("cb".into()));
        assert_eq!(iter.next(), Some("cc".into()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn generate_password_large() {
        let mut iter = password_generator_iter(
            &charset_lowercase_letters(),
            1,
            3,
            None,
            ProgressBar::hidden(),
        );
        let gold_path = "test-files/generated-passwords-lowercase.txt";
        let gold = fs::read_to_string(gold_path).expect("gold file not found!");
        for (i1, l1) in gold.lines().enumerate() {
            let l2 = iter.next().unwrap();
            if l1.trim_end() != l2.trim_end() {
                eprintln!("## GOLD line {} ##", i1 + 1);
                eprintln!("{}", l1.trim_end());
                eprintln!("## ACTUAL ##");
                eprintln!("{}", l2.trim_end());
                eprintln!("#####");
                assert_eq!(l1, l2);
            }
        }
    }
}
