use ahash::AHashMap;
use indicatif::ProgressBar;
use std::rc::Rc;

pub fn password_generator_count(charset: &Vec<char>, min_size: usize, max_size: usize) -> usize {
    // compute the number of passwords to generate
    let charset_len = charset.len();
    let mut total_password_count = 0;
    for i in min_size..=max_size {
        total_password_count += charset_len.pow(i as u32)
    }
    total_password_count
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
    password_buffer: Rc<String>,
    progress_bar: ProgressBar,
}

impl PasswordGenerator {
    fn new(
        charset: Vec<char>,
        min_size: usize,
        max_size: usize,
        progress_bar: ProgressBar,
    ) -> PasswordGenerator {
        let charset_len = charset.len();
        let charset_first = *charset.first().expect("charset non empty");
        let charset_last = *charset.last().expect("charset non empty");

        // pre-compute charset indices
        let charset_indices = charset
            .iter()
            .enumerate()
            .map(|(i, c)| (*c, i))
            .collect::<AHashMap<char, usize>>();

        progress_bar.println(format!(
            "Starting search space for password length {min_size} ({charset_len} possibilities) "
        ));
        let password = vec![charset_first; min_size];
        let password_buffer = Rc::new(password.iter().collect());
        let current_len = password.len();
        let current_index = current_len - 1;

        let generated_count = 0;
        let total_to_generate = password_generator_count(&charset, min_size, max_size);

        PasswordGenerator {
            charset,
            charset_indices,
            charset_len,
            charset_first,
            charset_last,
            max_size,
            current_len,
            current_index,
            generated_count,
            total_to_generate,
            password,
            password_buffer,
            progress_bar,
        }
    }
}

impl Iterator for PasswordGenerator {
    type Item = Rc<String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.password.len() > self.max_size {
            return None;
        }

        // first password
        if self.generated_count == 0 {
            self.generated_count += 1;
            return Some(Rc::clone(&self.password_buffer));
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
                        *x = self.charset_first
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
        // `get_mut` returns a mutable reference into the given Rc
        // if there are no other Rc or Weak pointers to the same allocation.
        let buf = match Rc::get_mut(&mut self.password_buffer) {
            Some(buf) => {
                buf.clear();
                buf
            }
            None => panic!("Should not happen!"),
        };
        buf.extend(self.password.iter());
        Some(Rc::clone(&self.password_buffer))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total_to_generate - self.generated_count;
        (remaining, Some(remaining))
    }
}

pub fn password_generator_iter(
    charset: &Vec<char>,
    min_size: usize,
    max_size: usize,
    progress_bar: ProgressBar,
) -> impl Iterator<Item = Rc<String>> {
    // start generation
    progress_bar.println(format!(
        "Generating passwords with length from {} to {} for charset with length {}\n{:?}",
        min_size,
        max_size,
        charset.len(),
        charset
    ));
    PasswordGenerator::new(charset.clone(), min_size, max_size, progress_bar)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::charsets::charset_lowercase_letters;
    use std::fs;

    #[test]
    fn generate_password_max_size_two() {
        let mut iter = password_generator_iter(&vec!['a', 'b', 'c'], 1, 2, ProgressBar::hidden());
        assert_eq!(iter.next(), Some(Rc::new("a".into())));
        assert_eq!(iter.next(), Some(Rc::new("b".into())));
        assert_eq!(iter.next(), Some(Rc::new("c".into())));
        assert_eq!(iter.next(), Some(Rc::new("aa".into())));
        assert_eq!(iter.next(), Some(Rc::new("ab".into())));
        assert_eq!(iter.next(), Some(Rc::new("ac".into())));
        assert_eq!(iter.next(), Some(Rc::new("ba".into())));
        assert_eq!(iter.next(), Some(Rc::new("bb".into())));
        assert_eq!(iter.next(), Some(Rc::new("bc".into())));
        assert_eq!(iter.next(), Some(Rc::new("ca".into())));
        assert_eq!(iter.next(), Some(Rc::new("cb".into())));
        assert_eq!(iter.next(), Some(Rc::new("cc".into())));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn generate_password_min_max_size_two() {
        let mut iter = password_generator_iter(&vec!['a', 'b', 'c'], 2, 2, ProgressBar::hidden());
        assert_eq!(iter.next(), Some(Rc::new("aa".into())));
        assert_eq!(iter.next(), Some(Rc::new("ab".into())));
        assert_eq!(iter.next(), Some(Rc::new("ac".into())));
        assert_eq!(iter.next(), Some(Rc::new("ba".into())));
        assert_eq!(iter.next(), Some(Rc::new("bb".into())));
        assert_eq!(iter.next(), Some(Rc::new("bc".into())));
        assert_eq!(iter.next(), Some(Rc::new("ca".into())));
        assert_eq!(iter.next(), Some(Rc::new("cb".into())));
        assert_eq!(iter.next(), Some(Rc::new("cc".into())));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn generate_password_large() {
        let mut iter =
            password_generator_iter(&charset_lowercase_letters(), 1, 3, ProgressBar::hidden());
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
                assert_eq!(l1, (*l2).clone());
            }
        }
    }
}
