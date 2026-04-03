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
    charset: Vec<u8>,
    // Direct lookup table: byte value -> index in charset (avoids HashMap hashing)
    charset_lookup: [u8; 128],
    charset_len: usize,
    charset_last_idx: u8,
    max_size: usize,
    generated_count: usize,
    total_to_generate: usize,
    password: Vec<u8>,
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
        let charset_bytes: Vec<u8> = charset.iter().map(|&c| c as u8).collect();
        let charset_len = charset_bytes.len();

        // Build direct lookup table: byte -> index in charset
        let mut charset_lookup = [0u8; 128];
        for (i, &b) in charset_bytes.iter().enumerate() {
            charset_lookup[b as usize] = i as u8;
        }

        let charset_last_idx = (charset_len - 1) as u8;

        let mut password = vec![charset_bytes[0]; min_size];
        let mut total_to_generate = password_generator_count(charset_len, min_size, max_size);
        if let Some(starting_password) = starting_password {
            password = starting_password.bytes().collect();
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

        Self {
            charset: charset_bytes,
            charset_lookup,
            charset_len,
            charset_last_idx,
            max_size,
            generated_count: 0,
            total_to_generate,
            password,
            progress_bar,
        }
    }
}

impl Iterator for PasswordGenerator {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.password.len() > self.max_size {
            return None;
        }

        // first password
        if self.generated_count == 0 {
            self.generated_count += 1;
            return Some(self.password.clone());
        }

        // end of search space
        if self.generated_count == self.total_to_generate {
            return None;
        }

        // Odometer-style increment from rightmost position
        let mut carry = true;
        for i in (0..self.password.len()).rev() {
            if !carry {
                break;
            }
            let idx = self.charset_lookup[self.password[i] as usize];
            if idx < self.charset_last_idx {
                self.password[i] = self.charset[(idx + 1) as usize];
                carry = false;
            } else {
                self.password[i] = self.charset[0];
            }
        }

        if carry {
            // All positions overflowed -> increase length
            let new_len = self.password.len() + 1;
            self.password = vec![self.charset[0]; new_len];
            let possibilities = self.charset_len.pow(new_len as u32);
            self.progress_bar.println(format!(
                "Starting search space for password length {} ({} possibilities) ({} passwords generated so far)",
                new_len, possibilities, self.generated_count
            ));
        }

        self.generated_count += 1;
        Some(self.password.clone())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total_to_generate - self.generated_count;
        (remaining, Some(remaining))
    }
}

pub fn password_generator_iter(
    charset: Vec<char>,
    min_size: usize,
    max_size: usize,
    starting_password: Option<String>,
    progress_bar: ProgressBar,
) -> impl Iterator<Item = Vec<u8>> {
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
    PasswordGenerator::new(charset, min_size, max_size, starting_password, progress_bar)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::charsets::charset_lowercase_letters;
    use std::fs;

    #[test]
    fn generate_password_max_size_two() {
        let mut iter =
            password_generator_iter(vec!['a', 'b', 'c'], 1, 2, None, ProgressBar::hidden());
        assert_eq!(iter.next(), Some(b"a".to_vec()));
        assert_eq!(iter.next(), Some(b"b".to_vec()));
        assert_eq!(iter.next(), Some(b"c".to_vec()));
        assert_eq!(iter.next(), Some(b"aa".to_vec()));
        assert_eq!(iter.next(), Some(b"ab".to_vec()));
        assert_eq!(iter.next(), Some(b"ac".to_vec()));
        assert_eq!(iter.next(), Some(b"ba".to_vec()));
        assert_eq!(iter.next(), Some(b"bb".to_vec()));
        assert_eq!(iter.next(), Some(b"bc".to_vec()));
        assert_eq!(iter.next(), Some(b"ca".to_vec()));
        assert_eq!(iter.next(), Some(b"cb".to_vec()));
        assert_eq!(iter.next(), Some(b"cc".to_vec()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn generate_password_max_size_two_starting_from() {
        let mut iter = password_generator_iter(
            vec!['a', 'b', 'c'],
            1,
            2,
            Some("bb".to_string()),
            ProgressBar::hidden(),
        );
        assert_eq!(iter.next(), Some(b"bb".to_vec()));
        assert_eq!(iter.next(), Some(b"bc".to_vec()));
        assert_eq!(iter.next(), Some(b"ca".to_vec()));
        assert_eq!(iter.next(), Some(b"cb".to_vec()));
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
        let mut iter =
            password_generator_iter(vec!['a', 'b', 'c'], 2, 2, None, ProgressBar::hidden());
        assert_eq!(iter.next(), Some(b"aa".to_vec()));
        assert_eq!(iter.next(), Some(b"ab".to_vec()));
        assert_eq!(iter.next(), Some(b"ac".to_vec()));
        assert_eq!(iter.next(), Some(b"ba".to_vec()));
        assert_eq!(iter.next(), Some(b"bb".to_vec()));
        assert_eq!(iter.next(), Some(b"bc".to_vec()));
        assert_eq!(iter.next(), Some(b"ca".to_vec()));
        assert_eq!(iter.next(), Some(b"cb".to_vec()));
        assert_eq!(iter.next(), Some(b"cc".to_vec()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn password_count_single_length() {
        assert_eq!(password_generator_count(3, 1, 1), 3);
        assert_eq!(password_generator_count(26, 1, 1), 26);
        assert_eq!(password_generator_count(10, 3, 3), 1000);
    }

    #[test]
    fn password_count_range() {
        // charset size 3, lengths 1-2: 3 + 9 = 12
        assert_eq!(password_generator_count(3, 1, 2), 12);
        // charset size 2, lengths 1-3: 2 + 4 + 8 = 14
        assert_eq!(password_generator_count(2, 1, 3), 14);
    }

    #[test]
    fn generate_password_single_char_charset() {
        let mut iter = password_generator_iter(vec!['a'], 1, 3, None, ProgressBar::hidden());
        assert_eq!(iter.next(), Some(b"a".to_vec()));
        assert_eq!(iter.next(), Some(b"aa".to_vec()));
        assert_eq!(iter.next(), Some(b"aaa".to_vec()));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn generate_password_size_hint() {
        let mut iter = password_generator_iter(vec!['a', 'b'], 1, 2, None, ProgressBar::hidden());
        assert_eq!(iter.size_hint(), (6, Some(6))); // 2 + 4 = 6
        iter.next();
        assert_eq!(iter.size_hint(), (5, Some(5)));
    }

    #[test]
    fn generate_password_large() {
        let mut iter = password_generator_iter(
            charset_lowercase_letters(),
            1,
            3,
            None,
            ProgressBar::hidden(),
        );
        let gold_path = "test-files/generated-passwords-lowercase.txt";
        let gold = fs::read_to_string(gold_path).expect("gold file not found!");
        for (i1, l1) in gold.lines().enumerate() {
            let l2 = iter.next().unwrap();
            let l2_str = String::from_utf8(l2).unwrap();
            if l1.trim_end() != l2_str.trim_end() {
                eprintln!("## GOLD line {} ##", i1 + 1);
                eprintln!("{}", l1.trim_end());
                eprintln!("## ACTUAL ##");
                eprintln!("{}", l2_str.trim_end());
                eprintln!("#####");
                assert_eq!(l1, l2_str);
            }
        }
    }
}
