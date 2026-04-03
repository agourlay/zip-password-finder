use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

pub fn password_reader_count(file_path: PathBuf) -> Result<usize, std::io::Error> {
    // compute the number of lines in the file
    let file = File::open(file_path)?;
    let mut reader = BufReader::new(file);
    let mut total_password_count = 0;
    let mut line_buffer = Vec::new();
    loop {
        // count line number without reallocating each line
        // read_until to avoid UTF-8 validation (unlike read_line which produce a String)
        let res = reader.read_until(b'\n', &mut line_buffer)?;
        if res == 0 {
            // end of file
            break;
        }
        line_buffer.clear();
        total_password_count += 1;
    }
    Ok(total_password_count)
}

pub fn password_dictionary_reader_iter(file_path: PathBuf) -> impl Iterator<Item = Vec<u8>> {
    DictionaryReader::new(file_path)
}

struct DictionaryReader {
    reader: BufReader<File>,
    line_buffer: Vec<u8>,
}

impl DictionaryReader {
    pub fn new(file_path: PathBuf) -> Self {
        let file = File::open(file_path).expect("Unable to open file");
        let reader = BufReader::new(file);
        Self {
            reader,
            line_buffer: Vec::new(),
        }
    }
}

impl Iterator for DictionaryReader {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            self.line_buffer.clear();
            let res = self.reader.read_until(b'\n', &mut self.line_buffer);
            match res {
                Ok(0) => return None,
                Ok(_) => {
                    // cleanup line endings
                    if self.line_buffer.last() == Some(&b'\n') {
                        self.line_buffer.pop();
                        if self.line_buffer.last() == Some(&b'\r') {
                            self.line_buffer.pop();
                        }
                    }
                    return Some(self.line_buffer.clone());
                }
                Err(_) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_passwords_from_dictionary() {
        let path = PathBuf::from("test-files/generated-passwords-lowercase.txt");
        let iter = password_dictionary_reader_iter(path);
        assert_eq!(iter.count(), 18278);
    }

    #[test]
    fn password_count_matches_iterator_count() {
        let path = PathBuf::from("test-files/generated-passwords-lowercase.txt");
        let count = password_reader_count(path).unwrap();
        assert_eq!(count, 18278);
    }

    #[test]
    fn dictionary_reader_trims_lines() {
        let path = PathBuf::from("test-files/generated-passwords-lowercase.txt");
        let mut iter = password_dictionary_reader_iter(path);
        let first = iter.next().unwrap();
        // should not contain trailing newline or carriage return
        assert!(!first.ends_with(b"\n"));
        assert!(!first.ends_with(b"\r"));
        assert_eq!(first, b"a");
    }
}
