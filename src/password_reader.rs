use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::rc::Rc;

pub fn password_reader_count(file_path: PathBuf) -> Result<usize, std::io::Error> {
    // compute the number of lines in the file
    let file = File::open(file_path).expect("Unable to open file");
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
    Ok(total_password_count)
}

pub fn password_dictionary_reader_iter(file_path: &Path) -> impl Iterator<Item = Rc<String>> {
    DictionaryReader::new(file_path.to_path_buf())
}

struct DictionaryReader {
    reader: BufReader<File>,
    line_buffer: Rc<String>,
}

impl DictionaryReader {
    pub fn new(file_path: PathBuf) -> Self {
        let file = File::open(file_path).expect("Unable to open file");
        let reader = BufReader::new(file);
        DictionaryReader {
            reader,
            line_buffer: Rc::new(String::with_capacity(1024)),
        }
    }
}

impl Iterator for DictionaryReader {
    type Item = Rc<String>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // `get_mut` returns a mutable reference into the given Rc
            // if there are no other Rc or Weak pointers to the same allocation.
            let buf = match Rc::get_mut(&mut self.line_buffer) {
                Some(buf) => {
                    buf.clear();
                    buf
                }
                None => panic!("Should not happen!"),
            };
            let res = self.reader.read_line(buf);
            match res {
                Ok(0) => return None,
                Ok(_) => {
                    // cleanup line
                    if buf.ends_with('\n') {
                        buf.pop();
                        if buf.ends_with('\r') {
                            buf.pop();
                        }
                    }
                    return Some(Rc::clone(&self.line_buffer));
                }
                Err(_) => continue, // not a valid String, ignore
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_passwords_from_dictionary() {
        let iter = password_dictionary_reader_iter(&PathBuf::from(
            "test-files/generated-passwords-lowercase.txt",
        ));
        assert_eq!(iter.count(), 18278);
    }
}
