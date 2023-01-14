use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

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

pub fn password_dictionary_reader_iter(file_path: &PathBuf) -> impl Iterator<Item = String> {
    // start actual reader
    let file = File::open(file_path).expect("Unable to open file");
    let reader = BufReader::new(file);
    reader.lines().filter_map(|line| line.ok()) // ignore non UTF8 strings
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
