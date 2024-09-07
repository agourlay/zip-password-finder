use crate::finder_errors::FinderError;
use crate::finder_errors::FinderError::CliArgumentError;

pub enum CharsetChoice {
    File(String),
    Preset(String),
}

pub fn charset_from_choice(charset_choice: &CharsetChoice) -> Result<Vec<char>, FinderError> {
    let mut charset = match charset_choice {
        CharsetChoice::File(file_path) => charset_from_file(file_path)?,
        CharsetChoice::Preset(preset) => preset_to_charset(preset)?,
    };
    // make sure the charset does not contain duplicates
    charset.sort_unstable();
    charset.dedup();
    Ok(charset)
}

fn charset_from_file(p0: &String) -> Result<Vec<char>, FinderError> {
    let path = std::path::Path::new(p0);
    if !path.is_file() {
        return Err(CliArgumentError {
            message: format!("'{}' does not exist", p0),
        });
    }
    let charset = std::fs::read_to_string(path)?;
    Ok(charset.chars().collect())
}

pub(crate) fn preset_to_charset(charset_choice: &str) -> Result<Vec<char>, FinderError> {
    let mut charset: Vec<char> = vec![];
    for symbol in charset_choice.chars() {
        match symbol {
            'l' => charset.append(&mut charset_lowercase_letters()),
            'u' => charset.append(&mut charset_uppercase_letters()),
            'd' => charset.append(&mut charset_digits()),
            's' => charset.append(&mut charset_symbols()),
            'h' => charset.append(&mut charset_lowercase_hex()),
            'H' => charset.append(&mut charset_uppercase_hex()),
            other => {
                return Err(CliArgumentError {
                    message: format!("Unknown charset option '{}'", other),
                })
            }
        }
    }
    Ok(charset)
}

pub fn charset_lowercase_letters() -> Vec<char> {
    vec![
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
        's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    ]
}

pub fn charset_uppercase_letters() -> Vec<char> {
    vec![
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
        'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    ]
}

pub fn charset_digits() -> Vec<char> {
    vec!['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
}

pub fn charset_symbols() -> Vec<char> {
    vec![
        ' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';',
        '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~',
    ]
}

pub fn charset_lowercase_hex() -> Vec<char> {
    vec![
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    ]
}

pub fn charset_uppercase_hex() -> Vec<char> {
    vec![
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_charset() {
        let charset = preset_to_charset("l").unwrap();
        assert_eq!(charset, charset_lowercase_letters());
        let charset = preset_to_charset("u").unwrap();
        assert_eq!(charset, charset_uppercase_letters());
        let charset = preset_to_charset("d").unwrap();
        assert_eq!(charset, charset_digits());
        let charset = preset_to_charset("s").unwrap();
        assert_eq!(charset, charset_symbols());
        let charset = preset_to_charset("h").unwrap();
        assert_eq!(charset, charset_lowercase_hex());
        let charset = preset_to_charset("H").unwrap();
        assert_eq!(charset, charset_uppercase_hex());
    }

    #[test]
    fn test_combined_charsets() {
        let charset = preset_to_charset("lu").unwrap();
        assert_eq!(
            charset,
            [charset_lowercase_letters(), charset_uppercase_letters()].concat()
        );

        let charset = preset_to_charset("lud").unwrap();
        assert_eq!(
            charset,
            [
                charset_lowercase_letters(),
                charset_uppercase_letters(),
                charset_digits(),
            ]
            .concat()
        );
    }

    #[test]
    fn test_charset_from_file() {
        let charset = charset_from_file(&"test-files/file-charset.txt".to_string()).unwrap();
        assert_eq!(
            charset,
            vec![
                'a', '"', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U', '2', '4', '6', '8', '0',
                '*', '#', '$'
            ]
        );
    }
}
