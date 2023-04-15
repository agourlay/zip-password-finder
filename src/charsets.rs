use crate::finder_errors::FinderError;
use crate::finder_errors::FinderError::CliArgumentError;

pub fn to_charset(charset_choice: &str) -> Result<Vec<char>, FinderError> {
    let mut charset: Vec<char> = vec![];
    for symbol in charset_choice.chars(){
        match symbol{
            'l' => charset.append(&mut charset_lowercase_letters()),
            'u' => charset.append(&mut charset_uppercase_letters()),
            'd' => charset.append(&mut charset_digits()),
            's' => charset.append(&mut charset_punctuations()),
            'h' => charset.append(&mut charset_lowercase_hex()),
            'H' => charset.append(&mut charset_uppercase_hex()),
            _ =>  return Err(CliArgumentError {message: "Unknown charset option".to_string()}),
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

pub fn charset_punctuations() -> Vec<char> {
    vec![
        ' ', '-', '=', '!', '@', '#', '$', '%', '^', '&', '*', '_', '+', '<', '>', '/', '?', '.',
        ';', ':', '{', '}',
    ]
}

pub fn charset_lowercase_hex() -> Vec<char> {
    vec!['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f']
}

pub fn charset_uppercase_hex() -> Vec<char> {
    vec!['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F']
}