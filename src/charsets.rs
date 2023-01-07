#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CharsetChoice {
    Basic,
    Easy,
    Medium,
    Hard,
}

impl CharsetChoice {
    pub fn to_charset(self) -> Vec<char> {
        match self {
            CharsetChoice::Basic => charset_lowercase_letters(),
            CharsetChoice::Easy => {
                vec![charset_lowercase_letters(), charset_uppercase_letters()].concat()
            }
            CharsetChoice::Medium => vec![
                charset_lowercase_letters(),
                charset_uppercase_letters(),
                charset_digits(),
            ]
            .concat(),
            CharsetChoice::Hard => vec![
                charset_lowercase_letters(),
                charset_uppercase_letters(),
                charset_digits(),
                charset_punctuations(),
            ]
            .concat(),
        }
    }
}

impl clap::ValueEnum for CharsetChoice {
    fn value_variants<'a>() -> &'a [Self] {
        &[Self::Basic, Self::Easy, Self::Medium, Self::Hard]
    }

    fn to_possible_value<'a>(&self) -> Option<clap::builder::PossibleValue> {
        match self {
            Self::Basic => Some(clap::builder::PossibleValue::new("basic")),
            Self::Easy => Some(clap::builder::PossibleValue::new("easy")),
            Self::Medium => Some(clap::builder::PossibleValue::new("medium")),
            Self::Hard => Some(clap::builder::PossibleValue::new("hard")),
        }
    }
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
