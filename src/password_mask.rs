use crate::charsets::{
    charset_digits, charset_lowercase_hex, charset_lowercase_letters, charset_symbols,
    charset_uppercase_hex, charset_uppercase_letters,
};
use crate::finder_errors::FinderError;
use crate::finder_errors::FinderError::CliArgumentError;

/// A parsed mask is a sequence of positions, each with its own charset.
#[derive(Clone, Debug)]
pub struct ParsedMask {
    pub positions: Vec<Vec<char>>,
}

/// Resolve a built-in charset token character to its charset.
fn resolve_builtin_token(token: char) -> Option<Vec<char>> {
    match token {
        'l' => Some(charset_lowercase_letters()),
        'u' => Some(charset_uppercase_letters()),
        'd' => Some(charset_digits()),
        's' => Some(charset_symbols()),
        'a' => {
            let mut all = charset_lowercase_letters();
            all.extend(charset_uppercase_letters());
            all.extend(charset_digits());
            all.extend(charset_symbols());
            Some(all)
        }
        'h' => Some(charset_lowercase_hex()),
        'H' => Some(charset_uppercase_hex()),
        _ => None,
    }
}

/// Parse a custom charset definition string into a charset.
///
/// Custom charset definitions can contain:
/// - Built-in tokens like `?l`, `?d`, `?u`, etc. which expand to their charsets
/// - Literal characters
///
/// For example: `?l?d` expands to lowercase letters + digits,
/// `aeiou` is just those 5 vowels, `?l@#$` is lowercase + @, #, $.
pub fn parse_custom_charset(definition: &str) -> Result<Vec<char>, FinderError> {
    let mut charset = Vec::new();
    let mut chars = definition.chars();

    while let Some(c) = chars.next() {
        if c == '?' {
            match chars.next() {
                Some('?') => charset.push('?'),
                Some(token) => {
                    if let Some(builtin) = resolve_builtin_token(token) {
                        charset.extend(builtin);
                    } else {
                        return Err(CliArgumentError {
                            message: format!(
                                "Unknown token '?{token}' in custom charset definition"
                            ),
                        });
                    }
                }
                None => {
                    return Err(CliArgumentError {
                        message: "Custom charset definition ends with incomplete token '?'"
                            .to_string(),
                    });
                }
            }
        } else {
            charset.push(c);
        }
    }

    if charset.is_empty() {
        return Err(CliArgumentError {
            message: "Custom charset definition is empty".to_string(),
        });
    }

    // deduplicate while preserving order
    let mut seen = Vec::with_capacity(charset.len());
    for c in charset {
        if !seen.contains(&c) {
            seen.push(c);
        }
    }

    Ok(seen)
}

/// Custom charsets `?1` through `?4`, indexed 0-3.
pub type CustomCharsets = [Option<Vec<char>>; 4];

/// Parse a mask pattern string into a `ParsedMask`.
///
/// Mask tokens:
/// - `?l` = lowercase letters (a-z)
/// - `?u` = uppercase letters (A-Z)
/// - `?d` = digits (0-9)
/// - `?s` = symbols
/// - `?a` = all printable (l+u+d+s)
/// - `?h` = lowercase hex (0-9a-f)
/// - `?H` = uppercase hex (0-9A-F)
/// - `?1`..`?4` = custom charsets
/// - `??` = literal '?'
/// - Any other character = literal
pub fn parse_mask(mask: &str, custom_charsets: &CustomCharsets) -> Result<ParsedMask, FinderError> {
    let mut positions = Vec::new();
    let mut chars = mask.chars();

    while let Some(c) = chars.next() {
        if c == '?' {
            match chars.next() {
                Some('?') => positions.push(vec!['?']),
                Some(token @ '1'..='4') => {
                    let idx = (token as usize) - ('1' as usize);
                    match &custom_charsets[idx] {
                        Some(charset) => positions.push(charset.clone()),
                        None => {
                            return Err(CliArgumentError {
                                message: format!(
                                    "Custom charset ?{token} used in mask but --customCharset{token} not provided"
                                ),
                            });
                        }
                    }
                }
                Some(token) => {
                    if let Some(builtin) = resolve_builtin_token(token) {
                        positions.push(builtin);
                    } else {
                        return Err(CliArgumentError {
                            message: format!("Unknown mask token '?{token}'"),
                        });
                    }
                }
                None => {
                    return Err(CliArgumentError {
                        message: "Mask ends with incomplete token '?'".to_string(),
                    });
                }
            }
        } else {
            positions.push(vec![c]);
        }
    }

    if positions.is_empty() {
        return Err(CliArgumentError {
            message: "Mask pattern is empty".to_string(),
        });
    }

    Ok(ParsedMask { positions })
}

/// Compute the total number of passwords for a parsed mask.
pub fn mask_password_count(mask: &ParsedMask) -> usize {
    mask.positions.iter().map(|p| p.len()).product()
}

struct MaskPasswordGenerator {
    positions: Vec<Vec<char>>,
    indices: Vec<usize>,
    total: usize,
    generated: usize,
    finished: bool,
}

impl MaskPasswordGenerator {
    fn new(mask: ParsedMask) -> Self {
        let total = mask_password_count(&mask);
        let len = mask.positions.len();
        Self {
            positions: mask.positions,
            indices: vec![0; len],
            total,
            generated: 0,
            finished: total == 0,
        }
    }

    fn current_password(&self) -> Vec<u8> {
        self.indices
            .iter()
            .enumerate()
            .map(|(pos, &idx)| self.positions[pos][idx] as u8)
            .collect()
    }
}

impl Iterator for MaskPasswordGenerator {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let password = self.current_password();
        self.generated += 1;

        if self.generated == self.total {
            self.finished = true;
        } else {
            // Increment: rightmost position first (odometer style)
            let mut carry = true;
            for i in (0..self.indices.len()).rev() {
                if carry {
                    self.indices[i] += 1;
                    if self.indices[i] >= self.positions[i].len() {
                        self.indices[i] = 0;
                    } else {
                        carry = false;
                    }
                }
            }
        }

        Some(password)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total - self.generated;
        (remaining, Some(remaining))
    }
}

pub fn mask_password_iter(mask: ParsedMask) -> impl Iterator<Item = Vec<u8>> {
    MaskPasswordGenerator::new(mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NO_CUSTOM: CustomCharsets = [None, None, None, None];

    #[test]
    fn parse_simple_mask() {
        let mask = parse_mask("?l?d", &NO_CUSTOM).unwrap();
        assert_eq!(mask.positions.len(), 2);
        assert_eq!(mask.positions[0].len(), 26); // lowercase
        assert_eq!(mask.positions[1].len(), 10); // digits
    }

    #[test]
    fn parse_literal_chars() {
        let mask = parse_mask("abc", &NO_CUSTOM).unwrap();
        assert_eq!(mask.positions.len(), 3);
        assert_eq!(mask.positions[0], vec!['a']);
        assert_eq!(mask.positions[1], vec!['b']);
        assert_eq!(mask.positions[2], vec!['c']);
    }

    #[test]
    fn parse_escaped_question_mark() {
        let mask = parse_mask("??", &NO_CUSTOM).unwrap();
        assert_eq!(mask.positions.len(), 1);
        assert_eq!(mask.positions[0], vec!['?']);
    }

    #[test]
    fn parse_mixed_mask() {
        let mask = parse_mask("prefix?d?l", &NO_CUSTOM).unwrap();
        assert_eq!(mask.positions.len(), 8); // 6 literals + 2 tokens
        // first 6 are literals
        assert_eq!(mask.positions[0], vec!['p']);
        assert_eq!(mask.positions[5], vec!['x']);
        // last 2 are charsets
        assert_eq!(mask.positions[6].len(), 10); // digits
        assert_eq!(mask.positions[7].len(), 26); // lowercase
    }

    #[test]
    fn parse_empty_mask_error() {
        assert!(parse_mask("", &NO_CUSTOM).is_err());
    }

    #[test]
    fn parse_incomplete_token_error() {
        assert!(parse_mask("abc?", &NO_CUSTOM).is_err());
    }

    #[test]
    fn parse_unknown_token_error() {
        assert!(parse_mask("?z", &NO_CUSTOM).is_err());
    }

    #[test]
    fn mask_count() {
        let mask = parse_mask("?d?d", &NO_CUSTOM).unwrap();
        assert_eq!(mask_password_count(&mask), 100);
    }

    #[test]
    fn mask_count_with_literal() {
        let mask = parse_mask("a?d", &NO_CUSTOM).unwrap();
        assert_eq!(mask_password_count(&mask), 10);
    }

    #[test]
    fn generate_small_mask() {
        let mask = parse_mask("?d", &NO_CUSTOM).unwrap();
        let passwords: Vec<Vec<u8>> = mask_password_iter(mask).collect();
        assert_eq!(passwords.len(), 10);
        assert_eq!(passwords[0], b"0");
        assert_eq!(passwords[9], b"9");
    }

    #[test]
    fn generate_two_digit_mask() {
        let mask = parse_mask("?d?d", &NO_CUSTOM).unwrap();
        let passwords: Vec<Vec<u8>> = mask_password_iter(mask).collect();
        assert_eq!(passwords.len(), 100);
        assert_eq!(passwords[0], b"00");
        assert_eq!(passwords[1], b"01");
        assert_eq!(passwords[9], b"09");
        assert_eq!(passwords[10], b"10");
        assert_eq!(passwords[99], b"99");
    }

    #[test]
    fn generate_literal_prefix_mask() {
        let mask = parse_mask("ab?d", &NO_CUSTOM).unwrap();
        let passwords: Vec<Vec<u8>> = mask_password_iter(mask).collect();
        assert_eq!(passwords.len(), 10);
        assert_eq!(passwords[0], b"ab0");
        assert_eq!(passwords[9], b"ab9");
    }

    #[test]
    fn generate_all_literals() {
        let mask = parse_mask("hello", &NO_CUSTOM).unwrap();
        let passwords: Vec<Vec<u8>> = mask_password_iter(mask).collect();
        assert_eq!(passwords.len(), 1);
        assert_eq!(passwords[0], b"hello");
    }

    #[test]
    fn parse_all_token_types() {
        let mask = parse_mask("?l?u?d?s?a?h?H", &NO_CUSTOM).unwrap();
        assert_eq!(mask.positions.len(), 7);
        assert_eq!(mask.positions[0].len(), 26); // lowercase
        assert_eq!(mask.positions[1].len(), 26); // uppercase
        assert_eq!(mask.positions[2].len(), 10); // digits
        assert_eq!(mask.positions[3].len(), 33); // symbols
        assert_eq!(mask.positions[4].len(), 95); // all (26+26+10+33)
        assert_eq!(mask.positions[5].len(), 16); // lowercase hex
        assert_eq!(mask.positions[6].len(), 16); // uppercase hex
    }

    // Custom charset tests

    #[test]
    fn parse_custom_charset_literal() {
        let charset = parse_custom_charset("aeiou").unwrap();
        assert_eq!(charset, vec!['a', 'e', 'i', 'o', 'u']);
    }

    #[test]
    fn parse_custom_charset_with_builtin() {
        let charset = parse_custom_charset("?l?d").unwrap();
        assert_eq!(charset.len(), 36); // 26 lowercase + 10 digits
    }

    #[test]
    fn parse_custom_charset_mixed() {
        let charset = parse_custom_charset("@#?d").unwrap();
        assert_eq!(charset.len(), 12); // @ + # + 10 digits
        assert_eq!(charset[0], '@');
        assert_eq!(charset[1], '#');
    }

    #[test]
    fn parse_custom_charset_deduplicates() {
        let charset = parse_custom_charset("aab").unwrap();
        assert_eq!(charset, vec!['a', 'b']);
    }

    #[test]
    fn parse_custom_charset_empty_error() {
        assert!(parse_custom_charset("").is_err());
    }

    #[test]
    fn parse_custom_charset_incomplete_token_error() {
        assert!(parse_custom_charset("abc?").is_err());
    }

    #[test]
    fn parse_custom_charset_unknown_token_error() {
        assert!(parse_custom_charset("?z").is_err());
    }

    #[test]
    fn parse_custom_charset_escaped_question_mark() {
        let charset = parse_custom_charset("a??b").unwrap();
        assert_eq!(charset, vec!['a', '?', 'b']);
    }

    #[test]
    fn mask_with_custom_charset() {
        let custom: CustomCharsets = [Some(vec!['x', 'y', 'z']), None, None, None];
        let mask = parse_mask("?1?d", &custom).unwrap();
        assert_eq!(mask.positions.len(), 2);
        assert_eq!(mask.positions[0], vec!['x', 'y', 'z']);
        assert_eq!(mask.positions[1].len(), 10); // digits
    }

    #[test]
    fn mask_with_multiple_custom_charsets() {
        let custom: CustomCharsets = [Some(vec!['a', 'b']), Some(vec!['1', '2', '3']), None, None];
        let mask = parse_mask("?1?2", &custom).unwrap();
        let passwords: Vec<Vec<u8>> = mask_password_iter(mask).collect();
        assert_eq!(passwords.len(), 6); // 2 * 3
        assert_eq!(passwords[0], b"a1");
        assert_eq!(passwords[1], b"a2");
        assert_eq!(passwords[2], b"a3");
        assert_eq!(passwords[3], b"b1");
        assert_eq!(passwords[4], b"b2");
        assert_eq!(passwords[5], b"b3");
    }

    #[test]
    fn mask_with_undefined_custom_charset_error() {
        assert!(parse_mask("?1?d", &NO_CUSTOM).is_err());
    }

    #[test]
    fn mask_custom_charset4() {
        let custom: CustomCharsets = [None, None, None, Some(vec!['!', '@'])];
        let mask = parse_mask("?4", &custom).unwrap();
        assert_eq!(mask.positions[0], vec!['!', '@']);
    }

    #[test]
    fn size_hint_accurate() {
        let mask = parse_mask("?d?d", &NO_CUSTOM).unwrap();
        let mut iter = MaskPasswordGenerator::new(mask);
        assert_eq!(iter.size_hint(), (100, Some(100)));
        iter.next();
        assert_eq!(iter.size_hint(), (99, Some(99)));
        // exhaust the iterator
        let remaining: Vec<_> = iter.collect();
        assert_eq!(remaining.len(), 99);
    }

    #[test]
    fn custom_charset_with_overlapping_builtins_deduplicates() {
        // ?h includes 0-9 and a-f; ?d includes 0-9 — overlap on digits should be deduped
        let charset = parse_custom_charset("?h?d").unwrap();
        assert_eq!(charset.len(), 16); // same as ?h alone since ?d is a subset
    }

    #[test]
    fn custom_charset_rejects_custom_references() {
        // ?1 through ?4 are not valid inside custom charset definitions
        assert!(parse_custom_charset("?1").is_err());
        assert!(parse_custom_charset("?2").is_err());
        assert!(parse_custom_charset("?3").is_err());
        assert!(parse_custom_charset("?4").is_err());
    }

    #[test]
    fn mask_with_all_four_custom_charsets() {
        let custom: CustomCharsets = [
            Some(vec!['a', 'b']),
            Some(vec!['1', '2']),
            Some(vec!['x']),
            Some(vec!['!', '@', '#']),
        ];
        let mask = parse_mask("?1?2?3?4", &custom).unwrap();
        assert_eq!(mask_password_count(&mask), 12); // 2 * 2 * 1 * 3
        let passwords: Vec<Vec<u8>> = mask_password_iter(mask).collect();
        assert_eq!(passwords.len(), 12);
        assert_eq!(passwords[0], b"a1x!");
        assert_eq!(passwords[11], b"b2x#");
    }

    #[test]
    fn mask_count_with_custom_charset() {
        let custom: CustomCharsets = [Some(vec!['a', 'b', 'c']), None, None, None];
        let mask = parse_mask("?1?1?d", &custom).unwrap();
        assert_eq!(mask_password_count(&mask), 3 * 3 * 10); // 90
    }
}
