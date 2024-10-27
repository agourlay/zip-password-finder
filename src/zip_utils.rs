use crate::finder_errors::FinderError;
use std::fs::File;
use std::path::Path;
use zip::result::ZipError;
use zip::result::ZipError::UnsupportedArchive;

#[derive(Clone, Debug)]
pub struct AesInfo {
    pub aes_key_length: usize,
    pub verification_value: [u8; 2],
    pub derived_key_length: usize,
    pub salt: Vec<u8>,
}

impl AesInfo {
    pub fn new(aes_key_length: usize, verification_value: [u8; 2], salt: Vec<u8>) -> Self {
        // derive a key from the password and salt
        // the length depends on the aes key length
        let derived_key_length = 2 * aes_key_length + 2;
        AesInfo {
            aes_key_length,
            verification_value,
            derived_key_length,
            salt,
        }
    }
}

pub struct ValidatedZip {
    pub aes_info: Option<AesInfo>,
    pub file_name: Option<String>,
}

impl ValidatedZip {
    pub fn new(aes_info: Option<AesInfo>, file_name: Option<String>) -> Self {
        ValidatedZip {
            aes_info,
            file_name,
        }
    }
}

// validate that the zip requires a password
pub fn validate_zip(file_path: &Path, file_number: usize) -> Result<ValidatedZip, FinderError> {
    let file = File::open(file_path)?;
    let mut archive = zip::ZipArchive::new(file)?;
    let aes_data = archive.get_aes_verification_key_and_salt(file_number);
    let file_name = archive.name_for_index(file_number).map(|s| s.to_string());
    let zip_result = archive.by_index(file_number);
    match zip_result {
        Ok(z) => Err(FinderError::invalid_zip_error(format!(
            "the selected file in the archive is not encrypted (file_number:{} file_name:{})",
            file_number,
            z.name()
        ))),
        Err(UnsupportedArchive("Password required to decrypt file")) => {
            let aes_info =
                if let Some(aes_zip_info) = aes_data.expect("Archive validated before-hand") {
                    let aes_key_length = aes_zip_info.aes_mode.key_length();
                    let verification_value = aes_zip_info.verification_value;
                    let salt = aes_zip_info.salt;
                    Some(AesInfo::new(aes_key_length, verification_value, salt))
                } else {
                    None
                };
            Ok(ValidatedZip::new(aes_info, file_name))
        }
        Err(ZipError::FileNotFound) => Err(FinderError::file_not_found_error(file_number)),
        Err(other) => Err(FinderError::invalid_zip_error(format!(
            "unexpected error while opening archive: {other:?}"
        ))),
    }
}
