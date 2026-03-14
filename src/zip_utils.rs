use crate::finder_errors::FinderError;
use std::fs::File;
use std::path::Path;
use zip::result::ZipError::UnsupportedArchive;

#[derive(Clone, Debug)]
pub struct AesInfo {
    pub aes_key_length: usize,
    pub verification_value: [u8; 2],
    pub derived_key_length: usize,
    pub salt: Vec<u8>,
}

impl AesInfo {
    pub const fn new(aes_key_length: usize, verification_value: [u8; 2], salt: Vec<u8>) -> Self {
        // derive a key from the password and salt
        // the length depends on the aes key length
        let derived_key_length = 2 * aes_key_length + 2;
        Self {
            aes_key_length,
            verification_value,
            derived_key_length,
            salt,
        }
    }
}

pub struct ValidatedZip {
    pub file_number: usize,
    pub aes_info: Option<AesInfo>,
    pub file_name: Option<String>,
}

impl ValidatedZip {
    pub const fn new(
        file_number: usize,
        aes_info: Option<AesInfo>,
        file_name: Option<String>,
    ) -> Self {
        Self {
            file_number,
            aes_info,
            file_name,
        }
    }
}

// Check if a specific file in the archive is encrypted
fn is_file_encrypted(archive: &mut zip::ZipArchive<File>, index: usize) -> bool {
    matches!(
        archive.by_index(index),
        Err(UnsupportedArchive("Password required to decrypt file"))
    )
}

// Build a listing of files in the archive for diagnostics (capped at 20 entries)
fn format_archive_listing(archive: &mut zip::ZipArchive<File>) -> String {
    let total = archive.len();
    let display_count = total.min(20);
    let mut listing = format!("Archive contents ({total} files):");
    for i in 0..display_count {
        let name = archive.name_for_index(i).unwrap_or("<unknown>").to_string();
        let is_dir = name.ends_with('/');
        let encrypted = is_file_encrypted(archive, i);
        let kind = if is_dir { "dir" } else { "file" };
        let enc = if encrypted { ", encrypted" } else { "" };
        listing.push_str(&format!("\n  [{i}] {name} ({kind}{enc})"));
    }
    if total > display_count {
        listing.push_str(&format!("\n  ... and {} more files", total - display_count));
    }
    listing
}

// Find the first encrypted file in the archive, returns its index
fn find_first_encrypted_file(archive: &mut zip::ZipArchive<File>) -> Option<usize> {
    (0..archive.len()).find(|&i| is_file_encrypted(archive, i))
}

// validate that the zip requires a password
pub fn validate_zip(file_path: &Path, file_number: usize) -> Result<ValidatedZip, FinderError> {
    let file = File::open(file_path)?;
    let mut archive = zip::ZipArchive::new(file)?;

    // Resolve the target file index
    let target_index = if is_file_encrypted(&mut archive, file_number) {
        file_number
    } else {
        // The selected file is not encrypted, try to find one that is
        match find_first_encrypted_file(&mut archive) {
            Some(index) => {
                let name = archive.name_for_index(index).unwrap_or("<unknown>");
                eprintln!(
                    "File at index {file_number} is not encrypted, auto-selecting file at index {index} ({name})"
                );
                index
            }
            None => {
                return Err(FinderError::invalid_zip_error(format!(
                    "no encrypted file found in archive\n{}",
                    format_archive_listing(&mut archive)
                )));
            }
        }
    };

    // At this point, target_index is guaranteed to be an encrypted file
    let aes_data = archive.get_aes_verification_key_and_salt(target_index);
    let file_name = archive
        .name_for_index(target_index)
        .map(ToString::to_string);
    let aes_info = if let Some(aes_zip_info) = aes_data.expect("Archive validated before-hand") {
        let aes_key_length = aes_zip_info.aes_mode.key_length();
        let verification_value = aes_zip_info.verification_value;
        let salt = aes_zip_info.salt;
        Some(AesInfo::new(aes_key_length, verification_value, salt))
    } else {
        None
    };
    Ok(ValidatedZip::new(target_index, aes_info, file_name))
}
