use crate::finder_errors::FinderError::{ClapMatchError, InvalidZip};
use thiserror::Error;
use zip::result::ZipError;

#[derive(Error, Debug)]
pub enum FinderError {
    #[error("standard I/O error - {e}")]
    StdIoError { e: std::io::Error },
    #[error("Invalid zip file error - {message}")]
    InvalidZip { message: String },
    #[error("File number not found within archive error - '{file_number}'")]
    FileNotFoundInArchive { file_number: usize },
    #[error("CLI argument error - {message:?}")]
    CliArgumentError { message: String },
    #[error("CLI argument error ({e})")]
    ClapError { e: clap::Error },
    #[error("CLI argument match error ({message})")]
    ClapMatchError { message: String },
}

impl FinderError {
    pub fn invalid_zip_error(message: String) -> Self {
        InvalidZip { message }
    }

    pub fn file_not_found_error(file_number: usize) -> Self {
        FinderError::FileNotFoundInArchive { file_number }
    }
}

impl From<std::io::Error> for FinderError {
    fn from(e: std::io::Error) -> Self {
        FinderError::StdIoError { e }
    }
}

impl From<ZipError> for FinderError {
    fn from(e: ZipError) -> Self {
        InvalidZip {
            message: format!("{e}"),
        }
    }
}

impl From<clap::Error> for FinderError {
    fn from(e: clap::Error) -> Self {
        FinderError::ClapError { e }
    }
}

impl From<clap::parser::MatchesError> for FinderError {
    fn from(e: clap::parser::MatchesError) -> Self {
        ClapMatchError {
            message: format!("{e}"),
        }
    }
}
