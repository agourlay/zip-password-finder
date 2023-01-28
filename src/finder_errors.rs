use crate::finder_errors::FinderError::InvalidZip;
use thiserror::Error;
use zip::result::ZipError;

#[derive(Error, Debug)]
pub enum FinderError {
    #[error("standard I/O error - {e}")]
    StdIoError { e: std::io::Error },
    #[error("Invalid zip file error - {message}")]
    InvalidZip { message: String },
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
}

impl std::convert::From<std::io::Error> for FinderError {
    fn from(e: std::io::Error) -> Self {
        FinderError::StdIoError { e }
    }
}

impl std::convert::From<ZipError> for FinderError {
    fn from(e: ZipError) -> Self {
        FinderError::InvalidZip {
            message: format!("{e}"),
        }
    }
}

impl std::convert::From<clap::Error> for FinderError {
    fn from(e: clap::Error) -> Self {
        FinderError::ClapError { e }
    }
}

impl std::convert::From<clap::parser::MatchesError> for FinderError {
    fn from(e: clap::parser::MatchesError) -> Self {
        FinderError::ClapMatchError {
            message: format!("{e}"),
        }
    }
}
