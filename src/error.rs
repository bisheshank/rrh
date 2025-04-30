use std::io;
use thiserror::Error;

/// Custom error types
#[derive(Error, Debug)]
pub enum SSHError {
    // Standard error
    #[error("Stderr: {0}")]
    StdErr(String),

    // Io error
    #[error("Io: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, SSHError>;
