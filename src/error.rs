use thiserror::Error;

/// Custom error types
#[derive(Error, Debug)]
pub enum SSHError {
    // Standard Error
    #[error("Stderr: {0}")]
    StdErr(String),
}

pub type Result<T> = std::result::Result<T, SSHError>;
