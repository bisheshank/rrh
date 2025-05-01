use std::io;
use thiserror::Error;

/// Custom error types
#[derive(Error, Debug)]
pub enum SshError {
    // Standard error
    #[error("Stderr: {0}")]
    StdErr(String),

    // Io error
    #[error("Io: {0}")]
    Io(#[from] io::Error),

    // Protocol error
    #[error("Protocol: {0}")]
    Protocol(String),

    // Version error
    #[error("Version String Missing")]
    MissingVersion,

    // Invalid state transition
    #[error("Invalid State Transition: {0}")]
    InvalidTransition(String, String),

    // Unimplemented functions
    #[error("Not Implemented: {0}")]
    NotImplemented(String),
}

pub type SshResult<T> = std::result::Result<T, SshError>;
