use thiserror::Error;

/// Custom error types
#[derive(Error, Debug)]
pub enum SshError {
    #[error("Stderr: {0}")]
    StdErr(String),

    #[error("Io: {0}")]
    Io(String),

    #[error("Protocol: {0}")]
    Protocol(String),

    #[error("Version String Missing")]
    MissingVersion,

    #[error("Invalid State Transition: {0} -> {1}")]
    InvalidTransition(String, String),

    #[error("Not Implemented: {0}")]
    NotImplemented(String),

    #[error("Task Join Error: {0}")]
    JoinError(String),
}

impl From<std::io::Error> for SshError {
    fn from(err: std::io::Error) -> Self {
        SshError::Io(err.to_string())
    }
}

pub type SshResult<T> = std::result::Result<T, SshError>;

