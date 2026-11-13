//! Errors for core domain types.
//!
//! Deliberately small: `via-core` describes the model and does no I/O, so
//! everything here is a validation failure with enough context to name the
//! offending value.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid {kind} {value:?}: {reason}")]
    InvalidId {
        kind: &'static str,
        value: String,
        reason: String,
    },

    #[error("invalid digest {value:?}: {reason}")]
    InvalidDigest { value: String, reason: String },

    #[error("invalid platform {value:?}: {reason}")]
    InvalidPlatform { value: String, reason: String },

    #[error("{what}: {reason}")]
    InvalidSetting { what: String, reason: String },
}

impl Error {
    pub(crate) fn invalid_digest(value: impl Into<String>, reason: impl Into<String>) -> Self {
        Error::InvalidDigest {
            value: value.into(),
            reason: reason.into(),
        }
    }
}
