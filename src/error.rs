//----------- GenerateError --------------------------------------------------

use core::fmt;

use domain::base::iana::SecurityAlgorithm;

/// An error occurred while generating a key pair with a KMIP server.
#[derive(Clone, Debug)]
pub enum GenerateError {
    /// The requested algorithm is not supported.
    UnsupportedAlgorithm,

    /// A problem occurred while communicating with the KMIP server.
    Kmip(String),
}

//--- Formatting

impl fmt::Display for GenerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlgorithm => {
                write!(f, "algorithm not supported")
            }
            Self::Kmip(err) => {
                write!(
                    f,
                    "a problem occurred while communicating with the KMIP server: {err}"
                )
            }
        }
    }
}

//--- impl Error

impl std::error::Error for GenerateError {}

//------------ DestroyError --------------------------------------------------

/// An error occurred while destroying a key using KMIP.
#[derive(Clone, Debug)]
pub enum DestroyError {
    /// A problem occurred while communicating with the KMIP server.
    Kmip(String),
}

//--- Formatting

impl fmt::Display for DestroyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kmip(err) => {
                write!(
                    f,
                    "a problem occurred while communicating with the KMIP server: {err}"
                )
            }
        }
    }
}

//--- Error

impl std::error::Error for DestroyError {}

//------------ KeyUrlError ---------------------------------------------------

/// An error occurred while parsing a KMIP key URL.
#[derive(Clone, Debug)]
pub struct KeyUrlParseError(pub String);

//--- Formatting

impl fmt::Display for KeyUrlParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid key URL: {}", self.0)
    }
}

//--- impl Error

impl std::error::Error for KeyUrlParseError {}

//--- Conversions

impl From<String> for KeyUrlParseError {
    fn from(err: String) -> Self {
        KeyUrlParseError(err)
    }
}

//------------ PublicKeyError ------------------------------------------------

/// An error occurred while retrieving a KMIP public key.
#[derive(Clone, Debug)]
pub enum PublicKeyError {
    /// The cryptographic algorithm of the KMIP key does not match the
    /// specified DNSSEC algorithm.
    AlgorithmMismatch {
        /// The DNSSEC algorithm that was expected.
        expected: SecurityAlgorithm,

        /// The type of key data received from the KMIP server.
        actual: String,
    },

    /// A problem occurred while communicating with the KMIP server.
    Kmip(String),
}

//--- Formatting

impl fmt::Display for PublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlgorithmMismatch { expected, actual } => {
                write!(
                    f,
                    "algorithm mismatch: expected {expected} but found {actual}"
                )
            }
            Self::Kmip(err) => {
                write!(
                    f,
                    "a problem occurred while communicating with the KMIP server: {err}"
                )
            }
        }
    }
}

//--- impl Error

impl std::error::Error for PublicKeyError {}

//--- Conversions

impl From<kmip_protocol::client::Error> for PublicKeyError {
    fn from(err: kmip_protocol::client::Error) -> Self {
        PublicKeyError::Kmip(err.to_string())
    }
}
