//----------- GenerateError --------------------------------------------------

use core::fmt;

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
    /// The received key material is not in the expected form.
    InvalidKeyMaterial(String),

    /// A problem occurred while communicating with the KMIP server.
    Kmip(String),
}

//--- Formatting

impl fmt::Display for PublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyMaterial(err) => {
                write!(f, "invalid key material: {err}")
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

impl From<kmip_protocol::net::NetError> for PublicKeyError {
    fn from(err: kmip_protocol::net::NetError) -> Self {
        PublicKeyError::Kmip(err.to_string())
    }
}
