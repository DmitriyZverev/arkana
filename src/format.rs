use crate::envelope::{self, Envelope, text::Encoding};
use thiserror::Error;

pub enum OutputFormat {
    Yaml { encoding: Encoding },
    Binary,
    Qr,
}

pub enum InputFormat {
    Yaml,
    Binary,
    Qr,
}

#[derive(Debug, Error)]
pub enum SerializeError {
    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),
    #[error(transparent)]
    Binary(#[from] envelope::binary::SerializeError),
    #[error(transparent)]
    Qr(#[from] envelope::qr::SerializeError),
}

#[derive(Debug, Error)]
pub enum DeserializeError {
    #[error(transparent)]
    Yaml(#[from] envelope::yaml::DeserializeError),
    #[error(transparent)]
    Binary(#[from] envelope::binary::DeserializeError),
    #[error(transparent)]
    Qr(#[from] envelope::qr::DeserializeError),
}

pub(crate) fn serialize(
    envelope: Envelope,
    format: OutputFormat,
) -> Result<Vec<u8>, SerializeError> {
    match format {
        OutputFormat::Yaml { encoding } => {
            envelope::yaml::serialize(envelope, encoding).map_err(SerializeError::Yaml)
        }
        OutputFormat::Binary => {
            envelope::binary::serialize(&envelope).map_err(SerializeError::Binary)
        }
        OutputFormat::Qr => envelope::qr::serialize(&envelope).map_err(SerializeError::Qr),
    }
}

pub(crate) fn deserialize(data: &[u8], format: InputFormat) -> Result<Envelope, DeserializeError> {
    match format {
        InputFormat::Yaml => envelope::yaml::deserialize(data).map_err(DeserializeError::Yaml),
        InputFormat::Binary => {
            envelope::binary::deserialize(data).map_err(DeserializeError::Binary)
        }
        InputFormat::Qr => envelope::qr::deserialize(data).map_err(DeserializeError::Qr),
    }
}
