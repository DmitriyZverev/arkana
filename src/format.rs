use crate::envelope::{self, Envelope, text::Encoding};
use thiserror::Error;

pub enum OutputFormat {
    Yaml { encoding: Encoding },
    Binary,
}

pub enum InputFormat {
    Yaml,
    Binary,
}

#[derive(Debug, Error)]
pub enum SerializeError {
    #[error(transparent)]
    Yaml(serde_yaml::Error),
    #[error(transparent)]
    Binary(envelope::binary::SerializeError),
}

#[derive(Debug, Error)]
pub enum DeserializeError {
    #[error(transparent)]
    Yaml(envelope::yaml::DeserializeError),
    #[error(transparent)]
    Binary(envelope::binary::DeserializeError),
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
    }
}

pub(crate) fn deserialize(data: &[u8], format: InputFormat) -> Result<Envelope, DeserializeError> {
    match format {
        InputFormat::Yaml => envelope::yaml::deserialize(data).map_err(DeserializeError::Yaml),
        InputFormat::Binary => {
            envelope::binary::deserialize(data).map_err(DeserializeError::Binary)
        }
    }
}
