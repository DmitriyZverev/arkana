use crate::crypto::{self, EncryptParams};
use crate::format::{self, InputFormat, OutputFormat};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptError {
    #[error(transparent)]
    Crypto(crypto::EncryptError),
    #[error(transparent)]
    Serialize(format::SerializeError),
}

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error(transparent)]
    Deserialize(format::DeserializeError),
    #[error(transparent)]
    Crypto(crypto::DecryptError),
}

#[derive(Debug, Error)]
pub enum ConvertError {
    #[error(transparent)]
    Deserialize(format::DeserializeError),
    #[error(transparent)]
    Serialize(format::SerializeError),
}

pub fn encrypt(params: EncryptParams, format: OutputFormat) -> Result<Vec<u8>, EncryptError> {
    let envelope = crypto::encrypt(params).map_err(EncryptError::Crypto)?;
    format::serialize(envelope, format).map_err(EncryptError::Serialize)
}

pub fn decrypt(data: &[u8], format: InputFormat, password: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let envelope = format::deserialize(data, format).map_err(DecryptError::Deserialize)?;
    crypto::decrypt(envelope, password).map_err(DecryptError::Crypto)
}

pub fn convert(data: &[u8], from: InputFormat, to: OutputFormat) -> Result<Vec<u8>, ConvertError> {
    let envelope = format::deserialize(data, from).map_err(ConvertError::Deserialize)?;
    format::serialize(envelope, to).map_err(ConvertError::Serialize)
}
