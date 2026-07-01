use crate::crypto::{self, EncryptParams};
use crate::format::{self, InputFormat, OutputFormat};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EncryptError {
    #[error(transparent)]
    Crypto(#[from] crypto::EncryptError),
    #[error(transparent)]
    Serialize(#[from] format::SerializeError),
}

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error(transparent)]
    Deserialize(#[from] format::DeserializeError),
    #[error(transparent)]
    Crypto(#[from] crypto::DecryptError),
}

#[derive(Debug, Error)]
pub enum ConvertError {
    #[error(transparent)]
    Deserialize(#[from] format::DeserializeError),
    #[error(transparent)]
    Serialize(#[from] format::SerializeError),
}

pub fn encrypt(params: EncryptParams, format: OutputFormat) -> Result<Vec<u8>, EncryptError> {
    let envelope = crypto::encrypt(params)?;
    Ok(format::serialize(envelope, format)?)
}

pub fn decrypt(data: &[u8], format: InputFormat, password: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let envelope = format::deserialize(data, format)?;
    Ok(crypto::decrypt(envelope, password)?)
}

pub fn convert(data: &[u8], from: InputFormat, to: OutputFormat) -> Result<Vec<u8>, ConvertError> {
    let envelope = format::deserialize(data, from)?;
    Ok(format::serialize(envelope, to)?)
}
