use crate::envelope;
use thiserror::Error;

type Version = u8;
type ParamsLen = u32;

const MAGIC: &[u8; 6] = b"arcana";
const VERSION: Version = 1;
pub(crate) const MAGIC_LEN: usize = MAGIC.len();
pub(crate) const VERSION_LEN: usize = size_of::<Version>();
pub(crate) const PARAMS_LEN: usize = size_of::<ParamsLen>();
pub(crate) const HEADER_LEN: usize = MAGIC_LEN + VERSION_LEN + PARAMS_LEN;

#[derive(Debug, Error)]
pub enum SerializeError {
    #[error("CBOR serialization error: {0}")]
    Cbor(ciborium::ser::Error<std::io::Error>),
}

#[derive(Debug, Error)]
pub enum DeserializeError {
    #[error("Input too short: expected {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    #[error("Invalid format: not an arcana binary envelope")]
    InvalidMagic,

    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),

    #[error("Trailing bytes after params")]
    TrailingBytes,

    #[error("CBOR error: {0}")]
    Cbor(ciborium::de::Error<std::io::Error>),
}

pub fn serialize_header(envelope: &envelope::Envelope) -> Result<Vec<u8>, SerializeError> {
    let mut params_bytes = Vec::new();
    ciborium::into_writer(&envelope.params, &mut params_bytes).map_err(SerializeError::Cbor)?;
    let params_len = params_bytes.len() as ParamsLen;
    let mut out = Vec::with_capacity(HEADER_LEN + params_bytes.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&params_len.to_be_bytes());
    out.extend_from_slice(&params_bytes);
    Ok(out)
}

pub fn serialize(envelope: &envelope::Envelope) -> Result<Vec<u8>, SerializeError> {
    let mut out = serialize_header(envelope)?;
    out.extend_from_slice(&envelope.ciphertext);
    Ok(out)
}

pub fn deserialize(data: &[u8]) -> Result<envelope::Envelope, DeserializeError> {
    let (header, rest) =
        data.split_first_chunk::<HEADER_LEN>()
            .ok_or(DeserializeError::TooShort {
                expected: HEADER_LEN,
                actual: data.len(),
            })?;
    let [m0, m1, m2, m3, m4, m5, version, p0, p1, p2, p3] = header;
    if [*m0, *m1, *m2, *m3, *m4, *m5] != *MAGIC {
        return Err(DeserializeError::InvalidMagic);
    }
    if *version != VERSION {
        return Err(DeserializeError::UnsupportedVersion(*version));
    }
    let params_len = ParamsLen::from_be_bytes([*p0, *p1, *p2, *p3]) as usize;
    let (params_bytes, ciphertext) =
        rest.split_at_checked(params_len)
            .ok_or(DeserializeError::TooShort {
                expected: HEADER_LEN + params_len,
                actual: data.len(),
            })?;
    let mut cursor = std::io::Cursor::new(params_bytes);
    let params: envelope::EnvelopeParams =
        ciborium::from_reader(&mut cursor).map_err(DeserializeError::Cbor)?;
    if cursor.position() as usize != params_bytes.len() {
        return Err(DeserializeError::TrailingBytes);
    }
    Ok(envelope::Envelope {
        params,
        ciphertext: ciphertext.to_vec(),
    })
}
