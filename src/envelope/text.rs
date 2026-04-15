use crate::envelope;
use crate::envelope::Argon2Params;
use data_encoding::{BASE32, BASE64, HEXUPPER, HEXUPPER_PERMISSIVE};
use serde::{Deserialize, Serialize};

#[derive(thiserror::Error, Debug)]
pub enum DecodeError {
    #[error("Invalid length: expected {expected}, actual {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error(transparent)]
    Decode(data_encoding::DecodeError),
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Decoding error: {0}")]
    Decode(DecodeError),
}

fn encode_bytes(bytes: &[u8], encoding: &Encoding) -> String {
    let encoded = match encoding {
        Encoding::Base16 => HEXUPPER.encode(bytes),
        Encoding::Base32 => BASE32.encode(bytes),
        Encoding::Base64 => BASE64.encode(bytes),
    };
    encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).expect("Encoding is ASCII"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn decode_bytes(s: &str, encoding: &Encoding) -> Result<Vec<u8>, data_encoding::DecodeError> {
    let cleaned: String = s.lines().collect();
    match encoding {
        Encoding::Base16 => HEXUPPER_PERMISSIVE.decode(cleaned.as_bytes()),
        Encoding::Base32 => BASE32.decode(cleaned.as_bytes()),
        Encoding::Base64 => BASE64.decode(cleaned.as_bytes()),
    }
}

fn decode_fixed<const N: usize>(s: &str, encoding: &Encoding) -> Result<[u8; N], DecodeError> {
    let bytes = decode_bytes(s, encoding).map_err(DecodeError::Decode)?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| DecodeError::InvalidLength {
        expected: N,
        actual: len,
    })
}

#[derive(Serialize, Deserialize, Default, Copy, Clone)]
pub enum Encoding {
    #[serde(rename = "base16")]
    Base16,
    #[serde(rename = "base32")]
    Base32,
    #[default]
    #[serde(rename = "base64")]
    Base64,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Cipher {
    #[serde(rename = "ChaCha20Poly1305")]
    ChaCha20Poly1305 {
        nonce: String,
        tag: String,
        ciphertext: String,
    },
}

impl Cipher {
    fn encode(cipher: envelope::Cipher, encoding: &Encoding) -> Self {
        match cipher {
            envelope::Cipher::ChaCha20Poly1305 {
                nonce,
                tag,
                ciphertext,
            } => Cipher::ChaCha20Poly1305 {
                nonce: encode_bytes(&nonce, encoding),
                tag: encode_bytes(&tag, encoding),
                ciphertext: encode_bytes(&ciphertext, encoding),
            },
        }
    }
}

impl envelope::Cipher {
    fn decode(cipher: Cipher, encoding: &Encoding) -> Result<Self, Error> {
        Ok(match cipher {
            Cipher::ChaCha20Poly1305 {
                nonce,
                tag,
                ciphertext,
            } => envelope::Cipher::ChaCha20Poly1305 {
                nonce: decode_fixed(&nonce, encoding).map_err(Error::Decode)?,
                tag: decode_fixed(&tag, encoding).map_err(Error::Decode)?,
                ciphertext: decode_bytes(&ciphertext, encoding)
                    .map_err(|e| Error::Decode(DecodeError::Decode(e)))?,
            },
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Kdf {
    #[serde(rename = "argon2")]
    Argon2 {
        #[serde(flatten)]
        params: Argon2Params,
        salt: String,
    },
}

impl Kdf {
    fn encode(kdf: envelope::Kdf, encoding: &Encoding) -> Self {
        match kdf {
            envelope::Kdf::Argon2 { params, salt } => Kdf::Argon2 {
                params,
                salt: encode_bytes(&salt, encoding),
            },
        }
    }
}

impl envelope::Kdf {
    fn decode(kdf: Kdf, encoding: &Encoding) -> Result<Self, Error> {
        Ok(match kdf {
            Kdf::Argon2 { params, salt } => envelope::Kdf::Argon2 {
                params,
                salt: decode_fixed(&salt, encoding).map_err(Error::Decode)?,
            },
        })
    }
}

#[derive(Deserialize, Serialize)]
pub struct Envelope {
    pub encoding: Encoding,
    pub kdf: Kdf,
    pub cipher: Cipher,
}

impl Envelope {
    pub fn encode(envelope: envelope::Envelope, encoding: Encoding) -> Self {
        Envelope {
            encoding,
            kdf: Kdf::encode(envelope.kdf, &encoding),
            cipher: Cipher::encode(envelope.cipher, &encoding),
        }
    }
}

impl TryFrom<Envelope> for envelope::Envelope {
    type Error = Error;

    fn try_from(envelope: Envelope) -> Result<Self, Error> {
        Ok(envelope::Envelope {
            kdf: envelope::Kdf::decode(envelope.kdf, &envelope.encoding)?,
            cipher: envelope::Cipher::decode(envelope.cipher, &envelope.encoding)?,
        })
    }
}
