use crate::envelope;
use crate::envelope::Argon2Params;
use serde::{Deserialize, Serialize};

mod base64_serde {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serializer};

    pub trait Base64Bytes: Sized {
        fn to_bytes(&self) -> &[u8];
        fn from_bytes(bytes: Vec<u8>) -> Result<Self, String>;
    }

    impl Base64Bytes for Vec<u8> {
        fn to_bytes(&self) -> &[u8] {
            self
        }

        fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
            Ok(bytes)
        }
    }

    impl<const N: usize> Base64Bytes for [u8; N] {
        fn to_bytes(&self) -> &[u8] {
            self
        }

        fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
            bytes
                .try_into()
                .map_err(|_| format!("expected {} bytes", N))
        }
    }

    pub fn serialize<S, T: Base64Bytes>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = STANDARD.encode(value.to_bytes());
        let wrapped = encoded
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        serializer.serialize_str(&wrapped)
    }

    pub fn deserialize<'de, D, T: Base64Bytes>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let cleaned: String = s.lines().collect();
        let bytes = STANDARD.decode(cleaned).map_err(serde::de::Error::custom)?;
        T::from_bytes(bytes).map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Cipher {
    #[serde(rename = "ChaCha20Poly1305")]
    ChaCha20Poly1305 {
        #[serde(with = "base64_serde")]
        nonce: [u8; envelope::Cipher::CHA_CHA20_NONCE_LEN],
        #[serde(with = "base64_serde")]
        tag: [u8; envelope::Cipher::POLY1305_TAG_LEN],
        #[serde(with = "base64_serde")]
        ciphertext: Vec<u8>,
    },
}

impl From<envelope::Cipher> for Cipher {
    fn from(cipher: envelope::Cipher) -> Self {
        match cipher {
            envelope::Cipher::ChaCha20Poly1305 {
                nonce,
                tag,
                ciphertext,
            } => Cipher::ChaCha20Poly1305 {
                nonce,
                tag,
                ciphertext,
            },
        }
    }
}

impl From<Cipher> for envelope::Cipher {
    fn from(cipher: Cipher) -> envelope::Cipher {
        match cipher {
            Cipher::ChaCha20Poly1305 {
                nonce,
                tag,
                ciphertext,
            } => envelope::Cipher::ChaCha20Poly1305 {
                nonce,
                tag,
                ciphertext,
            },
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Kdf {
    #[serde(rename = "argon2")]
    Argon2 {
        #[serde(flatten)]
        params: Argon2Params,
        #[serde(with = "base64_serde")]
        salt: [u8; envelope::Kdf::ARGON2_SALT_LEN],
    },
}

impl From<envelope::Kdf> for Kdf {
    fn from(kdf: envelope::Kdf) -> Self {
        match kdf {
            envelope::Kdf::Argon2 { params, salt } => Kdf::Argon2 { params, salt },
        }
    }
}

impl From<Kdf> for envelope::Kdf {
    fn from(kdf: Kdf) -> Self {
        match kdf {
            Kdf::Argon2 { params, salt } => envelope::Kdf::Argon2 { params, salt },
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct Envelope {
    pub kdf: Kdf,
    pub cipher: Cipher,
}

impl From<envelope::Envelope> for Envelope {
    fn from(envelope: envelope::Envelope) -> Self {
        Envelope {
            kdf: envelope.kdf.into(),
            cipher: envelope.cipher.into(),
        }
    }
}

impl From<Envelope> for envelope::Envelope {
    fn from(envelope: Envelope) -> Self {
        envelope::Envelope {
            kdf: envelope.kdf.into(),
            cipher: envelope.cipher.into(),
        }
    }
}
