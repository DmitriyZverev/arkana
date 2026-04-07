pub mod text;

use argon2::{Algorithm, Version};
use serde::{Deserialize, Serialize};

mod algorithm_serde {
    use argon2::Algorithm;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Algorithm, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(Algorithm::as_str(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Algorithm, D::Error>
    where
        D: Deserializer<'de>,
    {
        let algorithm = String::deserialize(deserializer)?;
        Algorithm::new(&algorithm)
            .map_err(|_| D::Error::unknown_variant(&algorithm, &["argon2i", "argon2d", "argon2id"]))
    }
}

mod version_serde {
    use argon2::Version;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Version, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(u32::from(*value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Version, D::Error>
    where
        D: Deserializer<'de>,
    {
        let version = u32::deserialize(deserializer)?;
        Version::try_from(version)
            .map_err(|_| D::Error::unknown_variant(&version.to_string(), &["16", "19"]))
    }
}

#[derive(Deserialize, Serialize)]
pub struct Argon2Params {
    #[serde(with = "algorithm_serde")]
    pub algorithm: Algorithm,
    #[serde(with = "version_serde")]
    pub version: Version,
    pub memory: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Argon2Params {
    pub const DEFAULT_ALGORITHM: Algorithm = Algorithm::Argon2id;
    pub const DEFAULT_VERSION: Version = Version::V0x13;
    pub const DEFAULT_MEMORY: u32 = 128 * 1024;
    pub const DEFAULT_ITERATIONS: u32 = 4;
    pub const DEFAULT_PARALLELISM: u32 = 4;
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            algorithm: Self::DEFAULT_ALGORITHM,
            version: Self::DEFAULT_VERSION,
            memory: Self::DEFAULT_MEMORY,
            iterations: Self::DEFAULT_ITERATIONS,
            parallelism: Self::DEFAULT_PARALLELISM,
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
        #[serde(with = "serde_bytes")]
        salt: [u8; Kdf::ARGON2_SALT_LEN],
    },
}

impl Kdf {
    pub const ARGON2_SALT_LEN: usize = 32;
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Cipher {
    #[serde(rename = "ChaCha20Poly1305")]
    ChaCha20Poly1305 {
        #[serde(with = "serde_bytes")]
        nonce: [u8; Cipher::CHA_CHA20_NONCE_LEN],
        #[serde(with = "serde_bytes")]
        tag: [u8; Cipher::POLY1305_TAG_LEN],
        #[serde(with = "serde_bytes")]
        ciphertext: Vec<u8>,
    },
}

impl Cipher {
    pub const CHA_CHA20_KEY_LEN: usize = 32;
    pub const CHA_CHA20_NONCE_LEN: usize = 12;
    pub const POLY1305_TAG_LEN: usize = 16;
}

#[derive(Deserialize, Serialize)]
pub struct Envelope {
    pub kdf: Kdf,
    pub cipher: Cipher,
}
