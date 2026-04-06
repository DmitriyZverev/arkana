#[cfg(not(feature = "deterministic"))]
use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::{Algorithm, Params, Version};
#[cfg(not(feature = "deterministic"))]
use chacha20poly1305::AeadCore;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

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
        let num = match value {
            Version::V0x10 => 0x10u32,
            Version::V0x13 => 0x13u32,
        };
        serializer.serialize_u32(num)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Version, D::Error>
    where
        D: Deserializer<'de>,
    {
        let num = u32::deserialize(deserializer)?;
        match num {
            0x10 => Ok(Version::V0x10),
            0x13 => Ok(Version::V0x13),
            _ => Err(D::Error::custom("unsupported Argon2 version")),
        }
    }
}

#[derive(Error, Debug)]
pub enum EncryptError {
    #[error("Failed to generate random salt")]
    #[cfg(not(feature = "deterministic"))]
    SaltGeneration,
    #[error("Key derivation failed")]
    KeyDerivation,
    #[error("Encryption failed")]
    Encryption,
}

#[derive(Error, Debug)]
pub enum DecryptError {
    #[error("Key derivation failed")]
    KeyDerivation,
    #[error("Decryption failed")]
    Decryption,
}

#[derive(Default)]
pub struct EncryptParams {
    pub data: Vec<u8>,
    pub password: Zeroizing<Vec<u8>>,
    pub kdf: Kdf,
    pub cipher: Cipher,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Cipher {
    #[default]
    ChaCha20Poly1305,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Argon2 {
    #[serde(with = "algorithm_serde")]
    pub algorithm: Algorithm,
    #[serde(with = "version_serde")]
    pub version: Version,
    pub memory: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Argon2 {
    pub const DEFAULT_ALGORITHM: Algorithm = Algorithm::Argon2id;
    pub const DEFAULT_VERSION: Version = Version::V0x13;
    pub const DEFAULT_MEMORY: u32 = 128 * 1024;
    pub const DEFAULT_ITERATIONS: u32 = 4;
    pub const DEFAULT_PARALLELISM: u32 = 4;
}

impl Default for Argon2 {
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

impl Argon2 {
    fn derive_key(
        &self,
        salt: &[u8],
        password: &[u8],
    ) -> Result<Zeroizing<[u8; KEY_LEN]>, argon2::Error> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        argon2::Argon2::new(
            self.algorithm,
            self.version,
            Params::new(
                self.memory,
                self.iterations,
                self.parallelism,
                Some(KEY_LEN),
            )?,
        )
        .hash_password_into(password, salt, key.as_mut())?;
        Ok(key)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Kdf {
    Argon2(Argon2),
}

impl Default for Kdf {
    fn default() -> Self {
        Self::Argon2(Argon2::default())
    }
}

#[derive(Deserialize, Serialize)]
pub struct KdfSection {
    #[serde(flatten)]
    pub r#type: Kdf,
    #[serde(with = "base64_serde")]
    pub salt: [u8; SALT_LEN],
}

#[derive(Deserialize, Serialize)]
pub struct CipherSection {
    #[serde(flatten)]
    pub r#type: Cipher,
    #[serde(with = "base64_serde")]
    pub nonce: [u8; NONCE_LEN],
    #[serde(with = "base64_serde")]
    pub tag: [u8; TAG_LEN],
    #[serde(with = "base64_serde")]
    pub ciphertext: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
pub struct Envelope {
    pub kdf: KdfSection,
    pub cipher: CipherSection,
}

const SALT_LEN: usize = 32;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

#[cfg(feature = "deterministic")]
fn generate_salt() -> Result<[u8; SALT_LEN], EncryptError> {
    Ok([0x1B; SALT_LEN])
}

#[cfg(not(feature = "deterministic"))]
fn generate_salt() -> Result<[u8; SALT_LEN], EncryptError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| EncryptError::SaltGeneration)?;
    Ok(salt)
}

#[cfg(feature = "deterministic")]
fn generate_nonce() -> [u8; NONCE_LEN] {
    [0x0A; NONCE_LEN]
}

#[cfg(not(feature = "deterministic"))]
fn generate_nonce() -> [u8; NONCE_LEN] {
    ChaCha20Poly1305::generate_nonce(OsRng).into()
}

pub fn encrypt(encrypt_params: EncryptParams) -> Result<Envelope, EncryptError> {
    let salt = generate_salt()?;
    let key = match &encrypt_params.kdf {
        Kdf::Argon2(argon2) => argon2
            .derive_key(&salt, &encrypt_params.password)
            .map_err(|_| EncryptError::KeyDerivation)?,
    };

    let (nonce, ciphertext, tag) = match &encrypt_params.cipher {
        Cipher::ChaCha20Poly1305 => {
            let nonce = generate_nonce();
            let mut buffer = encrypt_params.data;
            let tag = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
                .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", &mut buffer)
                .map_err(|_| EncryptError::Encryption)?;
            (nonce, buffer, tag.into())
        }
    };

    Ok(Envelope {
        cipher: CipherSection {
            r#type: encrypt_params.cipher,
            ciphertext,
            nonce,
            tag,
        },
        kdf: KdfSection {
            r#type: encrypt_params.kdf,
            salt,
        },
    })
}

pub fn decrypt(envelope: Envelope, password: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let key = match &envelope.kdf.r#type {
        Kdf::Argon2(argon2) => argon2
            .derive_key(&envelope.kdf.salt, password)
            .map_err(|_| DecryptError::KeyDerivation)?,
    };
    let mut buffer = envelope.cipher.ciphertext;
    ChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
        .decrypt_in_place_detached(
            Nonce::from_slice(&envelope.cipher.nonce),
            b"",
            &mut buffer,
            Tag::from_slice(&envelope.cipher.tag),
        )
        .map_err(|_| DecryptError::Decryption)?;

    Ok(buffer)
}
