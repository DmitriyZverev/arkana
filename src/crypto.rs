use crate::envelope;
use crate::envelope::{Argon2Params, Envelope, EnvelopeParams};
use argon2::Params;
#[cfg(not(feature = "deterministic"))]
use argon2::password_hash::rand_core::{OsRng, RngCore};
#[cfg(not(feature = "deterministic"))]
use chacha20poly1305::AeadCore;
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, Tag};
use thiserror::Error;
use zeroize::Zeroizing;

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

pub enum KdfParams {
    Argon2 { params: Argon2Params },
}

impl KdfParams {
    pub fn with_salt(
        self,
        salt: [u8; envelope::KdfParams::ARGON2_SALT_LEN],
    ) -> envelope::KdfParams {
        match self {
            KdfParams::Argon2 { params } => envelope::KdfParams::Argon2 { params, salt },
        }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::Argon2 {
            params: Argon2Params::default(),
        }
    }
}

#[derive(Default)]
pub enum CipherParams {
    #[default]
    ChaCha20Poly1305,
}

#[derive(Default)]
pub struct EncryptParams {
    pub data: Vec<u8>,
    pub password: Zeroizing<Vec<u8>>,
    pub kdf: KdfParams,
    pub cipher: CipherParams,
}

impl Argon2Params {
    fn derive_key(
        &self,
        salt: &[u8],
        password: &[u8],
    ) -> Result<Zeroizing<[u8; envelope::CipherParams::CHA_CHA20_KEY_LEN]>, argon2::Error> {
        let mut key = Zeroizing::new([0u8; envelope::CipherParams::CHA_CHA20_KEY_LEN]);
        argon2::Argon2::new(
            self.algorithm,
            self.version,
            Params::new(
                self.memory,
                self.iterations,
                self.parallelism,
                Some(envelope::CipherParams::CHA_CHA20_KEY_LEN),
            )?,
        )
        .hash_password_into(password, salt, key.as_mut())?;
        Ok(key)
    }
}

#[cfg(feature = "deterministic")]
fn generate_salt() -> Result<[u8; envelope::KdfParams::ARGON2_SALT_LEN], EncryptError> {
    Ok([0x1B; envelope::KdfParams::ARGON2_SALT_LEN])
}

#[cfg(not(feature = "deterministic"))]
fn generate_salt() -> Result<[u8; envelope::KdfParams::ARGON2_SALT_LEN], EncryptError> {
    let mut salt = [0u8; envelope::KdfParams::ARGON2_SALT_LEN];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| EncryptError::SaltGeneration)?;
    Ok(salt)
}

#[cfg(feature = "deterministic")]
fn generate_nonce() -> [u8; envelope::CipherParams::CHA_CHA20_NONCE_LEN] {
    [0x0A; envelope::CipherParams::CHA_CHA20_NONCE_LEN]
}

#[cfg(not(feature = "deterministic"))]
fn generate_nonce() -> [u8; envelope::CipherParams::CHA_CHA20_NONCE_LEN] {
    ChaCha20Poly1305::generate_nonce(OsRng).into()
}

pub fn encrypt(encrypt_params: EncryptParams) -> Result<Envelope, EncryptError> {
    let salt = generate_salt()?;
    let key = match &encrypt_params.kdf {
        KdfParams::Argon2 { params: argon2 } => argon2
            .derive_key(&salt, &encrypt_params.password)
            .map_err(|_| EncryptError::KeyDerivation)?,
    };

    let (cipher_params, ciphertext) = match &encrypt_params.cipher {
        CipherParams::ChaCha20Poly1305 => {
            let nonce = generate_nonce();
            let mut buffer = encrypt_params.data;
            let tag = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
                .encrypt_in_place_detached(Nonce::from_slice(&nonce), b"", &mut buffer)
                .map_err(|_| EncryptError::Encryption)?;
            (
                envelope::CipherParams::ChaCha20Poly1305 {
                    nonce,
                    tag: tag.into(),
                },
                buffer,
            )
        }
    };

    Ok(Envelope {
        params: EnvelopeParams {
            kdf: encrypt_params.kdf.with_salt(salt),
            cipher: cipher_params,
        },
        ciphertext,
    })
}

pub fn decrypt(envelope: Envelope, password: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let key = match &envelope.params.kdf {
        envelope::KdfParams::Argon2 {
            params: argon2,
            salt,
        } => argon2
            .derive_key(salt, password)
            .map_err(|_| DecryptError::KeyDerivation)?,
    };
    match envelope.params.cipher {
        envelope::CipherParams::ChaCha20Poly1305 { nonce, tag } => {
            let mut buffer = envelope.ciphertext;
            ChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
                .decrypt_in_place_detached(
                    Nonce::from_slice(&nonce),
                    b"",
                    &mut buffer,
                    Tag::from_slice(&tag),
                )
                .map_err(|_| DecryptError::Decryption)?;

            Ok(buffer)
        }
    }
}
