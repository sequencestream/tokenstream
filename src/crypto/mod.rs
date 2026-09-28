//! Encryption of upstream provider secrets at rest.
//!
//! A stored secret is self-describing: the ciphertext envelope carries the
//! random nonce, the key version, and the authenticated ciphertext together.
//! The master key is supplied by configuration and is never stored in the
//! database.

mod aes_gcm;

use std::error::Error;
use std::fmt;

pub use aes_gcm::{AesGcmCipher, KEY_VERSION};

use crate::domain::{SecretCiphertext, SecretString};

/// Encrypts and decrypts provider secrets that are stored at rest.
pub trait SecretCipher: Send + Sync {
    /// Seals `plaintext` into a self-describing ciphertext envelope.
    fn encrypt(&self, plaintext: &SecretString) -> Result<SecretCiphertext, CipherError>;

    /// Opens a ciphertext envelope previously produced by [`SecretCipher::encrypt`].
    fn decrypt(&self, ciphertext: &SecretCiphertext) -> Result<SecretString, CipherError>;
}

/// A cipher failure that carries no plaintext, key material, or ciphertext.
///
/// Every variant renders as a stable, non-sensitive description so a failure can
/// be logged or surfaced without its cause leaking through diagnostic output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherError {
    /// Sealing a plaintext value failed.
    Encryption,
    /// A value is malformed, uses an unsupported key version, or failed authentication.
    Decryption,
    /// The configured master key cannot initialize the cipher.
    InvalidKey,
}

impl fmt::Display for CipherError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Encryption => "secret encryption failed",
            Self::Decryption => "secret decryption failed",
            Self::InvalidKey => "master key is invalid",
        };
        formatter.write_str(message)
    }
}

impl Error for CipherError {}
