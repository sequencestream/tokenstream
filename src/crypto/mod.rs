//! Cryptographic handling of provider secrets.
//!
//! Upstream keys are encrypted at rest: a stored ciphertext is self-describing
//! and carries the random nonce, the key version, and the authenticated
//! ciphertext together, while the master key is supplied by configuration and
//! never stored in the database. Gateway credentials pair a non-secret key
//! identifier with a secret whose Argon2id hash is the only persisted form.

mod aes_gcm;
mod gateway_secret;
mod password_work;
pub use password_work::{PasswordWork, PasswordWorkError};

use std::error::Error;
use std::fmt;

pub use aes_gcm::{AesGcmCipher, KEY_VERSION};
pub use gateway_secret::Argon2GatewaySecretVerifier;

use crate::domain::{GatewayCredential, PasswordHash, SecretCiphertext, SecretString};

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

/// Issues and verifies provider-scoped gateway credentials.
///
/// A credential pairs a random, non-secret key identifier with a secret of at
/// least 256 bits of entropy. Implementations persist only the Argon2id hash of
/// the secret and verify it without a comparison path that depends on the
/// secret value.
pub trait GatewaySecretVerifier: Send + Sync {
    /// Generates a fresh credential and the hash that may be stored for it.
    ///
    /// The secret is returned only here; the stored hash cannot reconstruct it.
    fn issue(&self) -> Result<(GatewayCredential, PasswordHash), GatewaySecretError>;

    /// Reports whether `secret` matches `hash`.
    ///
    /// A mismatch is `Ok(false)`; an unusable stored hash is an error.
    fn verify(
        &self,
        secret: &SecretString,
        hash: &PasswordHash,
    ) -> Result<bool, GatewaySecretError>;
}

/// A gateway-credential failure that carries no secret, hash, or key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewaySecretError {
    /// The random source could not produce credential material.
    Generation,
    /// Hashing a generated secret failed.
    Hashing,
    /// The stored hash is not a usable Argon2id password hash.
    InvalidHash,
}

impl fmt::Display for GatewaySecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Generation => "gateway credential generation failed",
            Self::Hashing => "gateway secret hashing failed",
            Self::InvalidHash => "stored gateway secret hash is invalid",
        };
        formatter.write_str(message)
    }
}

impl Error for GatewaySecretError {}
