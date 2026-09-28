//! Issuance and verification of provider-scoped gateway credentials.
//!
//! A credential is combined from a non-secret key identifier and a secret with
//! at least 256 bits of entropy. Only the Argon2id hash of the secret is
//! persisted; the secret itself is available solely from the credential
//! returned when it is issued. Verification derives the hash again and compares
//! the outputs without a comparison path that depends on the secret value.

use std::fmt;

use argon2::password_hash::{
    PasswordHash as PhcPasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::{Argon2, password_hash};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

use crate::domain::{
    GATEWAY_KEY_ID_BYTES, GATEWAY_SECRET_BYTES, GatewayCredential, GatewayKeyId, PasswordHash,
    SecretString,
};

use super::{GatewaySecretError, GatewaySecretVerifier};

/// Salt length for the Argon2id hash of a gateway secret.
const SALT_BYTES: usize = 16;

/// Argon2id-based issuer and verifier for gateway secrets.
///
/// The instance is stateless: it never retains a secret or hash beyond a single
/// call, so an issued secret exists only in the credential handed back to the
/// caller.
pub struct Argon2GatewaySecretVerifier {
    argon2: Argon2<'static>,
}

impl Argon2GatewaySecretVerifier {
    /// Builds a verifier with the default Argon2id cost parameters.
    pub fn new() -> Self {
        Self {
            argon2: Argon2::default(),
        }
    }
}

impl Default for Argon2GatewaySecretVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewaySecretVerifier for Argon2GatewaySecretVerifier {
    fn issue(&self) -> Result<(GatewayCredential, PasswordHash), GatewaySecretError> {
        let mut key_id_bytes = [0_u8; GATEWAY_KEY_ID_BYTES];
        let mut secret_bytes = Zeroizing::new([0_u8; GATEWAY_SECRET_BYTES]);
        let mut salt_bytes = [0_u8; SALT_BYTES];
        getrandom::getrandom(&mut key_id_bytes).map_err(|_| GatewaySecretError::Generation)?;
        getrandom::getrandom(&mut secret_bytes[..]).map_err(|_| GatewaySecretError::Generation)?;
        getrandom::getrandom(&mut salt_bytes).map_err(|_| GatewaySecretError::Generation)?;

        let key_id = GatewayKeyId::new(URL_SAFE_NO_PAD.encode(key_id_bytes))
            .map_err(|_| GatewaySecretError::Generation)?;
        let secret = SecretString::new(URL_SAFE_NO_PAD.encode(&secret_bytes[..]));

        let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| GatewaySecretError::Hashing)?;
        let hashed = self
            .argon2
            .hash_password(secret.expose().as_bytes(), &salt)
            .map_err(|_| GatewaySecretError::Hashing)?;

        Ok((
            GatewayCredential::new(key_id, secret),
            PasswordHash::new(hashed.to_string()),
        ))
    }

    fn verify(
        &self,
        secret: &SecretString,
        hash: &PasswordHash,
    ) -> Result<bool, GatewaySecretError> {
        let parsed =
            PhcPasswordHash::new(hash.expose()).map_err(|_| GatewaySecretError::InvalidHash)?;
        match self
            .argon2
            .verify_password(secret.expose().as_bytes(), &parsed)
        {
            Ok(()) => Ok(true),
            Err(password_hash::Error::Password) => Ok(false),
            Err(_) => Err(GatewaySecretError::InvalidHash),
        }
    }
}

impl fmt::Debug for Argon2GatewaySecretVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Argon2GatewaySecretVerifier")
            .finish_non_exhaustive()
    }
}
