//! AES-256-GCM sealing for upstream provider keys.
//!
//! Every stored value is a three-part envelope: a key-version token, the
//! URL-safe base64 nonce, and the URL-safe base64 authenticated ciphertext
//! (the GCM tag is appended to the ciphertext by the AEAD).

use std::fmt;

use std::sync::{Arc, RwLock};

use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::{Zeroize, Zeroizing};

use crate::domain::{SecretCiphertext, SecretString};

use super::{CipherError, SecretCipher};

/// Key-version marker recorded in every envelope.
///
/// It identifies which master-key generation sealed a value, so a later
/// rotation can still open ciphertexts produced by an earlier key.
pub const KEY_VERSION: u8 = 1;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Authenticated cipher keyed by the configured 32-byte master key.
pub struct AesGcmCipher {
    key: Zeroizing<[u8; 32]>,
    key_version: u8,
}

impl AesGcmCipher {
    /// Builds a cipher over a 32-byte master key using the current key version.
    pub fn new(master_key: &[u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(*master_key),
            key_version: KEY_VERSION,
        }
    }

    fn cipher(&self) -> Result<Aes256Gcm, CipherError> {
        Aes256Gcm::new_from_slice(self.key.as_slice()).map_err(|_| CipherError::InvalidKey)
    }
}

impl SecretCipher for AesGcmCipher {
    fn encrypt(&self, plaintext: &SecretString) -> Result<SecretCiphertext, CipherError> {
        let cipher = self.cipher()?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let sealed = cipher
            .encrypt(&nonce, plaintext.expose().as_bytes())
            .map_err(|_| CipherError::Encryption)?;
        let envelope = format!(
            "v{}.{}.{}",
            self.key_version,
            URL_SAFE_NO_PAD.encode(nonce.as_slice()),
            URL_SAFE_NO_PAD.encode(&sealed),
        );
        Ok(SecretCiphertext::new(envelope))
    }

    fn decrypt(&self, ciphertext: &SecretCiphertext) -> Result<SecretString, CipherError> {
        let envelope = Envelope::parse(ciphertext.expose())?;
        if envelope.key_version != self.key_version {
            return Err(CipherError::Decryption);
        }
        let cipher = self.cipher()?;
        let nonce = Nonce::from_slice(envelope.nonce.as_slice());
        let mut plaintext = cipher
            .decrypt(nonce, envelope.ciphertext.as_slice())
            .map_err(|_| CipherError::Decryption)?;
        let secret = std::str::from_utf8(&plaintext)
            .map(SecretString::new)
            .map_err(|_| CipherError::Decryption);
        plaintext.zeroize();
        secret
    }
}

/// A process-wide cipher whose key can be replaced after stored secrets are re-encrypted.
#[derive(Clone)]
pub struct SharedCipher {
    inner: Arc<RwLock<AesGcmCipher>>,
}

impl SharedCipher {
    /// Builds a shared cipher over a 32-byte master key.
    pub fn new(master_key: &[u8; 32]) -> Self {
        Self {
            inner: Arc::new(RwLock::new(AesGcmCipher::new(master_key))),
        }
    }

    /// Replaces the in-memory key. Stored ciphertexts must already use this key.
    pub fn install(&self, master_key: &[u8; 32]) {
        *self.inner.write().expect("cipher lock is not poisoned") = AesGcmCipher::new(master_key);
    }
}

impl SecretCipher for SharedCipher {
    fn encrypt(&self, plaintext: &SecretString) -> Result<SecretCiphertext, CipherError> {
        self.inner
            .read()
            .expect("cipher lock is not poisoned")
            .encrypt(plaintext)
    }

    fn decrypt(&self, ciphertext: &SecretCiphertext) -> Result<SecretString, CipherError> {
        self.inner
            .read()
            .expect("cipher lock is not poisoned")
            .decrypt(ciphertext)
    }

    fn install_master_key(&self, key: &[u8; 32]) {
        self.install(key);
    }
}

impl fmt::Debug for SharedCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedCipher")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for AesGcmCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AesGcmCipher")
            .field("key_version", &self.key_version)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

/// A decoded ciphertext envelope.
struct Envelope {
    key_version: u8,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl Envelope {
    /// Splits and decodes `<key-version>.<nonce>.<ciphertext>`.
    ///
    /// Every structural or encoding problem maps to [`CipherError::Decryption`]
    /// so no distinguishing detail escapes.
    fn parse(value: &str) -> Result<Self, CipherError> {
        let mut parts = value.split('.');
        let (Some(version), Some(nonce), Some(ciphertext), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(CipherError::Decryption);
        };

        let key_version = parse_key_version(version).ok_or(CipherError::Decryption)?;
        let nonce = URL_SAFE_NO_PAD
            .decode(nonce)
            .map_err(|_| CipherError::Decryption)?;
        if nonce.len() != NONCE_LEN {
            return Err(CipherError::Decryption);
        }
        let ciphertext = URL_SAFE_NO_PAD
            .decode(ciphertext)
            .map_err(|_| CipherError::Decryption)?;
        if ciphertext.len() < TAG_LEN {
            return Err(CipherError::Decryption);
        }

        Ok(Self {
            key_version,
            nonce,
            ciphertext,
        })
    }
}

/// Parses a `v<number>` key-version token, rejecting anything else.
fn parse_key_version(token: &str) -> Option<u8> {
    let digits = token.strip_prefix('v')?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{Envelope, NONCE_LEN, TAG_LEN};

    fn nonce_base64() -> String {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        URL_SAFE_NO_PAD.encode([0_u8; NONCE_LEN])
    }

    fn ciphertext_base64() -> String {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        URL_SAFE_NO_PAD.encode(vec![0_u8; TAG_LEN])
    }

    #[test]
    fn accepts_a_well_formed_envelope() {
        let value = format!("v1.{}.{}", nonce_base64(), ciphertext_base64());
        let envelope = Envelope::parse(&value).expect("well-formed envelope");
        assert_eq!(envelope.key_version, 1);
        assert_eq!(envelope.nonce.len(), NONCE_LEN);
        assert_eq!(envelope.ciphertext.len(), TAG_LEN);
    }

    #[test]
    fn rejects_malformed_envelopes() {
        let nonce = nonce_base64();
        let ciphertext = ciphertext_base64();
        let short_nonce = {
            use base64::Engine as _;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            URL_SAFE_NO_PAD.encode([0_u8; NONCE_LEN - 1])
        };
        let short_ciphertext = {
            use base64::Engine as _;
            use base64::engine::general_purpose::URL_SAFE_NO_PAD;
            URL_SAFE_NO_PAD.encode([0_u8; TAG_LEN - 1])
        };

        let candidates = [
            String::new(),
            "not-an-envelope".to_owned(),
            format!("v1.{nonce}"),
            format!("v1.{nonce}.{ciphertext}.extra"),
            format!("1.{nonce}.{ciphertext}"),
            format!("vX.{nonce}.{ciphertext}"),
            format!("v256.{nonce}.{ciphertext}"),
            format!("v1.@@@.{ciphertext}"),
            format!("v1.{short_nonce}.{ciphertext}"),
            format!("v1.{nonce}.{short_ciphertext}"),
        ];

        for candidate in candidates {
            assert!(
                Envelope::parse(&candidate).is_err(),
                "expected rejection for {candidate:?}"
            );
        }
    }
}
