//! Upstream-secret sealing contract for the AES-256-GCM cipher.
//!
//! These tests prove round trips, per-sealing nonce freshness, rejection of
//! tampered or malformed envelopes, and that failures never leak plaintext,
//! ciphertext, or key material.

use std::collections::HashSet;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tokenstream::crypto::{AesGcmCipher, CipherError, KEY_VERSION, SecretCipher};
use tokenstream::domain::{SecretCiphertext, SecretString};

const NONCE_LEN: usize = 12;

fn cipher() -> AesGcmCipher {
    AesGcmCipher::new(&[0x11; 32])
}

fn seal(cipher: &AesGcmCipher, plaintext: &str) -> String {
    cipher
        .encrypt(&SecretString::new(plaintext))
        .expect("sealing succeeds")
        .expose()
        .to_owned()
}

fn parts(envelope: &str) -> Vec<&str> {
    envelope.split('.').collect()
}

/// Replaces one base64 character, always changing the decoded bits.
fn flip_char(segment: &str, index: usize) -> String {
    let mut bytes: Vec<u8> = segment.bytes().collect();
    bytes[index] = if bytes[index] == b'A' { b'B' } else { b'A' };
    String::from_utf8(bytes).expect("base64 alphabet is valid UTF-8")
}

fn expect_rejected(cipher: &AesGcmCipher, envelope: &str) {
    assert!(
        matches!(
            cipher.decrypt(&SecretCiphertext::new(envelope)),
            Err(CipherError::Decryption)
        ),
        "expected decryption failure"
    );
}

#[test]
fn round_trips_provider_keys_of_different_shapes() {
    let cipher = cipher();
    let long = "k".repeat(4096);
    let samples = ["", "sk-abc123", "多行\n密钥 🔑", long.as_str()];

    for plaintext in samples {
        let envelope = seal(&cipher, plaintext);
        let opened = cipher
            .decrypt(&SecretCiphertext::new(envelope))
            .expect("opening succeeds");
        assert_eq!(opened.expose(), plaintext);
    }
}

#[test]
fn envelope_records_the_current_key_version() {
    let envelope = seal(&cipher(), "sk-secret");
    let parts = parts(&envelope);

    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0], format!("v{KEY_VERSION}"));
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("nonce is base64")
            .len(),
        NONCE_LEN
    );
}

#[test]
fn every_sealing_uses_a_fresh_random_nonce() {
    let cipher = cipher();
    let mut nonces = HashSet::new();
    let mut envelopes = HashSet::new();

    for _ in 0..1024 {
        let envelope = seal(&cipher, "sk-identical-plaintext");
        let nonce = parts(&envelope)[1].to_owned();
        assert!(nonces.insert(nonce), "nonce was reused");
        assert!(envelopes.insert(envelope), "ciphertext was reused");
    }
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let cipher = cipher();
    let envelope = seal(&cipher, "sk-secret");
    let parts = parts(&envelope);
    let index = parts[2].len() / 2;
    let tampered = format!("{}.{}.{}", parts[0], parts[1], flip_char(parts[2], index));

    expect_rejected(&cipher, &tampered);
}

#[test]
fn tampered_nonce_is_rejected() {
    let cipher = cipher();
    let envelope = seal(&cipher, "sk-secret");
    let parts = parts(&envelope);
    let index = parts[1].len() / 2;
    let tampered = format!("{}.{}.{}", parts[0], flip_char(parts[1], index), parts[2]);

    expect_rejected(&cipher, &tampered);
}

#[test]
fn unsupported_key_version_is_rejected() {
    let cipher = cipher();
    let envelope = seal(&cipher, "sk-secret");
    let parts = parts(&envelope);
    let future = format!("v9.{}.{}", parts[1], parts[2]);

    expect_rejected(&cipher, &future);
}

#[test]
fn malformed_envelopes_are_rejected() {
    let cipher = cipher();
    let envelope = seal(&cipher, "sk-secret");
    let parts = parts(&envelope);
    let (version, nonce, ciphertext) = (parts[0], parts[1], parts[2]);
    let short_nonce = URL_SAFE_NO_PAD.encode([0_u8; NONCE_LEN - 1]);
    let short_ciphertext = URL_SAFE_NO_PAD.encode([0_u8; 8]);

    let candidates = [
        String::new(),
        "not-an-envelope".to_owned(),
        format!("{version}.{nonce}"),
        format!("{version}.{nonce}.{ciphertext}.extra"),
        format!("{}.{nonce}.{ciphertext}", version.trim_start_matches('v')),
        format!("vX.{nonce}.{ciphertext}"),
        format!("{version}.@@@.{ciphertext}"),
        format!("{version}.{short_nonce}.{ciphertext}"),
        format!("{version}.{nonce}.{short_ciphertext}"),
    ];

    for candidate in candidates {
        expect_rejected(&cipher, &candidate);
    }
}

#[test]
fn a_different_master_key_cannot_open_the_envelope() {
    let envelope = seal(&cipher(), "sk-secret");
    let other = AesGcmCipher::new(&[0x22; 32]);

    expect_rejected(&other, &envelope);
}

#[test]
fn decryption_failures_do_not_reveal_secrets() {
    let cipher = cipher();
    let plaintext = "sk-live-do-not-log-9f3a";
    let envelope = seal(&cipher, plaintext);
    let parts = parts(&envelope);
    let index = parts[2].len() / 2;
    let tampered = format!("{}.{}.{}", parts[0], parts[1], flip_char(parts[2], index));

    let error = cipher
        .decrypt(&SecretCiphertext::new(tampered))
        .expect_err("tampered ciphertext fails");

    assert_eq!(error, CipherError::Decryption);
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(!rendered.contains(plaintext), "error leaked plaintext");
        assert!(!rendered.contains(parts[1]), "error leaked the nonce");
        assert!(!rendered.contains(parts[2]), "error leaked the ciphertext");
    }
}

#[test]
fn cipher_debug_hides_the_master_key() {
    let rendered = format!("{:?}", cipher());

    assert!(rendered.contains("key_version"));
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains("171717"));
}

#[test]
fn sealed_envelopes_are_redacted_in_debug_output() {
    let envelope = seal(&cipher(), "sk-secret-value");
    let sealed = SecretCiphertext::new(envelope.clone());

    let rendered = format!("{sealed:?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(&envelope));
}
