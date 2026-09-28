//! Gateway-credential issuance and verification contract.
//!
//! These tests prove the external `<key-id>.<secret>` format and its length
//! boundaries, that the secret carries 256 bits of entropy, that only an
//! Argon2id hash is stored, and that the secret is displayed exactly once.

use std::collections::HashSet;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tokenstream::crypto::{Argon2GatewaySecretVerifier, GatewaySecretError, GatewaySecretVerifier};
use tokenstream::domain::{
    CredentialFormatError, GATEWAY_KEY_ID_LENGTH, GATEWAY_SECRET_BYTES, GATEWAY_SECRET_LENGTH,
    GatewayCredential, MAX_GATEWAY_CREDENTIAL_LEN, PasswordHash, SecretString,
};

/// Matches the default Argon2id parameters also used by startup configuration.
const ARGON2ID_PREFIX: &str = "$argon2id$v=19$m=19456,t=2,p=1$";

fn verifier() -> Argon2GatewaySecretVerifier {
    Argon2GatewaySecretVerifier::new()
}

fn issue() -> (GatewayCredential, PasswordHash) {
    verifier().issue().expect("issuing a credential succeeds")
}

fn is_credential_alphabet(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[test]
fn issued_credentials_carry_256_bits_in_the_documented_format() {
    let (credential, _) = issue();
    let key_id = credential.key_id().as_str();
    let secret = credential.secret().expose();

    assert_eq!(GATEWAY_SECRET_BYTES * 8, 256);
    assert_eq!(key_id.len(), GATEWAY_KEY_ID_LENGTH);
    assert_eq!(secret.len(), GATEWAY_SECRET_LENGTH);
    assert!(is_credential_alphabet(key_id));
    assert!(is_credential_alphabet(secret));
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(secret)
            .expect("secret is base64")
            .len(),
        GATEWAY_SECRET_BYTES
    );
    assert_eq!(
        credential.render(),
        format!("{key_id}.{secret}"),
        "render must join the identifier and secret with a separator"
    );
}

#[test]
fn the_rendered_credential_round_trips_through_the_parser() {
    let (credential, _) = issue();
    let parsed = GatewayCredential::parse(&credential.render()).expect("issued credential parses");

    assert_eq!(parsed.key_id().as_str(), credential.key_id().as_str());
    assert_eq!(parsed.secret().expose(), credential.secret().expose());
}

#[test]
fn every_issuance_yields_fresh_random_material() {
    let mut rendered = HashSet::new();

    for _ in 0..8 {
        let (credential, _) = issue();
        assert!(
            rendered.insert(credential.render()),
            "credentials must not repeat"
        );
    }
}

#[test]
fn only_the_matching_secret_verifies_against_a_stored_hash() {
    let verifier = verifier();
    let (credential, hash) = issue();
    let other = issue();

    assert_eq!(
        verifier.verify(credential.secret(), &hash),
        Ok(true),
        "the issued secret must verify"
    );
    assert_eq!(
        verifier.verify(&SecretString::new("not-the-issued-secret"), &hash),
        Ok(false),
        "an unrelated secret must not verify"
    );
    assert_eq!(
        verifier.verify(other.0.secret(), &hash),
        Ok(false),
        "another credential's secret must not verify"
    );
}

#[test]
fn a_secret_verifies_against_its_own_hash_only() {
    let verifier = verifier();
    let (first, first_hash) = issue();
    let (second, second_hash) = issue();

    assert_eq!(verifier.verify(first.secret(), &first_hash), Ok(true));
    assert_eq!(verifier.verify(second.secret(), &second_hash), Ok(true));
    assert_ne!(first_hash.expose(), second_hash.expose());
}

#[test]
fn the_stored_hash_is_argon2id_and_never_contains_the_secret() {
    let (credential, hash) = issue();
    let secret = credential.secret().expose();

    assert!(
        hash.expose().starts_with(ARGON2ID_PREFIX),
        "the stored hash must be a default-cost Argon2id password hash"
    );
    assert!(
        !hash.expose().contains(secret),
        "the stored hash must not embed the secret"
    );
    for rendered in [
        format!("{credential:?}"),
        format!("{hash:?}"),
        hash.expose().to_owned(),
    ] {
        assert!(!rendered.contains(secret), "rendering leaked the secret");
    }
}

#[test]
fn a_malformed_or_foreign_hash_fails_closed() {
    let verifier = verifier();
    let secret = issue().0.secret().clone();

    for malformed in [
        "",
        "not-a-password-hash",
        "$argon2id$v=19$m=19456,t=2,p=1$",
        "$argon2id$v=19$notparams$c2FsdA$aGFzaA",
    ] {
        let hash = PasswordHash::new(malformed);
        assert_eq!(
            verifier.verify(&secret, &hash),
            Err(GatewaySecretError::InvalidHash),
            "expected a closed failure for {malformed:?}"
        );
    }
}

#[test]
fn the_parser_accepts_the_boundaries_and_rejects_everything_else() {
    let (credential, _) = issue();
    let key_id = credential.key_id().as_str();
    let secret = credential.secret().expose();
    let long_secret = "a".repeat(GATEWAY_SECRET_LENGTH + 1);

    assert!(GatewayCredential::parse(&credential.render()).is_ok());

    let rejections = [
        (String::new(), CredentialFormatError::Empty),
        (
            "no-separator-at-all".to_owned(),
            CredentialFormatError::MissingSeparator,
        ),
        (format!(".{secret}"), CredentialFormatError::EmptyComponent),
        (format!("{key_id}."), CredentialFormatError::EmptyComponent),
        (
            format!("{}.{secret}", "a".repeat(MAX_GATEWAY_CREDENTIAL_LEN)),
            CredentialFormatError::TooLong,
        ),
        (
            format!("{}.{long_secret}", "a".repeat(129)),
            CredentialFormatError::TooLong,
        ),
        (
            format!("{key_id}.{}", "a".repeat(42)),
            CredentialFormatError::InvalidSecret,
        ),
        (
            format!("{key_id}=.{secret}"),
            CredentialFormatError::InvalidKeyId,
        ),
        (
            format!("{key_id}.{secret}="),
            CredentialFormatError::InvalidSecret,
        ),
        (
            format!("{key_id}.{secret}.extra"),
            CredentialFormatError::InvalidSecret,
        ),
    ];

    for (candidate, expected) in rejections {
        assert_eq!(
            GatewayCredential::parse(&candidate).err(),
            Some(expected),
            "expected {expected:?} for {candidate:?}"
        );
    }
}

#[test]
fn credential_failures_never_render_secret_material() {
    let secret = "s".repeat(GATEWAY_SECRET_LENGTH);
    let malformed = format!("key-id.{secret}.");

    let error = GatewayCredential::parse(&malformed).expect_err("trailing separator is rejected");
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(
            !rendered.contains(&secret),
            "format error leaked the secret"
        );
    }

    let hash = PasswordHash::new("not-a-hash");
    let error = verifier()
        .verify(&SecretString::new(secret), &hash)
        .expect_err("malformed hash fails closed");
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(
            !rendered.contains("not-a-hash"),
            "hash error leaked the hash"
        );
    }
}
