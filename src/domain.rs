use std::error::Error;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::Serialize;
use url::Url;
use zeroize::Zeroize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PositiveValueError;

impl fmt::Display for PositiveValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("value must be a positive signed 64-bit integer")
    }
}

impl Error for PositiveValueError {}

macro_rules! positive_value {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(i64);

        impl $name {
            pub fn get(self) -> i64 {
                self.0
            }
        }

        impl TryFrom<i64> for $name {
            type Error = PositiveValueError;

            fn try_from(value: i64) -> Result<Self, Self::Error> {
                if value > 0 {
                    Ok(Self(value))
                } else {
                    Err(PositiveValueError)
                }
            }
        }
    };
}

positive_value!(ProviderId);
positive_value!(RequestLogId);
positive_value!(ProviderCursor);
positive_value!(RequestLogCursor);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmptyOpaqueValueError;

impl fmt::Display for EmptyOpaqueValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("opaque identifier must not be empty")
    }
}

impl Error for EmptyOpaqueValueError {}

macro_rules! opaque_identifier {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, PartialEq)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, EmptyOpaqueValueError> {
                let value = value.into();
                if value.is_empty() {
                    Err(EmptyOpaqueValueError)
                } else {
                    Ok(Self(value))
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

opaque_identifier!(RequestId);
opaque_identifier!(GatewayKeyId);

impl RequestId {
    /// Generates a fresh, opaque internal request identifier.
    ///
    /// The value is 128 random bits rendered as lowercase hexadecimal behind a
    /// short `req_` prefix. It is not secret, never serves as a database key,
    /// and is the only caller-visible identifier a local gateway error echoes.
    pub fn generate() -> Self {
        const RANDOM_BYTES: usize = 16;
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let mut random = [0u8; RANDOM_BYTES];
        getrandom::getrandom(&mut random).expect("the operating system random source is available");

        let mut value = String::with_capacity(4 + RANDOM_BYTES * 2);
        value.push_str("req_");
        for byte in random {
            value.push(HEX[usize::from(byte >> 4)] as char);
            value.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        Self(value)
    }
}

macro_rules! protected_string {
    ($name:ident) => {
        #[derive(Clone, Eq, PartialEq)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            pub fn expose(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }
    };
}

protected_string!(SecretString);
protected_string!(SecretCiphertext);
protected_string!(PasswordHash);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolType {
    OpenAi,
    Anthropic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Enabled,
    Disabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportType {
    Http,
    WebSocket,
}

#[derive(Clone, Debug)]
pub struct Provider {
    id: ProviderId,
    name: String,
    protocol_type: ProtocolType,
    endpoint: Url,
    upstream_api_key_ciphertext: SecretCiphertext,
    gateway_key_id: GatewayKeyId,
    gateway_api_key_hash: PasswordHash,
    status: ProviderStatus,
    created_at: DateTime<Utc>,
}

impl Provider {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: ProviderId,
        name: String,
        protocol_type: ProtocolType,
        endpoint: Url,
        upstream_api_key_ciphertext: SecretCiphertext,
        gateway_key_id: GatewayKeyId,
        gateway_api_key_hash: PasswordHash,
        status: ProviderStatus,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            name,
            protocol_type,
            endpoint,
            upstream_api_key_ciphertext,
            gateway_key_id,
            gateway_api_key_hash,
            status,
            created_at,
        }
    }

    pub fn id(&self) -> ProviderId {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn protocol_type(&self) -> ProtocolType {
        self.protocol_type
    }

    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    pub fn upstream_api_key_ciphertext(&self) -> &SecretCiphertext {
        &self.upstream_api_key_ciphertext
    }

    pub fn gateway_key_id(&self) -> &GatewayKeyId {
        &self.gateway_key_id
    }

    pub fn gateway_api_key_hash(&self) -> &PasswordHash {
        &self.gateway_api_key_hash
    }

    pub fn status(&self) -> ProviderStatus {
        self.status
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

#[derive(Debug)]
pub struct ProviderSnapshot {
    id: ProviderId,
    protocol_type: ProtocolType,
    endpoint: Url,
    upstream_api_key: SecretString,
}

impl ProviderSnapshot {
    pub fn new(
        id: ProviderId,
        protocol_type: ProtocolType,
        endpoint: Url,
        upstream_api_key: SecretString,
    ) -> Self {
        Self {
            id,
            protocol_type,
            endpoint,
            upstream_api_key,
        }
    }

    pub fn id(&self) -> ProviderId {
        self.id
    }

    pub fn protocol_type(&self) -> ProtocolType {
        self.protocol_type
    }

    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    pub fn upstream_api_key(&self) -> &SecretString {
        &self.upstream_api_key
    }
}

/// Separator between the key identifier and the secret in the external
/// credential representation.
pub const GATEWAY_CREDENTIAL_SEPARATOR: char = '.';

/// Random bytes in a generated gateway key identifier.
pub const GATEWAY_KEY_ID_BYTES: usize = 16;

/// Random bytes in a generated gateway secret: 256 bits of entropy.
pub const GATEWAY_SECRET_BYTES: usize = 32;

/// Encoded length of a generated key identifier in the credential format.
pub const GATEWAY_KEY_ID_LENGTH: usize = encoded_credential_length(GATEWAY_KEY_ID_BYTES);

/// Encoded length of a generated secret in the credential format.
pub const GATEWAY_SECRET_LENGTH: usize = encoded_credential_length(GATEWAY_SECRET_BYTES);

/// Longest external credential the parser will consider.
pub const MAX_GATEWAY_CREDENTIAL_LEN: usize = MAX_KEY_ID_LEN + 1 + MAX_SECRET_LEN;

const MIN_SECRET_LEN: usize = GATEWAY_SECRET_LENGTH;
const MAX_KEY_ID_LEN: usize = 128;
const MAX_SECRET_LEN: usize = 128;

/// Length of `bytes` once encoded as URL-safe base64 without padding.
const fn encoded_credential_length(bytes: usize) -> usize {
    bytes / 3 * 4
        + match bytes % 3 {
            0 => 0,
            1 => 2,
            _ => 3,
        }
}

/// Rejection reason for an external credential that is not a well-formed
/// `<key-id>.<secret>` pair. It never carries credential characters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialFormatError {
    /// The credential is empty.
    Empty,
    /// The credential or one of its components exceeds the accepted length.
    TooLong,
    /// The credential does not contain the key-id/secret separator.
    MissingSeparator,
    /// The key identifier or secret component is empty.
    EmptyComponent,
    /// The key identifier is not a valid non-secret lookup identifier.
    InvalidKeyId,
    /// The secret is shorter than 256 bits or uses characters outside the format.
    InvalidSecret,
}

impl fmt::Display for CredentialFormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "credential must not be empty",
            Self::TooLong => "credential exceeds the accepted length",
            Self::MissingSeparator => "credential must contain a key-id/secret separator",
            Self::EmptyComponent => "credential components must not be empty",
            Self::InvalidKeyId => "credential key identifier is malformed",
            Self::InvalidSecret => "credential secret is malformed or too short",
        };
        formatter.write_str(message)
    }
}

impl Error for CredentialFormatError {}

/// True when every byte is URL-safe base64 without padding, the credential alphabet.
fn is_credential_alphabet(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

#[derive(Debug)]
pub struct GatewayCredential {
    key_id: GatewayKeyId,
    secret: SecretString,
}

impl GatewayCredential {
    pub fn new(key_id: GatewayKeyId, secret: SecretString) -> Self {
        Self { key_id, secret }
    }

    pub fn key_id(&self) -> &GatewayKeyId {
        &self.key_id
    }

    pub fn secret(&self) -> &SecretString {
        &self.secret
    }

    /// Renders the external `<key-id>.<secret>` representation.
    ///
    /// The secret it contains is shown only at issuance or rotation; callers
    /// must not persist or log the rendered value.
    pub fn render(&self) -> String {
        let mut rendered = String::with_capacity(
            self.key_id.as_str().len()
                + GATEWAY_CREDENTIAL_SEPARATOR.len_utf8()
                + self.secret.expose().len(),
        );
        rendered.push_str(self.key_id.as_str());
        rendered.push(GATEWAY_CREDENTIAL_SEPARATOR);
        rendered.push_str(self.secret.expose());
        rendered
    }

    /// Parses and validates the external `<key-id>.<secret>` representation.
    ///
    /// The key identifier is a random, non-secret lookup value and the secret
    /// carries at least 256 bits of entropy. Inputs outside the accepted format
    /// or length bounds are rejected before any lookup.
    pub fn parse(raw: &str) -> Result<Self, CredentialFormatError> {
        if raw.is_empty() {
            return Err(CredentialFormatError::Empty);
        }
        if raw.len() > MAX_GATEWAY_CREDENTIAL_LEN {
            return Err(CredentialFormatError::TooLong);
        }

        let (key_id, secret) = raw
            .split_once(GATEWAY_CREDENTIAL_SEPARATOR)
            .ok_or(CredentialFormatError::MissingSeparator)?;
        if key_id.is_empty() || secret.is_empty() {
            return Err(CredentialFormatError::EmptyComponent);
        }
        if key_id.len() > MAX_KEY_ID_LEN || secret.len() > MAX_SECRET_LEN {
            return Err(CredentialFormatError::TooLong);
        }
        if !is_credential_alphabet(key_id) {
            return Err(CredentialFormatError::InvalidKeyId);
        }
        if secret.len() < MIN_SECRET_LEN || !is_credential_alphabet(secret) {
            return Err(CredentialFormatError::InvalidSecret);
        }

        let key_id = GatewayKeyId::new(key_id).map_err(|_| CredentialFormatError::InvalidKeyId)?;
        Ok(Self::new(key_id, SecretString::new(secret)))
    }
}

#[derive(Clone, Debug)]
pub struct RequestLog {
    id: RequestLogId,
    request_id: RequestId,
    provider_id: ProviderId,
    protocol_type: ProtocolType,
    transport_type: TransportType,
    path: String,
    status_code: Option<u16>,
    start_time: DateTime<Utc>,
    end_time: Option<DateTime<Utc>>,
    error_msg: Option<String>,
}

impl RequestLog {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: RequestLogId,
        request_id: RequestId,
        provider_id: ProviderId,
        protocol_type: ProtocolType,
        transport_type: TransportType,
        path: String,
        status_code: Option<u16>,
        start_time: DateTime<Utc>,
        end_time: Option<DateTime<Utc>>,
        error_msg: Option<String>,
    ) -> Self {
        Self {
            id,
            request_id,
            provider_id,
            protocol_type,
            transport_type,
            path,
            status_code,
            start_time,
            end_time,
            error_msg,
        }
    }

    pub fn id(&self) -> RequestLogId {
        self.id
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    pub fn provider_id(&self) -> ProviderId {
        self.provider_id
    }

    pub fn protocol_type(&self) -> ProtocolType {
        self.protocol_type
    }

    pub fn transport_type(&self) -> TransportType {
        self.transport_type
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn status_code(&self) -> Option<u16> {
        self.status_code
    }

    pub fn start_time(&self) -> DateTime<Utc> {
        self.start_time
    }

    pub fn end_time(&self) -> Option<DateTime<Utc>> {
        self.end_time
    }

    pub fn error_msg(&self) -> Option<&str> {
        self.error_msg.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderAdminView {
    pub id: i64,
    pub name: String,
    pub protocol_type: ProtocolType,
    pub endpoint: String,
    pub status: ProviderStatus,
    pub gateway_key_id: String,
    pub has_upstream_api_key: bool,
    pub created_at: DateTime<Utc>,
}

impl From<&Provider> for ProviderAdminView {
    fn from(provider: &Provider) -> Self {
        Self {
            id: provider.id.get(),
            name: provider.name.clone(),
            protocol_type: provider.protocol_type,
            endpoint: provider.endpoint.to_string(),
            status: provider.status,
            gateway_key_id: provider.gateway_key_id.as_str().to_owned(),
            has_upstream_api_key: true,
            created_at: provider.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    #[test]
    fn database_ids_and_cursors_accept_only_positive_values() {
        for value in [i64::MIN, -1, 0] {
            assert_eq!(ProviderId::try_from(value), Err(PositiveValueError));
            assert_eq!(RequestLogId::try_from(value), Err(PositiveValueError));
            assert_eq!(ProviderCursor::try_from(value), Err(PositiveValueError));
            assert_eq!(RequestLogCursor::try_from(value), Err(PositiveValueError));
        }

        assert_eq!(ProviderId::try_from(1).expect("positive ID").get(), 1);
        assert_eq!(
            RequestLogCursor::try_from(i64::MAX)
                .expect("positive cursor")
                .get(),
            i64::MAX
        );
    }

    #[test]
    fn request_identifier_is_opaque_and_independent_from_row_ids() {
        let request_id = RequestId::new("req_01JTEST").expect("non-empty request ID");
        let row_id = RequestLogId::try_from(42).expect("positive row ID");

        assert_eq!(request_id.as_str(), "req_01JTEST");
        assert_eq!(row_id.get(), 42);
        assert_eq!(RequestId::new(""), Err(EmptyOpaqueValueError));
    }

    #[test]
    fn generated_request_identifiers_are_opaque_and_distinct() {
        let generated: std::collections::BTreeSet<String> = (0..64)
            .map(|_| RequestId::generate().as_str().to_owned())
            .collect();

        assert_eq!(generated.len(), 64);
        for value in generated {
            assert!(value.starts_with("req_"), "{value}");
            assert_eq!(value.len(), 4 + 32, "{value}");
            assert!(
                value[4..]
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
                "{value}"
            );
        }
    }

    #[test]
    fn secrets_are_redacted_from_every_debug_container() {
        let plaintext = "upstream-super-secret";
        let secret = SecretString::new(plaintext);
        let ciphertext = SecretCiphertext::new("ciphertext-secret");
        let hash = PasswordHash::new("password-hash-secret");
        let credential = GatewayCredential::new(
            GatewayKeyId::new("key-id").expect("non-empty key ID"),
            secret.clone(),
        );
        let snapshot = ProviderSnapshot::new(
            ProviderId::try_from(1).expect("positive ID"),
            ProtocolType::OpenAi,
            Url::parse("https://api.example.com").expect("valid URL"),
            secret,
        );

        for rendered in [
            format!("{ciphertext:?}"),
            format!("{hash:?}"),
            format!("{credential:?}"),
            format!("{snapshot:?}"),
        ] {
            assert!(rendered.contains("[REDACTED]"));
            assert!(!rendered.contains(plaintext));
            assert!(!rendered.contains("ciphertext-secret"));
            assert!(!rendered.contains("password-hash-secret"));
        }
    }

    #[test]
    fn snapshot_owns_an_immutable_copy_of_request_configuration() {
        let mut endpoint = Url::parse("https://api.example.com/base").expect("valid URL");
        let snapshot = ProviderSnapshot::new(
            ProviderId::try_from(7).expect("positive ID"),
            ProtocolType::Anthropic,
            endpoint.clone(),
            SecretString::new("request-local-secret"),
        );
        endpoint.set_path("/changed");

        assert_eq!(snapshot.id().get(), 7);
        assert_eq!(snapshot.protocol_type(), ProtocolType::Anthropic);
        assert_eq!(snapshot.endpoint().path(), "/base");
        assert_eq!(snapshot.upstream_api_key().expose(), "request-local-secret");
    }

    #[test]
    fn administration_view_serializes_only_redacted_provider_fields() {
        let provider = Provider::new(
            ProviderId::try_from(9).expect("positive ID"),
            "primary".to_owned(),
            ProtocolType::OpenAi,
            Url::parse("https://api.example.com").expect("valid URL"),
            SecretCiphertext::new("encrypted-upstream-key"),
            GatewayKeyId::new("lookup-id").expect("non-empty key ID"),
            PasswordHash::new("gateway-secret-hash"),
            ProviderStatus::Enabled,
            Utc.with_ymd_and_hms(2026, 9, 28, 12, 0, 0)
                .single()
                .expect("valid timestamp"),
        );

        let json = serde_json::to_string(&ProviderAdminView::from(&provider))
            .expect("admin view is serializable");

        assert!(json.contains("\"gateway_key_id\":\"lookup-id\""));
        assert!(json.contains("\"has_upstream_api_key\":true"));
        assert!(!json.contains("encrypted-upstream-key"));
        assert!(!json.contains("gateway-secret-hash"));
        assert!(!json.contains("ciphertext"));
        assert!(!json.contains("hash"));
    }
}
