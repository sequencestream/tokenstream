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
