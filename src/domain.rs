use std::error::Error;
use std::fmt;
use std::time::Duration;

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

positive_value!(AccountId);
positive_value!(ProviderId);
positive_value!(ApiKeyId);
positive_value!(ModelAliasId);
positive_value!(RequestLogId);
positive_value!(AccountCursor);
positive_value!(ApiKeyCursor);
positive_value!(ModelAliasCursor);
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

/// An admission bound that cannot be used as a limit.
///
/// Zero is rejected rather than clamped or honoured: a limit of zero forbids all
/// traffic through that provider or credential, which is indistinguishable from
/// a configuration mistake and is never what an operator meant to express.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidAdmissionBound;

impl fmt::Display for InvalidAdmissionBound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an admission bound must be greater than zero")
    }
}

impl Error for InvalidAdmissionBound {}

/// The widest admission bound storage accepts.
///
/// A bound is a configuration value an operator types, not a capacity the
/// process could ever hold, so the ceiling exists to reject an obviously wrong
/// entry rather than to reserve for it.
pub const MAX_ADMISSION_BOUND: u32 = 1_000_000_000;

/// An optional admission bound for one provider or credential.
///
/// An absent bound is unbounded, and only the layers that are set apply. The
/// bound travels in the request snapshot so a later edit cannot reach a request
/// or connection that was already admitted under a different one.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdmissionBound(Option<u32>);

impl AdmissionBound {
    /// Builds a bound, refusing zero.
    pub fn new(value: Option<u32>) -> Result<Self, InvalidAdmissionBound> {
        match value {
            Some(0) => Err(InvalidAdmissionBound),
            value => Ok(Self(value)),
        }
    }

    /// The bound as a positive count, or `None` when the dimension is unbounded.
    pub fn get(self) -> Option<u32> {
        self.0
    }

    /// Whether this dimension carries no bound at all.
    pub fn is_unbounded(self) -> bool {
        self.0.is_none()
    }
}

impl Serialize for AdmissionBound {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Some(value) => serializer.serialize_u32(value),
            None => serializer.serialize_none(),
        }
    }
}

/// Validates one operator-supplied admission bound.
///
/// The zero case is refused rather than honoured: a limit of zero would forbid
/// every request through that provider or credential, which is an accident
/// rather than a policy. The ceiling rejects an entry no deployment could
/// actually reach, so a typo is caught at the edge instead of becoming a bound
/// that silently never fires.
pub fn validate_admission_bound(value: Option<i64>) -> Result<Option<u32>, InvalidAdmissionBound> {
    match value {
        None => Ok(None),
        Some(value) => {
            if value <= 0 || value > i64::from(MAX_ADMISSION_BOUND) {
                return Err(InvalidAdmissionBound);
            }
            Ok(Some(value as u32))
        }
    }
}

/// The widest consecutive-failure threshold storage accepts.
///
/// A threshold is a count of probe results, not a capacity the process could ever
/// hold, so the ceiling rejects an obviously wrong entry rather than reserving
/// for it. A high threshold is also self-defeating: it means an upstream has to
/// fail this many times in a row before anyone is told.
pub const MAX_HEALTH_THRESHOLD: u32 = 1_000;

/// The widest probe interval storage accepts.
///
/// The ceiling is a day. An operator who wants to know less often than daily has
/// disabled the information rather than delayed it.
pub const MAX_PROBE_INTERVAL_MS: u64 = 86_400_000;

/// A probe configuration that cannot be used.
///
/// Zero is refused for the same reason an admission bound of zero is: it would
/// isolate a provider immediately, or probe it without pause, rather than
/// describe when to do either.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidHealthSetting;

impl fmt::Display for InvalidHealthSetting {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the health configuration is invalid")
    }
}

impl Error for InvalidHealthSetting {}

/// The probe configuration a request may name on a provider.
///
/// A provider is probed only when it names a probe path, and the path is resolved
/// against the provider's own endpoint origin rather than being a second stored
/// URL. That is what makes a probe incapable of leaving the origin the operator
/// already trusted, and it is why a probe target can be validated without knowing
/// anything about the upstream's protocol.
///
/// Every value is validated rather than clamped: a silent clamp is a configuration
/// the operator did not write.
pub fn validate_provider_probe(
    probe_path: Option<&str>,
    failure_threshold: Option<i64>,
    probe_interval_ms: Option<i64>,
    probe_timeout_ms: Option<i64>,
) -> Result<Option<ProviderProbePath>, InvalidHealthSetting> {
    let Some(raw) = probe_path else {
        // A configuration carrying settings but no path describes a provider that
        // is never probed, and completing it with a default target would assert a
        // reachability contract the operator never agreed to.
        if failure_threshold.is_some() || probe_interval_ms.is_some() || probe_timeout_ms.is_some()
        {
            return Err(InvalidHealthSetting);
        }
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    // A probe path must be a rooted, dot-free, normalized path. Rejecting `..`
    // keeps a probe inside the origin it was aimed at rather than letting an
    // operator's own configuration walk the request somewhere they did not name.
    if !trimmed.starts_with('/')
        || trimmed.ends_with('/')
        || trimmed.chars().any(char::is_control)
        || trimmed
            .trim_start_matches('/')
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(InvalidHealthSetting);
    }
    let threshold = validate_probe_count(failure_threshold, MAX_HEALTH_THRESHOLD)?;
    let interval = validate_probe_millis(probe_interval_ms, MAX_PROBE_INTERVAL_MS)?;
    let timeout = validate_probe_millis(probe_timeout_ms, MAX_PROBE_INTERVAL_MS)?;
    // A probe with a path but an unbounded number, an interval, or a timeout is
    // a half-written configuration, and each missing piece would leave the probe
    // undecidable: an absent threshold isolates immediately, an absent interval
    // never probes.
    let (Some(threshold), Some(interval), Some(timeout)) = (threshold, interval, timeout) else {
        return Err(InvalidHealthSetting);
    };
    Ok(Some(ProviderProbePath {
        path: trimmed.to_owned(),
        interval: Duration::from_millis(interval),
        timeout: Duration::from_millis(timeout),
        failure_threshold: threshold,
    }))
}

/// The validated, origin-relative description of a provider's probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderProbePath {
    path: String,
    interval: Duration,
    timeout: Duration,
    failure_threshold: u32,
}

impl ProviderProbePath {
    /// The origin-relative path the probe is aimed at.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The interval between two probes of this provider.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// The deadline one probe attempt is bounded by.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Consecutive failures needed before the provider is isolated.
    pub fn failure_threshold(&self) -> u32 {
        self.failure_threshold
    }

    /// Resolves this probe against a provider endpoint, producing the target a
    /// probe issues against.
    ///
    /// The path is joined onto the endpoint's own base, so a probe is always
    /// aimed inside the origin the operator already trusts and can never walk
    /// somewhere they did not name. The endpoint's query and fragment are
    /// dropped: a probe asks whether the origin serves, not for a particular
    /// resource, and a stored query string would be one more secret-shaped value
    /// to persist per provider.
    pub fn resolve(&self, endpoint: &Url) -> Result<ProviderProbe, InvalidHealthSetting> {
        let base = endpoint.path().trim_end_matches('/');
        let target = format!(
            "{}{base}{}",
            endpoint.origin().ascii_serialization(),
            self.path
        );
        let target = Url::parse(&target).map_err(|_| InvalidHealthSetting)?;
        ProviderProbe::new(
            self.path.clone(),
            target,
            self.interval,
            self.timeout,
            self.failure_threshold,
        )
        .map_err(|_| InvalidHealthSetting)
    }
}

/// Validates one operator-supplied positive count within a ceiling.
fn validate_probe_count(
    value: Option<i64>,
    ceiling: u32,
) -> Result<Option<u32>, InvalidHealthSetting> {
    match value {
        None => Ok(None),
        Some(value) if value <= 0 || value > i64::from(ceiling) => Err(InvalidHealthSetting),
        Some(value) => Ok(Some(value as u32)),
    }
}

/// Validates one operator-supplied positive duration in milliseconds.
fn validate_probe_millis(
    value: Option<i64>,
    ceiling: u64,
) -> Result<Option<u64>, InvalidHealthSetting> {
    match value {
        None => Ok(None),
        Some(value) if value <= 0 || value > ceiling as i64 => Err(InvalidHealthSetting),
        Some(value) => Ok(Some(value as u64)),
    }
}

/// The admission bounds a provider carries.
///
/// A provider is bounded so one upstream cannot consume capacity that belongs to
/// another. Both dimensions are optional; a provider that carries neither is
/// bounded only by the process-wide gate.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ProviderAdmission {
    max_concurrent_requests: AdmissionBound,
    max_requests_per_second: AdmissionBound,
}

impl ProviderAdmission {
    /// Builds both bounds, refusing a zero in either.
    pub fn new(
        max_concurrent_requests: Option<u32>,
        max_requests_per_second: Option<u32>,
    ) -> Result<Self, InvalidAdmissionBound> {
        Ok(Self {
            max_concurrent_requests: AdmissionBound::new(max_concurrent_requests)?,
            max_requests_per_second: AdmissionBound::new(max_requests_per_second)?,
        })
    }

    pub fn max_concurrent_requests(self) -> AdmissionBound {
        self.max_concurrent_requests
    }

    pub fn max_requests_per_second(self) -> AdmissionBound {
        self.max_requests_per_second
    }

    /// Whether this provider carries no bound, and so needs no counter state.
    pub fn is_unbounded(self) -> bool {
        self.max_concurrent_requests.is_unbounded() && self.max_requests_per_second.is_unbounded()
    }
}

/// The admission bounds a credential carries.
///
/// The credential is the unit admission counts, because it is the unit that
/// already identifies a caller. A regular user may set and clear these on its
/// own credential.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct CredentialAdmission {
    max_concurrent_requests: AdmissionBound,
    max_requests_per_second: AdmissionBound,
    max_websockets: AdmissionBound,
}

impl CredentialAdmission {
    /// Builds all three bounds, refusing a zero in any of them.
    pub fn new(
        max_concurrent_requests: Option<u32>,
        max_requests_per_second: Option<u32>,
        max_websockets: Option<u32>,
    ) -> Result<Self, InvalidAdmissionBound> {
        Ok(Self {
            max_concurrent_requests: AdmissionBound::new(max_concurrent_requests)?,
            max_requests_per_second: AdmissionBound::new(max_requests_per_second)?,
            max_websockets: AdmissionBound::new(max_websockets)?,
        })
    }

    pub fn max_concurrent_requests(self) -> AdmissionBound {
        self.max_concurrent_requests
    }

    pub fn max_requests_per_second(self) -> AdmissionBound {
        self.max_requests_per_second
    }

    pub fn max_websockets(self) -> AdmissionBound {
        self.max_websockets
    }

    /// Whether this credential carries no bound, and so needs no counter state.
    pub fn is_unbounded(self) -> bool {
        self.max_concurrent_requests.is_unbounded()
            && self.max_requests_per_second.is_unbounded()
            && self.max_websockets.is_unbounded()
    }
}

/// The health state a provider is in, as observed by probes or set by an operator.
///
/// This is deliberately separate from the enabled state. An operator's decision and a probe's
/// observation are different facts: collapsing them would let a probe undo a human decision, and
/// would leave an operator unable to record that a provider is expected to be down. Only this
/// state may refuse traffic, and it may only refuse — it never reroutes a request.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderHealthState {
    /// Probes are succeeding, or none is configured. New requests are admitted.
    #[default]
    Healthy,
    /// Consecutive probe failures reached the threshold. New requests are refused.
    Isolated,
    /// An operator opened a maintenance window. Not probed; new requests are refused.
    Maintenance,
}

impl ProviderHealthState {
    /// Whether a new request must be refused before any upstream is contacted.
    ///
    /// An already-admitted exchange is unaffected: it owns a frozen snapshot and is never cut off.
    pub fn refuses_new_requests(self) -> bool {
        matches!(self, Self::Isolated | Self::Maintenance)
    }
}

/// The probe configuration a provider carries.
///
/// Health is opt-in per provider rather than a default, because a default probe asserts a
/// reachability contract the gateway does not have and cannot verify. A provider that carries no
/// probe target is never probed and therefore never isolated.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderProbe {
    path: String,
    target: Url,
    interval: Duration,
    timeout: Duration,
    failure_threshold: u32,
}

/// A probe configuration that cannot be used.
///
/// The same discipline as an admission bound: a value that would make probing meaningless is
/// refused at the edge rather than clamped, because a silent clamp is a configuration the operator
/// did not write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidProbeConfig;

impl fmt::Display for InvalidProbeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the probe configuration is invalid")
    }
}

impl Error for InvalidProbeConfig {}

impl ProviderProbe {
    /// Builds a probe configuration, refusing a zero threshold or a zero interval or timeout.
    pub fn new(
        path: String,
        target: Url,
        interval: Duration,
        timeout: Duration,
        failure_threshold: u32,
    ) -> Result<Self, InvalidProbeConfig> {
        if failure_threshold == 0 {
            return Err(InvalidProbeConfig);
        }
        if interval.is_zero() || timeout.is_zero() {
            return Err(InvalidProbeConfig);
        }
        Ok(Self {
            path,
            target,
            interval,
            timeout,
            failure_threshold,
        })
    }

    pub fn target(&self) -> &Url {
        &self.target
    }

    /// The origin-relative path the operator configured.
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Consecutive failures needed before the provider is isolated.
    pub fn failure_threshold(&self) -> u32 {
        self.failure_threshold
    }
}

/// The fixed set of control-plane roles.
///
/// This is deliberately a closed set rather than a table of permissions: the
/// resources an operator can reach are still only accounts, credentials,
/// providers, and process settings. Adding a role is an architectural change
/// with its own record, not a configuration edit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountRole {
    /// Manages accounts, credentials, providers, and process settings.
    Admin,
    /// Manages only its own credentials and model aliases.
    User,
}

impl AccountRole {
    /// Whether this role may reach the administrator-only surfaces.
    pub fn is_admin(self) -> bool {
        matches!(self, Self::Admin)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    Enabled,
    Disabled,
}

/// A principal that owns data-plane credentials and signs into the control plane.
#[derive(Clone, Debug)]
pub struct Account {
    id: AccountId,
    name: String,
    password_hash: PasswordHash,
    role: AccountRole,
    status: AccountStatus,
    is_bootstrap: bool,
    created_at: DateTime<Utc>,
}

/// Longest accepted account or credential name, counted in Unicode scalar values.
pub const MAX_ACCOUNT_NAME_LEN: usize = 128;

impl Account {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: AccountId,
        name: String,
        password_hash: PasswordHash,
        role: AccountRole,
        status: AccountStatus,
        is_bootstrap: bool,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            name,
            password_hash,
            role,
            status,
            is_bootstrap,
            created_at,
        }
    }

    pub fn id(&self) -> AccountId {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn password_hash(&self) -> &PasswordHash {
        &self.password_hash
    }

    pub fn role(&self) -> AccountRole {
        self.role
    }

    pub fn status(&self) -> AccountStatus {
        self.status
    }

    /// Whether this is the one account that can never be disabled or demoted.
    pub fn is_bootstrap(&self) -> bool {
        self.is_bootstrap
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyStatus {
    Enabled,
    Disabled,
}

/// A data-plane credential: it belongs to an account and names the providers
/// that account's traffic may reach.
///
/// The credential carries no protocol and no endpoint. Both belong to the
/// provider it resolves to, which is what makes one credential usable against
/// several upstreams while every request still resolves to exactly one.
#[derive(Clone, Debug)]
pub struct ApiKey {
    id: ApiKeyId,
    account_id: AccountId,
    name: String,
    key_id: GatewayKeyId,
    secret_hash: PasswordHash,
    status: ApiKeyStatus,
    default_provider_id: Option<ProviderId>,
    expires_at: Option<DateTime<Utc>>,
    admission: CredentialAdmission,
    created_at: DateTime<Utc>,
}

impl ApiKey {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: ApiKeyId,
        account_id: AccountId,
        name: String,
        key_id: GatewayKeyId,
        secret_hash: PasswordHash,
        status: ApiKeyStatus,
        default_provider_id: Option<ProviderId>,
        expires_at: Option<DateTime<Utc>>,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            account_id,
            name,
            key_id,
            secret_hash,
            status,
            default_provider_id,
            expires_at,
            admission: CredentialAdmission::default(),
            created_at,
        }
    }

    /// Rebuilds a stored credential with the admission bounds storage returned.
    pub fn with_admission(mut self, admission: CredentialAdmission) -> Self {
        self.admission = admission;
        self
    }

    pub fn id(&self) -> ApiKeyId {
        self.id
    }

    pub fn account_id(&self) -> AccountId {
        self.account_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn key_id(&self) -> &GatewayKeyId {
        &self.key_id
    }

    pub fn secret_hash(&self) -> &PasswordHash {
        &self.secret_hash
    }

    pub fn status(&self) -> ApiKeyStatus {
        self.status
    }

    /// The provider used when the request names none of the allowed providers.
    pub fn default_provider_id(&self) -> Option<ProviderId> {
        self.default_provider_id
    }

    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }

    /// The admission bounds this credential carries.
    pub fn admission(&self) -> CredentialAdmission {
        self.admission
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Whether `now` is at or past this credential's expiration.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }
}

/// One allowed provider of a credential, in preference order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApiKeyBinding {
    pub api_key_id: ApiKeyId,
    pub provider_id: ProviderId,
    pub position: i64,
}

#[derive(Clone, Debug)]
pub struct ApiKeyWithBindings {
    api_key: ApiKey,
    bindings: Vec<ApiKeyBinding>,
}

impl ApiKeyWithBindings {
    pub fn new(api_key: ApiKey, bindings: Vec<ApiKeyBinding>) -> Self {
        Self { api_key, bindings }
    }

    pub fn api_key(&self) -> &ApiKey {
        &self.api_key
    }

    /// The allowed providers in preference order.
    pub fn bindings(&self) -> &[ApiKeyBinding] {
        &self.bindings
    }

    /// Whether `provider_id` is one of the allowed providers.
    pub fn allows(&self, provider_id: ProviderId) -> bool {
        self.bindings
            .iter()
            .any(|binding| binding.provider_id == provider_id)
    }

    pub fn into_parts(self) -> (ApiKey, Vec<ApiKeyBinding>) {
        (self.api_key, self.bindings)
    }
}

/// Account-owned configuration for one caller-facing model name.
///
/// This value is deliberately absent from request snapshots. It is durable
/// control-plane state only and cannot affect a proxy exchange.
#[derive(Clone, Debug)]
pub struct ModelAlias {
    id: ModelAliasId,
    account_id: AccountId,
    name: String,
    created_at: DateTime<Utc>,
}

impl ModelAlias {
    pub fn new(
        id: ModelAliasId,
        account_id: AccountId,
        name: String,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            account_id,
            name,
            created_at,
        }
    }

    pub fn id(&self) -> ModelAliasId {
        self.id
    }

    pub fn account_id(&self) -> AccountId {
        self.account_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

/// One provider-specific target stored under a model alias.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelAliasTarget {
    provider_id: ProviderId,
    upstream_model: String,
    position: i64,
}

impl ModelAliasTarget {
    pub fn new(provider_id: ProviderId, upstream_model: String, position: i64) -> Self {
        Self {
            provider_id,
            upstream_model,
            position,
        }
    }

    pub fn provider_id(&self) -> ProviderId {
        self.provider_id
    }

    pub fn upstream_model(&self) -> &str {
        &self.upstream_model
    }

    pub fn position(&self) -> i64 {
        self.position
    }
}

#[derive(Clone, Debug)]
pub struct ModelAliasWithTargets {
    alias: ModelAlias,
    targets: Vec<ModelAliasTarget>,
}

impl ModelAliasWithTargets {
    pub fn new(alias: ModelAlias, targets: Vec<ModelAliasTarget>) -> Self {
        Self { alias, targets }
    }

    pub fn alias(&self) -> &ModelAlias {
        &self.alias
    }

    pub fn targets(&self) -> &[ModelAliasTarget] {
        &self.targets
    }

    pub fn into_parts(self) -> (ModelAlias, Vec<ModelAliasTarget>) {
        (self.alias, self.targets)
    }
}

#[derive(Clone, Debug)]
pub struct Provider {
    id: ProviderId,
    name: String,
    protocol_type: ProtocolType,
    endpoint: Url,
    upstream_api_key_ciphertext: SecretCiphertext,
    status: ProviderStatus,
    health: ProviderHealthState,
    admission: ProviderAdmission,
    probe: Option<ProviderProbe>,
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
        status: ProviderStatus,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            name,
            protocol_type,
            endpoint,
            upstream_api_key_ciphertext,
            status,
            health: ProviderHealthState::default(),
            admission: ProviderAdmission::default(),
            probe: None,
            created_at,
        }
    }

    /// Rebuilds a stored provider with the admission bounds storage returned.
    pub fn with_admission(mut self, admission: ProviderAdmission) -> Self {
        self.admission = admission;
        self
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

    pub fn status(&self) -> ProviderStatus {
        self.status
    }

    /// The observed health state of this provider.
    pub fn health(&self) -> ProviderHealthState {
        self.health
    }

    /// Rebuilds a stored provider with the health state storage returned.
    pub fn with_health(mut self, health: ProviderHealthState) -> Self {
        self.health = health;
        self
    }

    /// Rebuilds a stored provider with the probe configuration storage returned.
    pub fn with_probe(mut self, probe: Option<ProviderProbe>) -> Self {
        self.probe = probe;
        self
    }

    /// The probe configuration, absent when this provider is never probed.
    pub fn probe(&self) -> Option<&ProviderProbe> {
        self.probe.as_ref()
    }

    /// The admission bounds this provider carries.
    pub fn admission(&self) -> ProviderAdmission {
        self.admission
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }
}

/// The immutable configuration one request or connection owns for its lifetime.
///
/// Authentication freezes the account that presented the credential, the
/// credential itself, and the single provider that request resolved to. Later
/// edits to any of the three cannot reach work that was already admitted, and
/// the snapshot never carries a credential plaintext or secret hash.
#[derive(Debug)]
pub struct ProviderSnapshot {
    account_id: AccountId,
    api_key_id: ApiKeyId,
    id: ProviderId,
    protocol_type: ProtocolType,
    endpoint: Url,
    upstream_api_key: SecretString,
    provider_admission: ProviderAdmission,
    credential_admission: CredentialAdmission,
    health: ProviderHealthState,
}

impl ProviderSnapshot {
    pub fn new(
        account_id: AccountId,
        api_key_id: ApiKeyId,
        id: ProviderId,
        protocol_type: ProtocolType,
        endpoint: Url,
        upstream_api_key: SecretString,
    ) -> Self {
        Self {
            account_id,
            api_key_id,
            id,
            protocol_type,
            endpoint,
            upstream_api_key,
            provider_admission: ProviderAdmission::default(),
            credential_admission: CredentialAdmission::default(),
            health: ProviderHealthState::default(),
        }
    }

    /// Freezes the provider's health state alongside the rest of the snapshot.
    ///
    /// The state is read once, when the request is admitted, so a provider that
    /// becomes unhealthy afterwards cannot cut off a stream that is already
    /// running. Only new requests consult the current state.
    pub fn with_health(mut self, health: ProviderHealthState) -> Self {
        self.health = health;
        self
    }

    /// The health state frozen when this request was admitted.
    pub fn health(&self) -> ProviderHealthState {
        self.health
    }

    /// Attaches the admission bounds frozen from the credential and the
    /// selected provider.
    ///
    /// Both are resolved once, when the snapshot is created, so a later edit to
    /// either limit cannot reach a request or connection that is already
    /// admitted.
    pub fn with_admission(
        mut self,
        provider_admission: ProviderAdmission,
        credential_admission: CredentialAdmission,
    ) -> Self {
        self.provider_admission = provider_admission;
        self.credential_admission = credential_admission;
        self
    }

    /// The admission bounds of the provider this request resolved to.
    pub fn provider_admission(&self) -> ProviderAdmission {
        self.provider_admission
    }

    /// The admission bounds of the credential this request presented.
    pub fn credential_admission(&self) -> CredentialAdmission {
        self.credential_admission
    }

    /// The account that owns the credential this request presented.
    pub fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// The credential this request presented.
    pub fn api_key_id(&self) -> ApiKeyId {
        self.api_key_id
    }

    /// The one provider this request resolved to.
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
    account_id: AccountId,
    api_key_id: ApiKeyId,
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
        account_id: AccountId,
        api_key_id: ApiKeyId,
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
            account_id,
            api_key_id,
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

    /// The account whose credential presented this request.
    pub fn account_id(&self) -> AccountId {
        self.account_id
    }

    /// The credential this request presented.
    pub fn api_key_id(&self) -> ApiKeyId {
        self.api_key_id
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
    /// The observed health state. Kept beside the enabled status rather than
    /// merged into it: one is an operator's decision and the other is an
    /// observation, and an operator needs to see which is which.
    pub health: ProviderHealthState,
    pub has_upstream_api_key: bool,
    /// This provider's own admission bounds. Absent means unbounded.
    pub max_concurrent_requests: Option<u32>,
    pub max_requests_per_second: Option<u32>,
    /// The health probe. Every field is absent together, so an absent object
    /// means this provider is never probed.
    pub health_probe: Option<ProviderProbeView>,
    pub created_at: DateTime<Utc>,
}

/// The probe a provider is checked with, as the administration view shows it.
///
/// The target is reported as the path the operator configured, not as the URL it
/// resolves to, because the path is what they wrote and the origin is already
/// shown beside it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderProbeView {
    pub probe_path: String,
    pub failure_threshold: u32,
    pub probe_interval_ms: u64,
    pub probe_timeout_ms: u64,
}

impl From<&Provider> for ProviderAdminView {
    fn from(provider: &Provider) -> Self {
        Self {
            id: provider.id.get(),
            name: provider.name.clone(),
            protocol_type: provider.protocol_type,
            endpoint: provider.endpoint.to_string(),
            status: provider.status,
            health: provider.health(),
            has_upstream_api_key: true,
            max_concurrent_requests: provider.admission().max_concurrent_requests().get(),
            max_requests_per_second: provider.admission().max_requests_per_second().get(),
            health_probe: provider.probe().map(|probe| ProviderProbeView {
                probe_path: probe.path().to_owned(),
                failure_threshold: probe.failure_threshold(),
                probe_interval_ms: probe.interval().as_millis().min(u128::from(u64::MAX)) as u64,
                probe_timeout_ms: probe.timeout().as_millis().min(u128::from(u64::MAX)) as u64,
            }),
            created_at: provider.created_at,
        }
    }
}

/// The redacted administration representation of an account.
///
/// It carries no password hash of any form. A generated password appears once,
/// at creation, and only in the creation result.
#[derive(Clone, Serialize)]
pub struct AccountAdminView {
    pub id: i64,
    pub name: String,
    pub role: AccountRole,
    pub status: AccountStatus,
    pub is_bootstrap: bool,
    pub created_at: DateTime<Utc>,
}

impl From<&Account> for AccountAdminView {
    fn from(account: &Account) -> Self {
        Self {
            id: account.id.get(),
            name: account.name.clone(),
            role: account.role,
            status: account.status,
            is_bootstrap: account.is_bootstrap,
            created_at: account.created_at,
        }
    }
}

/// The redacted administration representation of a credential.
///
/// The key identifier is a non-secret lookup value, so it is safe to show. The
/// secret is not present in any field, and cannot be added to one by accident:
/// the stored record never holds it.
#[derive(Clone, Serialize)]
pub struct ApiKeyAdminView {
    pub id: i64,
    pub account_id: i64,
    pub name: String,
    pub key_id: String,
    pub status: ApiKeyStatus,
    pub expires_at: Option<DateTime<Utc>>,
    pub default_provider_id: Option<i64>,
    pub provider_ids: Vec<i64>,
    /// This credential's own admission bounds. Absent means unbounded.
    pub max_concurrent_requests: Option<u32>,
    pub max_requests_per_second: Option<u32>,
    pub max_websockets: Option<u32>,
    pub created_at: DateTime<Utc>,
}

impl ApiKeyAdminView {
    pub fn new(api_key: &ApiKey, bindings: &[ApiKeyBinding]) -> Self {
        let admission = api_key.admission();
        Self {
            id: api_key.id.get(),
            account_id: api_key.account_id.get(),
            name: api_key.name.clone(),
            key_id: api_key.key_id.as_str().to_owned(),
            status: api_key.status,
            expires_at: api_key.expires_at,
            default_provider_id: api_key.default_provider_id.map(ProviderId::get),
            provider_ids: bindings.iter().map(|b| b.provider_id.get()).collect(),
            max_concurrent_requests: admission.max_concurrent_requests().get(),
            max_requests_per_second: admission.max_requests_per_second().get(),
            max_websockets: admission.max_websockets().get(),
            created_at: api_key.created_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ModelAliasTargetView {
    pub provider_id: i64,
    pub upstream_model: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ModelAliasAdminView {
    pub id: i64,
    pub account_id: i64,
    pub name: String,
    pub targets: Vec<ModelAliasTargetView>,
    pub created_at: DateTime<Utc>,
}

impl From<&ModelAliasWithTargets> for ModelAliasAdminView {
    fn from(value: &ModelAliasWithTargets) -> Self {
        Self {
            id: value.alias.id.get(),
            account_id: value.alias.account_id.get(),
            name: value.alias.name.clone(),
            targets: value
                .targets
                .iter()
                .map(|target| ModelAliasTargetView {
                    provider_id: target.provider_id.get(),
                    upstream_model: target.upstream_model.clone(),
                })
                .collect(),
            created_at: value.alias.created_at,
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
            AccountId::try_from(1).expect("positive account ID"),
            ApiKeyId::try_from(1).expect("positive credential ID"),
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
            AccountId::try_from(2).expect("positive account ID"),
            ApiKeyId::try_from(3).expect("positive credential ID"),
            ProviderId::try_from(7).expect("positive ID"),
            ProtocolType::Anthropic,
            endpoint.clone(),
            SecretString::new("request-local-secret"),
        );
        endpoint.set_path("/changed");

        assert_eq!(snapshot.account_id().get(), 2);
        assert_eq!(snapshot.api_key_id().get(), 3);
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
            ProviderStatus::Enabled,
            Utc.with_ymd_and_hms(2026, 9, 28, 12, 0, 0)
                .single()
                .expect("valid timestamp"),
        );

        let json = serde_json::to_string(&ProviderAdminView::from(&provider))
            .expect("admin view is serializable");

        assert!(json.contains("\"has_upstream_api_key\":true"));
        assert!(!json.contains("gateway_key_id"));
        assert!(!json.contains("encrypted-upstream-key"));
        assert!(!json.contains("gateway-secret-hash"));
        assert!(!json.contains("ciphertext"));
        assert!(!json.contains("hash"));
    }
}
