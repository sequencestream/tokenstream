//! Authenticated administration sessions and HTTP API.

pub mod assets;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordVerifier};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Incoming};
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, SET_COOKIE};
use hyper::{Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};

use crate::ControlPlaneService;
use crate::admin::assets::{AdminAssets, PAGE_CONTENT_SECURITY_POLICY};
use crate::crypto::{
    AesGcmCipher, Argon2GatewaySecretVerifier, GatewaySecretVerifier, PasswordWorkError,
    SecretCipher,
};
use crate::domain::{
    ProtocolType, ProviderAdminView, ProviderCursor, ProviderId, ProviderStatus, RequestLog,
    RequestLogCursor, SecretString, TransportType,
};
use crate::persistence::{
    Database, ProviderListRequest, ProviderRepository, RepositoryError, RequestLogQuery,
    RequestLogRepository,
};
use crate::providers::{
    CreateProviderRequest, ProviderService, ProviderServiceError, UpdateProviderRequest,
};
use crate::telemetry::{Metrics, ProxyFailureCategory};

const SESSION_COOKIE: &str = "tokenstream_admin";
const MAX_ADMIN_BODY_BYTES: usize = 16 * 1024;
const MAX_ACTIVE_SESSIONS: usize = 1_024;
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(15 * 60);

type ApiBody = Full<Bytes>;

#[derive(Clone)]
pub struct AdminApi<R, C, V> {
    repository: R,
    providers: Arc<ProviderService<R, C, V>>,
    password_hash: Arc<str>,
    password_work: crate::crypto::PasswordWork,
    body_timeout: Duration,
    connection_settings: crate::ConnectionSettings,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    session_ttl: Duration,
    assets: Option<AdminAssets>,
    development_mode: bool,
    metrics: Metrics,
}

#[derive(Clone)]
struct Session {
    csrf_token: String,
    expires_at: Instant,
}

impl<R, C, V> AdminApi<R, C, V>
where
    R: ProviderRepository + RequestLogRepository + Clone,
    C: SecretCipher,
    V: GatewaySecretVerifier + 'static,
{
    pub fn new(
        repository: R,
        cipher: C,
        verifier: V,
        allow_insecure_endpoints: bool,
        password_hash: impl Into<Arc<str>>,
    ) -> Self {
        let mut api = Self::with_session_ttl(
            repository,
            cipher,
            verifier,
            allow_insecure_endpoints,
            password_hash,
            DEFAULT_SESSION_TTL,
        );
        api.development_mode = allow_insecure_endpoints;
        api
    }

    pub fn with_session_ttl(
        repository: R,
        cipher: C,
        verifier: V,
        allow_insecure_endpoints: bool,
        password_hash: impl Into<Arc<str>>,
        session_ttl: Duration,
    ) -> Self {
        Self {
            providers: Arc::new(ProviderService::new(
                repository.clone(),
                cipher,
                verifier,
                allow_insecure_endpoints,
            )),
            repository,
            password_hash: password_hash.into(),
            password_work: crate::crypto::PasswordWork::default(),
            body_timeout: Duration::from_secs(30),
            connection_settings: crate::ConnectionSettings::default(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_ttl,
            assets: None,
            development_mode: false,
            metrics: Metrics::default(),
        }
    }

    pub fn with_runtime(
        mut self,
        config: &crate::config::Config,
        work: crate::crypto::PasswordWork,
    ) -> Self {
        self.password_work = work.clone();
        Arc::get_mut(&mut self.providers)
            .expect("unshared provider service")
            .set_password_work(work);
        self.body_timeout = config.admin_body_timeout();
        self.connection_settings = crate::ConnectionSettings::control(config);
        self.development_mode = config.development_mode();
        self.session_ttl = config.admin_session_ttl();
        self
    }

    pub fn with_password_work(mut self, work: crate::crypto::PasswordWork) -> Self {
        self.password_work = work.clone();
        Arc::get_mut(&mut self.providers)
            .expect("unshared provider service")
            .set_password_work(work);
        self
    }

    pub fn with_metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = metrics;
        self
    }

    /// Serves the compiled administration page from a configured directory.
    pub fn with_assets(mut self, root: &std::path::Path) -> Self {
        self.assets = Some(AdminAssets::new(root));
        self
    }

    /// Confirms a configured administration page directory is usable.
    pub fn verify_assets(&self) -> std::io::Result<()> {
        match &self.assets {
            Some(assets) => assets.verify(),
            None => Ok(()),
        }
    }

    pub async fn handle<B>(&self, request: Request<B>, metrics: Metrics) -> Response<ApiBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();

        if method == Method::GET && path == "/healthz" {
            return Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Full::new(Bytes::from_static(b"control plane ok\n")))
                .expect("health response is valid");
        }

        if method == Method::POST && path == "/admin/api/session" {
            return self.sign_in(request).await;
        }

        if (method == Method::GET || method == Method::HEAD)
            && let Some(response) = self.serve_page(&path)
        {
            return response;
        }

        let Some((session_token, session)) = self.authenticate(&request) else {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication required.",
            );
        };

        if method == Method::GET && path == "/admin/api/session" {
            return json_response(
                StatusCode::OK,
                &SessionView {
                    signed_in: true,
                    csrf_token: &session.csrf_token,
                },
            );
        }
        if method == Method::GET && path == "/metrics" {
            return Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")
                .body(Full::new(Bytes::from(metrics.render())))
                .expect("metrics response is valid");
        }

        if is_state_changing(&method) && !valid_csrf(&request, &session.csrf_token) {
            return api_error(
                StatusCode::FORBIDDEN,
                "invalid_csrf",
                "CSRF validation failed.",
            );
        }

        if method == Method::DELETE && path == "/admin/api/session" {
            self.sessions
                .lock()
                .expect("session lock is not poisoned")
                .remove(&session_token);
            let mut response = empty_response(StatusCode::NO_CONTENT);
            response.headers_mut().insert(
                SET_COOKIE,
                self.session_cookie(&format!("{SESSION_COOKIE}=; Max-Age=0"))
                    .parse()
                    .expect("cleared session cookie is valid"),
            );
            return response;
        }

        if path == "/admin/api/providers" {
            return match method {
                Method::GET => self.list_providers(request.uri().query()).await,
                Method::POST => self.create_provider(request).await,
                _ => method_not_allowed(),
            };
        }
        if path == "/admin/api/request-logs" {
            return if method == Method::GET {
                self.list_request_logs(request.uri().query()).await
            } else {
                method_not_allowed()
            };
        }
        if let Some((id, rotate)) = provider_item_path(&path) {
            let Ok(id) = ProviderId::try_from(id) else {
                return invalid_input("Provider ID must be a positive integer.");
            };
            if rotate {
                return if method == Method::POST {
                    self.rotate_provider(id).await
                } else {
                    method_not_allowed()
                };
            }
            return match method {
                Method::GET => self.get_provider(id).await,
                Method::PATCH => self.update_provider(id, request).await,
                Method::DELETE => self.delete_provider(id).await,
                _ => method_not_allowed(),
            };
        }

        api_error(StatusCode::NOT_FOUND, "not_found", "Resource not found.")
    }

    /// Serves a compiled page asset, when one is configured and the path names
    /// one. The page and the API share this origin, so the page is reachable
    /// before a session exists while every API path stays authenticated.
    fn serve_page(&self, path: &str) -> Option<Response<ApiBody>> {
        if path.starts_with("/admin/api/") || path == "/metrics" || path == "/healthz" {
            return None;
        }
        let asset = self.assets.as_ref()?.resolve(path)?;
        let mut response = asset.into_response();
        response
            .headers_mut()
            .insert("content-security-policy", PAGE_CONTENT_SECURITY_POLICY);
        Some(response)
    }

    async fn sign_in<B>(&self, request: Request<B>) -> Response<ApiBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let Ok(input) = read_json::<_, SignInRequest>(request.into_body(), self.body_timeout).await
        else {
            return invalid_input("A valid JSON password is required.");
        };
        let hash = self.password_hash.clone();
        let password = SecretString::new(input.password);
        let verified = match self
            .password_work
            .run(move || verify_password(password.expose(), &hash))
            .await
        {
            Ok(verified) => verified,
            Err(PasswordWorkError::Busy) => {
                self.metrics
                    .record_failure(ProxyFailureCategory::ResourceExhausted);
                return resource_exhausted();
            }
            Err(PasswordWorkError::Failed) => return internal_error(),
        };
        if !verified {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "Invalid credentials.",
            );
        }
        let Ok(session_token) = random_token() else {
            return internal_error();
        };
        let Ok(csrf_token) = random_token() else {
            return internal_error();
        };
        let now = Instant::now();
        let mut sessions = self.sessions.lock().expect("session lock is not poisoned");
        sessions.retain(|_, session| session.expires_at > now);
        if sessions.len() >= MAX_ACTIVE_SESSIONS {
            return api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "session_limit_reached",
                "No administration session capacity is available.",
            );
        }
        sessions.insert(
            session_token.clone(),
            Session {
                csrf_token: csrf_token.clone(),
                expires_at: now + self.session_ttl,
            },
        );
        drop(sessions);
        let max_age = self.session_ttl.as_secs();
        let mut response = json_response(
            StatusCode::OK,
            &SessionView {
                signed_in: true,
                csrf_token: &csrf_token,
            },
        );
        response.headers_mut().insert(
            SET_COOKIE,
            self.session_cookie(&format!(
                "{SESSION_COOKIE}={session_token}; Max-Age={max_age}"
            ))
            .parse()
            .expect("session cookie is valid"),
        );
        response
    }

    /// Builds the session cookie for one response.
    ///
    /// A production deployment terminates TLS in front of this process and
    /// marks the request as secure, so the cookie keeps its `Secure` flag. A
    /// development deployment on plaintext localhost has no secure origin to
    /// keep the cookie on; it drops only that flag and retains `HttpOnly` and
    /// `SameSite=Strict`, which is what allows the same page to run locally.
    fn session_cookie(&self, prefix: &str) -> String {
        let secure = if self.development_mode {
            ""
        } else {
            " Secure;"
        };
        format!("{prefix} Path=/; HttpOnly;{secure} SameSite=Strict")
    }

    fn authenticate<B>(&self, request: &Request<B>) -> Option<(String, Session)> {
        let token = cookie_value(request, SESSION_COOKIE)?;
        let now = Instant::now();
        let mut sessions = self.sessions.lock().expect("session lock is not poisoned");
        sessions.retain(|_, session| session.expires_at > now);
        let session = sessions.get(&token)?.clone();
        Some((token, session))
    }

    async fn list_providers(&self, query: Option<&str>) -> Response<ApiBody> {
        let Ok(page) = parse_provider_page(query) else {
            return invalid_input("Invalid provider cursor or page size.");
        };
        match self.providers.list(page).await {
            Ok(page) => {
                let next_after_id = page.next_after_id().map(|cursor| cursor.get());
                let items = page.items().iter().map(ProviderAdminView::from).collect();
                json_response(
                    StatusCode::OK,
                    &ProviderListView {
                        items,
                        next_after_id,
                    },
                )
            }
            Err(error) => self.provider_error(error),
        }
    }

    async fn create_provider<B>(&self, request: Request<B>) -> Response<ApiBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let Ok(input) =
            read_json::<_, CreateProviderBody>(request.into_body(), self.body_timeout).await
        else {
            return invalid_input("Invalid provider configuration.");
        };
        let Some(protocol_type) = parse_protocol(&input.protocol_type) else {
            return invalid_input("Invalid provider protocol.");
        };
        let Some(status) = parse_status(&input.status) else {
            return invalid_input("Invalid provider status.");
        };
        let request = CreateProviderRequest::new(
            input.name,
            protocol_type,
            input.endpoint,
            SecretString::new(input.upstream_api_key),
            status,
        );
        match self.providers.create(request).await {
            Ok(created) => {
                let (provider, credential) = created.into_parts();
                json_response(
                    StatusCode::CREATED,
                    &CredentialView {
                        provider: ProviderAdminView::from(&provider),
                        gateway_api_key: credential.render(),
                    },
                )
            }
            Err(error) => self.provider_error(error),
        }
    }

    async fn get_provider(&self, id: ProviderId) -> Response<ApiBody> {
        match self.providers.get(id).await {
            Ok(provider) => json_response(StatusCode::OK, &ProviderAdminView::from(&provider)),
            Err(error) => self.provider_error(error),
        }
    }

    async fn update_provider<B>(&self, id: ProviderId, request: Request<B>) -> Response<ApiBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let Ok(input) =
            read_json::<_, UpdateProviderBody>(request.into_body(), self.body_timeout).await
        else {
            return invalid_input("Invalid provider configuration.");
        };
        let mut change = UpdateProviderRequest::new();
        if let Some(name) = input.name {
            change = change.with_name(name);
        }
        if let Some(endpoint) = input.endpoint {
            change = change.with_endpoint(endpoint);
        }
        if let Some(key) = input.upstream_api_key {
            change = change.with_upstream_api_key(SecretString::new(key));
        }
        if let Some(raw_status) = input.status {
            let Some(status) = parse_status(&raw_status) else {
                return invalid_input("Invalid provider status.");
            };
            change = change.with_status(status);
        }
        match self.providers.update(id, change).await {
            Ok(provider) => json_response(StatusCode::OK, &ProviderAdminView::from(&provider)),
            Err(error) => self.provider_error(error),
        }
    }

    async fn delete_provider(&self, id: ProviderId) -> Response<ApiBody> {
        match self.providers.delete(id).await {
            Ok(()) => empty_response(StatusCode::NO_CONTENT),
            Err(error) => self.provider_error(error),
        }
    }

    async fn rotate_provider(&self, id: ProviderId) -> Response<ApiBody> {
        match self.providers.rotate_gateway_credential(id).await {
            Ok(rotated) => {
                let (provider, credential) = rotated.into_parts();
                json_response(
                    StatusCode::OK,
                    &CredentialView {
                        provider: ProviderAdminView::from(&provider),
                        gateway_api_key: credential.render(),
                    },
                )
            }
            Err(error) => self.provider_error(error),
        }
    }

    async fn list_request_logs(&self, query: Option<&str>) -> Response<ApiBody> {
        let Ok(query) = parse_log_query(query) else {
            return invalid_input("Invalid request-log query.");
        };
        match self.repository.query(query).await {
            Ok(page) => {
                let next_after_id = page.next_after_id().map(|cursor| cursor.get());
                let items = page.items().iter().map(RequestLogView::from).collect();
                json_response(
                    StatusCode::OK,
                    &RequestLogListView {
                        items,
                        next_after_id,
                    },
                )
            }
            Err(RepositoryError::Timeout) => {
                self.metrics
                    .record_failure(ProxyFailureCategory::ResourceExhausted);
                resource_exhausted()
            }
            Err(_) => internal_error(),
        }
    }

    fn provider_error(&self, error: ProviderServiceError) -> Response<ApiBody> {
        match error {
            ProviderServiceError::InvalidName
            | ProviderServiceError::InvalidEndpoint
            | ProviderServiceError::InsecureEndpoint
            | ProviderServiceError::InvalidUpstreamApiKey => {
                invalid_input("Invalid provider configuration.")
            }
            ProviderServiceError::Conflict => api_error(
                StatusCode::CONFLICT,
                "provider_conflict",
                "Provider configuration conflicts with an existing provider.",
            ),
            ProviderServiceError::NotFound => api_error(
                StatusCode::NOT_FOUND,
                "provider_not_found",
                "Provider not found.",
            ),
            ProviderServiceError::InUse => api_error(
                StatusCode::CONFLICT,
                "provider_in_use",
                "Provider is referenced by request logs.",
            ),
            ProviderServiceError::NoFieldsToUpdate => {
                invalid_input("No provider field was supplied.")
            }
            ProviderServiceError::Busy => {
                self.metrics
                    .record_failure(ProxyFailureCategory::ResourceExhausted);
                resource_exhausted()
            }
            ProviderServiceError::Credential
            | ProviderServiceError::Cipher
            | ProviderServiceError::Storage => internal_error(),
        }
    }
}

impl ControlPlaneService for AdminApi<Database, AesGcmCipher, Argon2GatewaySecretVerifier> {
    fn connection_settings(&self) -> crate::ConnectionSettings {
        self.connection_settings
    }
    async fn serve(&self, request: Request<Incoming>, metrics: Metrics) -> Response<ApiBody> {
        self.handle(request, metrics).await
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignInRequest {
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateProviderBody {
    name: String,
    protocol_type: String,
    endpoint: String,
    upstream_api_key: String,
    status: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateProviderBody {
    name: Option<String>,
    endpoint: Option<String>,
    upstream_api_key: Option<String>,
    status: Option<String>,
}

#[derive(Serialize)]
struct SessionView<'a> {
    signed_in: bool,
    csrf_token: &'a str,
}

#[derive(Serialize)]
struct ProviderListView {
    items: Vec<ProviderAdminView>,
    next_after_id: Option<i64>,
}

#[derive(Serialize)]
struct CredentialView {
    provider: ProviderAdminView,
    gateway_api_key: String,
}

#[derive(Serialize)]
struct RequestLogListView {
    items: Vec<RequestLogView>,
    next_after_id: Option<i64>,
}

#[derive(Serialize)]
struct RequestLogView {
    id: i64,
    request_id: String,
    provider_id: i64,
    protocol_type: ProtocolType,
    transport_type: TransportType,
    path: String,
    status_code: Option<u16>,
    start_time: DateTime<Utc>,
    end_time: Option<DateTime<Utc>>,
    error_msg: Option<String>,
    incomplete: bool,
}

impl From<&RequestLog> for RequestLogView {
    fn from(log: &RequestLog) -> Self {
        Self {
            id: log.id().get(),
            request_id: log.request_id().as_str().to_owned(),
            provider_id: log.provider_id().get(),
            protocol_type: log.protocol_type(),
            transport_type: log.transport_type(),
            path: log.path().to_owned(),
            status_code: log.status_code(),
            start_time: log.start_time(),
            end_time: log.end_time(),
            error_msg: log.error_msg().map(str::to_owned),
            incomplete: log.end_time().is_none(),
        }
    }
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: &'a str,
}

async fn read_json<B, T>(body: B, deadline: Duration) -> Result<T, ()>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    T: for<'de> Deserialize<'de>,
{
    let bytes = tokio::time::timeout(deadline, Limited::new(body, MAX_ADMIN_BODY_BYTES).collect())
        .await
        .map_err(|_| ())?
        .map_err(|_| ())?
        .to_bytes();
    serde_json::from_slice(&bytes).map_err(|_| ())
}

fn verify_password(password: &str, encoded_hash: &str) -> bool {
    let Ok(hash) = PasswordHash::new(encoded_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .is_ok()
}

fn random_token() -> Result<String, ()> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| ())?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn cookie_value<B>(request: &Request<B>, name: &str) -> Option<String> {
    let mut found = None;
    for value in request.headers().get_all(COOKIE) {
        for pair in value.to_str().ok()?.split(';') {
            let Some((key, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if key == name {
                if found.is_some() || value.is_empty() || value.len() > 128 {
                    return None;
                }
                found = Some(value.to_owned());
            }
        }
    }
    found
}

fn valid_csrf<B>(request: &Request<B>, expected: &str) -> bool {
    let Some(actual) = request
        .headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    constant_time_eq(actual.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

fn is_state_changing(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PATCH | Method::PUT | Method::DELETE
    )
}

fn parse_provider_page(query: Option<&str>) -> Result<ProviderListRequest, ()> {
    let params = unique_query(query, &["after_id", "limit"])?;
    let after_id = params
        .get("after_id")
        .map(|v| parse_positive(v).and_then(|id| ProviderCursor::try_from(id).map_err(|_| ())))
        .transpose()?;
    let limit = params
        .get("limit")
        .map(|v| v.parse::<usize>().map_err(|_| ()))
        .transpose()?
        .unwrap_or(100);
    ProviderListRequest::new(after_id, limit).map_err(|_| ())
}

fn parse_log_query(query: Option<&str>) -> Result<RequestLogQuery, ()> {
    let params = unique_query(
        query,
        &[
            "after_id",
            "limit",
            "provider_id",
            "transport_type",
            "start_time_gte",
            "start_time_lt",
        ],
    )?;
    let after_id = params
        .get("after_id")
        .map(|v| parse_positive(v).and_then(|id| RequestLogCursor::try_from(id).map_err(|_| ())))
        .transpose()?;
    let limit = params
        .get("limit")
        .map(|v| v.parse::<usize>().map_err(|_| ()))
        .transpose()?
        .unwrap_or(100);
    let provider_id = params
        .get("provider_id")
        .map(|v| parse_positive(v).and_then(|id| ProviderId::try_from(id).map_err(|_| ())))
        .transpose()?;
    let transport = params
        .get("transport_type")
        .map(|value| match value.as_str() {
            "http" => Ok(TransportType::Http),
            "websocket" => Ok(TransportType::WebSocket),
            _ => Err(()),
        })
        .transpose()?;
    let gte = params
        .get("start_time_gte")
        .map(|v| parse_time(v))
        .transpose()?;
    let lt = params
        .get("start_time_lt")
        .map(|v| parse_time(v))
        .transpose()?;
    RequestLogQuery::new(after_id, limit, provider_id, transport, gte, lt).map_err(|_| ())
}

fn unique_query(query: Option<&str>, allowed: &[&str]) -> Result<HashMap<String, String>, ()> {
    let mut params = HashMap::new();
    for (key, value) in url::form_urlencoded::parse(query.unwrap_or_default().as_bytes()) {
        if !allowed.contains(&key.as_ref())
            || params
                .insert(key.into_owned(), value.into_owned())
                .is_some()
        {
            return Err(());
        }
    }
    Ok(params)
}

fn parse_positive(value: &str) -> Result<i64, ()> {
    value
        .parse::<i64>()
        .map_err(|_| ())
        .and_then(|id| (id > 0).then_some(id).ok_or(()))
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, ()> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| ())
}

fn parse_protocol(value: &str) -> Option<ProtocolType> {
    match value {
        "openai" => Some(ProtocolType::OpenAi),
        "anthropic" => Some(ProtocolType::Anthropic),
        _ => None,
    }
}

fn parse_status(value: &str) -> Option<ProviderStatus> {
    match value {
        "enabled" => Some(ProviderStatus::Enabled),
        "disabled" => Some(ProviderStatus::Disabled),
        _ => None,
    }
}

fn provider_item_path(path: &str) -> Option<(i64, bool)> {
    let suffix = path.strip_prefix("/admin/api/providers/")?;
    let (id, rotate) = match suffix.strip_suffix("/gateway-key:rotate") {
        Some(id) => (id, true),
        None => (suffix, false),
    };
    if id.is_empty() || id.contains('/') {
        return None;
    }
    Some((id.parse().ok()?, rotate))
}

fn resource_exhausted() -> Response<ApiBody> {
    api_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "resource_exhausted",
        "The gateway has no spare capacity for this request.",
    )
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response<ApiBody> {
    let body = serde_json::to_vec(value).expect("administration response is serializable");
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header(CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::from(body)))
        .expect("JSON response is valid")
}

fn empty_response(status: StatusCode) -> Response<ApiBody> {
    Response::builder()
        .status(status)
        .header(CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::new()))
        .expect("empty administration response is valid")
}

fn api_error(status: StatusCode, code: &'static str, message: &'static str) -> Response<ApiBody> {
    json_response(
        status,
        &ErrorEnvelope {
            error: ErrorBody { code, message },
        },
    )
}

fn invalid_input(message: &'static str) -> Response<ApiBody> {
    api_error(StatusCode::BAD_REQUEST, "invalid_request", message)
}

fn internal_error() -> Response<ApiBody> {
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "The request could not be completed.",
    )
}

fn method_not_allowed() -> Response<ApiBody> {
    api_error(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "Method not allowed.",
    )
}
