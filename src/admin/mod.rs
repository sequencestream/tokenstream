//! Authenticated administration sessions and HTTP API.

pub mod assets;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
use crate::config::Config;
use crate::credentials::{
    CreateAccountRequest, CreateApiKeyRequest, CredentialService, CredentialServiceError,
    UpdateAccountRequest, UpdateApiKeyRequest,
};
use crate::crypto::{
    AesGcmCipher, Argon2GatewaySecretVerifier, GatewaySecretVerifier, SecretCipher, SharedCipher,
};
use crate::domain::{
    AccountAdminView, AccountCursor, AccountId, AccountRole, AccountStatus, ApiKeyAdminView,
    ApiKeyCursor, ApiKeyId, ApiKeyStatus, CredentialAdmission, InvalidAdmissionBound, ProtocolType,
    ProviderAdminView, ProviderAdmission, ProviderCursor, ProviderId, ProviderStatus, RequestLog,
    RequestLogCursor, SecretString, TransportType,
};
use crate::persistence::{
    AccountListRequest, AccountRepository, ApiKeyListRequest, Database, ProviderListRequest,
    ProviderRepository, RepositoryError, RequestLogQuery, RequestLogRepository,
};
use crate::providers::{
    CreateProviderRequest, ProviderService, ProviderServiceError, UpdateProviderRequest,
};
use crate::telemetry::{Metrics, ProxyFailureCategory};

const SESSION_COOKIE: &str = "tokenstream_admin";

/// The name of the account created from the configured administrator
/// credentials when no account exists yet.
pub const DEFAULT_BOOTSTRAP_ACCOUNT_NAME: &str = "admin";
const MAX_ADMIN_BODY_BYTES: usize = 16 * 1024;
const MAX_ACTIVE_SESSIONS: usize = 1_024;
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(15 * 60);

type ApiBody = Full<Bytes>;

#[derive(Clone)]
pub struct AdminApi<R, C, V> {
    repository: R,
    providers: Arc<ProviderService<R, C>>,
    credentials: Arc<CredentialService<R, V>>,
    bootstrap_password_hash: Arc<Mutex<Arc<str>>>,
    body_timeout: Arc<Mutex<Duration>>,
    connection_settings: crate::ConnectionSettings,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    session_ttl: Arc<Mutex<Duration>>,
    assets: AdminAssets,
    development_mode: Arc<Mutex<bool>>,
    metrics: Metrics,
    process: Option<Arc<Mutex<ProcessSettings>>>,
}

struct ProcessSettings {
    startup: Config,
    desired: Config,
    overlay: HashMap<String, String>,
}

#[derive(Clone)]
struct Session {
    csrf_token: String,
    account_id: AccountId,
    role: AccountRole,
    expires_at: Instant,
}

/// The principal a request acts as, resolved once before dispatch.
///
/// Authorization reads this and never re-reads the session, so a handler cannot
/// decide for itself whether the caller was allowed to reach it.
#[derive(Clone, Copy)]
struct Principal {
    account_id: AccountId,
    role: AccountRole,
}

impl Principal {
    fn is_admin(self) -> bool {
        self.role.is_admin()
    }
}

impl<R, C, V> AdminApi<R, C, V>
where
    R: ProviderRepository
        + RequestLogRepository
        + AccountRepository
        + crate::persistence::ApiKeyRepository
        + Clone,
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
        api.development_mode = Arc::new(Mutex::new(allow_insecure_endpoints));
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
                allow_insecure_endpoints,
            )),
            // Credential issuance and account passwords both hash on the
            // control-plane budget, so a burst of administration cannot consume
            // data-plane verification capacity.
            credentials: Arc::new(CredentialService::new(repository.clone(), verifier)),
            repository,
            // The bootstrap name identifies the first account; the configured
            // password hash stays the operator's way back into a deployment
            // even after the account exists and its own password is changed.
            bootstrap_password_hash: Arc::new(Mutex::new(password_hash.into())),
            body_timeout: Arc::new(Mutex::new(Duration::from_secs(30))),
            connection_settings: crate::ConnectionSettings::default(),
            sessions: Arc::new(Mutex::new(HashMap::new())),
            session_ttl: Arc::new(Mutex::new(session_ttl)),
            assets: AdminAssets::embedded(),
            development_mode: Arc::new(Mutex::new(false)),
            metrics: Metrics::default(),
            process: None,
        }
    }

    pub fn with_runtime(
        mut self,
        config: &crate::config::Config,
        work: crate::crypto::PasswordWork,
    ) -> Self {
        Arc::get_mut(&mut self.credentials)
            .expect("unshared credential service")
            .set_password_work(work);
        self.body_timeout = Arc::new(Mutex::new(config.admin_body_timeout()));
        self.connection_settings = crate::ConnectionSettings::control(config);
        self.development_mode = Arc::new(Mutex::new(config.development_mode()));
        self.session_ttl = Arc::new(Mutex::new(config.admin_session_ttl()));
        let overlay = config
            .data_dir()
            .and_then(|dir| crate::local_state::load_overlay(dir).ok())
            .unwrap_or_default();
        self.process = Some(Arc::new(Mutex::new(ProcessSettings {
            startup: config.clone(),
            desired: config.clone(),
            overlay,
        })));
        self
    }

    pub fn with_password_work(mut self, work: crate::crypto::PasswordWork) -> Self {
        Arc::get_mut(&mut self.credentials)
            .expect("unshared credential service")
            .set_password_work(work);
        self
    }

    pub fn with_metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = metrics;
        self
    }

    fn current_body_timeout(&self) -> Duration {
        *self
            .body_timeout
            .lock()
            .expect("body timeout lock is not poisoned")
    }

    pub fn with_assets(mut self, assets: AdminAssets) -> Self {
        self.assets = assets;
        self
    }

    /// Creates the bootstrap administrator when the store holds no account.
    ///
    /// This runs once per deployment. Credentials that predate accounts are
    /// adopted into this account in the same transaction, so an upgrade never
    /// invalidates a client that already holds one.
    pub async fn ensure_bootstrap_account(
        &self,
        name: &str,
        password: &str,
    ) -> Result<bool, CredentialServiceError> {
        Ok(self
            .credentials
            .ensure_bootstrap(name.to_owned(), crate::domain::SecretString::new(password))
            .await?
            .is_some())
    }

    /// Confirms the compiled administration page is present.
    pub fn verify_assets(&self) -> std::io::Result<()> {
        self.assets.verify()
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

        let Some((session_token, principal)) = self.authenticate(&request) else {
            return api_error(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication required.",
            );
        };

        if method == Method::GET && path == "/admin/api/session" {
            let Some(session) = self.session(&session_token) else {
                return api_error(
                    StatusCode::UNAUTHORIZED,
                    "unauthorized",
                    "Authentication required.",
                );
            };
            let name = self
                .account_name(session.account_id)
                .await
                .unwrap_or_default();
            return json_response(
                StatusCode::OK,
                &SessionView {
                    signed_in: true,
                    csrf_token: &session.csrf_token,
                    account_name: &name,
                    role: session.role,
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

        if is_state_changing(&method) && !self.valid_session_csrf(&request, &session_token) {
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

        if path == "/admin/api/accounts" {
            if !principal.is_admin() {
                return forbidden();
            }
            return match method {
                Method::GET => self.list_accounts(request.uri().query()).await,
                Method::POST => self.create_account(request).await,
                _ => method_not_allowed(),
            };
        }
        if let Some(id) = account_item_path(&path) {
            if !principal.is_admin() {
                return forbidden();
            }
            let id = parse_account_id(id);
            return match method {
                Method::GET => self.get_account(id).await,
                Method::PATCH => self.update_account(id, request).await,
                Method::DELETE => self.delete_account(id).await,
                _ => method_not_allowed(),
            };
        }
        if path == "/admin/api/api-keys" {
            return match method {
                Method::GET => self.list_api_keys(principal, request.uri().query()).await,
                Method::POST => self.create_api_key(principal, request).await,
                _ => method_not_allowed(),
            };
        }
        if let Some((id, rotate)) = api_key_item_path(&path) {
            return if rotate {
                match method {
                    Method::POST => self.rotate_api_key(principal, parse_api_key_id(id)).await,
                    _ => method_not_allowed(),
                }
            } else {
                match method {
                    Method::GET => self.get_api_key(principal, parse_api_key_id(id)).await,
                    Method::PATCH => {
                        self.update_api_key(principal, parse_api_key_id(id), request)
                            .await
                    }
                    Method::DELETE => self.delete_api_key(principal, parse_api_key_id(id)).await,
                    _ => method_not_allowed(),
                }
            };
        }
        if path == "/admin/api/providers" {
            return match method {
                Method::GET => self.list_providers(request.uri().query()).await,
                Method::POST if principal.is_admin() => self.create_provider(request).await,
                _ if !principal.is_admin() => forbidden(),
                _ => method_not_allowed(),
            };
        }
        if path == "/admin/api/request-logs" {
            return if method == Method::GET {
                self.list_request_logs(principal, request.uri().query())
                    .await
            } else {
                method_not_allowed()
            };
        }
        if path == "/admin/api/settings" {
            return match method {
                _ if !principal.is_admin() => forbidden(),
                Method::GET => self.list_settings(),
                Method::PATCH => self.patch_settings(request).await,
                _ => method_not_allowed(),
            };
        }
        if let Some((id, rotate)) = provider_item_path(&path) {
            let Ok(id) = ProviderId::try_from(id) else {
                return invalid_input("Provider ID must be a positive integer.");
            };
            // Rotation belongs to the account that owns a credential, not to a
            // provider, so the provider route no longer issues one.
            if rotate {
                return method_not_allowed();
            }
            return match method {
                Method::GET => self.get_provider(id).await,
                Method::PATCH if principal.is_admin() => self.update_provider(id, request).await,
                Method::DELETE if principal.is_admin() => self.delete_provider(id).await,
                _ if !principal.is_admin() => forbidden(),
                _ => method_not_allowed(),
            };
        }

        api_error(StatusCode::NOT_FOUND, "not_found", "Resource not found.")
    }

    /// Serves a compiled page asset when the path names one. The page and the
    /// API share this origin, so the page is reachable before a session exists
    /// while every API path stays authenticated.
    fn serve_page(&self, path: &str) -> Option<Response<ApiBody>> {
        if path.starts_with("/admin/api/") || path == "/metrics" || path == "/healthz" {
            return None;
        }
        let asset = self.assets.resolve(path)?;
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
        let Ok(input) =
            read_json::<_, SignInRequest>(request.into_body(), self.current_body_timeout()).await
        else {
            return invalid_input("A valid JSON name and password are required.");
        };
        // The named account resolves through storage so a disabled account
        // fails the same way a wrong password does, without a second error
        // path an operator could learn something from.
        let account = match self
            .credentials
            .verify_sign_in(&input.name, &input.password)
            .await
        {
            Ok(account) => account,
            Err(CredentialServiceError::InvalidCredentials) => {
                return api_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_credentials",
                    "Invalid credentials.",
                );
            }
            Err(CredentialServiceError::Busy) => {
                self.metrics
                    .record_failure(ProxyFailureCategory::ResourceExhausted);
                return resource_exhausted();
            }
            Err(_) => return internal_error(),
        };
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
        let session_ttl = *self
            .session_ttl
            .lock()
            .expect("session ttl lock is not poisoned");
        sessions.insert(
            session_token.clone(),
            Session {
                csrf_token: csrf_token.clone(),
                account_id: account.id(),
                role: account.role(),
                expires_at: now + session_ttl,
            },
        );
        drop(sessions);
        let max_age = session_ttl.as_secs();
        let mut response = json_response(
            StatusCode::OK,
            &SessionView {
                signed_in: true,
                csrf_token: &csrf_token,
                account_name: account.name(),
                role: account.role(),
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
        let secure = if *self
            .development_mode
            .lock()
            .expect("development mode lock is not poisoned")
        {
            ""
        } else {
            " Secure;"
        };
        format!("{prefix} Path=/; HttpOnly;{secure} SameSite=Strict")
    }

    /// Resolves the principal a request acts as.
    ///
    /// The result is decided once, from the session's account and role, and is
    /// what every authorization check below reads. A handler never decides
    /// whether the caller was allowed to reach it.
    fn authenticate<B>(&self, request: &Request<B>) -> Option<(String, Principal)> {
        let token = cookie_value(request, SESSION_COOKIE)?;
        let now = Instant::now();
        let mut sessions = self.sessions.lock().expect("session lock is not poisoned");
        sessions.retain(|_, session| session.expires_at > now);
        let session = sessions.get(&token)?;
        Some((
            token.clone(),
            Principal {
                account_id: session.account_id,
                role: session.role,
            },
        ))
    }

    /// Reads the live session record for a token.
    fn session(&self, token: &str) -> Option<Session> {
        let sessions = self.sessions.lock().expect("session lock is not poisoned");
        sessions.get(token).cloned()
    }

    /// Reads an account's current name for the session view.
    async fn account_name(&self, id: AccountId) -> Option<String> {
        self.credentials
            .get_account(id)
            .await
            .ok()
            .map(|account| account.name().to_owned())
    }

    /// Confirms the session's CSRF token matches the request.
    fn valid_session_csrf<B>(&self, request: &Request<B>, token: &str) -> bool {
        let sessions = self.sessions.lock().expect("session lock is not poisoned");
        sessions
            .get(token)
            .is_some_and(|session| valid_csrf(request, &session.csrf_token))
    }

    async fn list_accounts(&self, query: Option<&str>) -> Response<ApiBody> {
        let Ok(page) = parse_account_page(query) else {
            return invalid_input("Invalid account cursor or page size.");
        };
        match self.credentials.list_accounts(page).await {
            Ok(page) => {
                let next_after_id = page.next_after_id().map(|cursor| cursor.get());
                let items = page.items().iter().map(AccountAdminView::from).collect();
                json_response(
                    StatusCode::OK,
                    &AccountListView {
                        items,
                        next_after_id,
                    },
                )
            }
            Err(error) => self.credential_error(error),
        }
    }

    async fn create_account<B>(&self, request: Request<B>) -> Response<ApiBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let Ok(input) =
            read_json::<_, CreateAccountBody>(request.into_body(), self.current_body_timeout())
                .await
        else {
            return invalid_input("Invalid account configuration.");
        };
        let Some(role) = parse_account_role(&input.role) else {
            return invalid_input("Invalid account role.");
        };
        let Some(status) = parse_account_status(&input.status) else {
            return invalid_input("Invalid account status.");
        };
        let password = input.password.filter(|value| !value.is_empty());
        match self
            .credentials
            .create_account(CreateAccountRequest::new(
                input.name,
                password.map(SecretString::new),
                role,
                status,
            ))
            .await
        {
            Ok(created) => {
                let (account, generated) = created.into_parts();
                json_response(
                    StatusCode::CREATED,
                    &AccountCreateView {
                        account: AccountAdminView::from(&account),
                        generated_password: generated.map(|p| p.expose().to_owned()),
                    },
                )
            }
            Err(error) => self.credential_error(error),
        }
    }

    async fn get_account(&self, id: AccountId) -> Response<ApiBody> {
        match self.credentials.get_account(id).await {
            Ok(account) => json_response(StatusCode::OK, &AccountAdminView::from(&account)),
            Err(error) => self.credential_error(error),
        }
    }

    async fn update_account<B>(&self, id: AccountId, request: Request<B>) -> Response<ApiBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let Ok(input) =
            read_json::<_, UpdateAccountBody>(request.into_body(), self.current_body_timeout())
                .await
        else {
            return invalid_input("Invalid account configuration.");
        };
        let mut change = UpdateAccountRequest::new();
        if let Some(name) = input.name {
            change = change.with_name(name);
        }
        if let Some(password) = input.password.filter(|value| !value.is_empty()) {
            change = change.with_password(SecretString::new(password));
        }
        if let Some(raw_role) = input.role {
            let Some(role) = parse_account_role(&raw_role) else {
                return invalid_input("Invalid account role.");
            };
            change = change.with_role(role);
        }
        if let Some(raw_status) = input.status {
            let Some(status) = parse_account_status(&raw_status) else {
                return invalid_input("Invalid account status.");
            };
            change = change.with_status(status);
        }
        match self.credentials.update_account(id, change).await {
            Ok(account) => json_response(StatusCode::OK, &AccountAdminView::from(&account)),
            Err(error) => self.credential_error(error),
        }
    }

    async fn delete_account(&self, id: AccountId) -> Response<ApiBody> {
        match self.credentials.delete_account(id).await {
            Ok(()) => empty_response(StatusCode::NO_CONTENT),
            Err(error) => self.credential_error(error),
        }
    }

    async fn list_api_keys(&self, principal: Principal, query: Option<&str>) -> Response<ApiBody> {
        let Ok(page) = parse_api_key_page(query) else {
            return invalid_input("Invalid credential cursor or page size.");
        };
        // A regular user is scoped to its own account rather than refused, so
        // the same list view works for both roles without leaking other rows.
        let page = if principal.is_admin() {
            page
        } else {
            match ApiKeyListRequest::new(page.after_id(), page.limit(), Some(principal.account_id))
            {
                Ok(page) => page,
                Err(_) => return invalid_input("Invalid credential page size."),
            }
        };
        match self.credentials.list_api_keys(page).await {
            Ok(page) => {
                let next_after_id = page.next_after_id().map(|cursor| cursor.get());
                let items = page
                    .items()
                    .iter()
                    .map(|key| ApiKeyAdminView::new(key.api_key(), key.bindings()))
                    .collect();
                json_response(
                    StatusCode::OK,
                    &ApiKeyListView {
                        items,
                        next_after_id,
                    },
                )
            }
            Err(error) => self.credential_error(error),
        }
    }

    async fn create_api_key<B>(
        &self,
        principal: Principal,
        request: Request<B>,
    ) -> Response<ApiBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let Ok(input) =
            read_json::<_, CreateApiKeyBody>(request.into_body(), self.current_body_timeout())
                .await
        else {
            return invalid_input("Invalid credential configuration.");
        };
        let Some(account_id) = input.account_id.and_then(|id| AccountId::try_from(id).ok()) else {
            return invalid_input("An owning account is required.");
        };
        // A regular user may issue credentials only for itself. Naming another
        // account is refused rather than silently redirected to its own.
        if !principal.is_admin() && account_id != principal.account_id {
            return forbidden();
        }
        let Some(status) = parse_api_key_status(&input.status) else {
            return invalid_input("Invalid credential status.");
        };
        let mut provider_ids = Vec::with_capacity(input.provider_ids.len());
        for raw in &input.provider_ids {
            let Some(id) = ProviderId::try_from(*raw).ok() else {
                return invalid_input("Invalid provider identifier.");
            };
            provider_ids.push(id);
        }
        let default_provider_id = match input.default_provider_id {
            Some(raw) => match ProviderId::try_from(raw).ok() {
                Some(id) => Some(id),
                None => return invalid_input("Invalid default provider identifier."),
            },
            None => None,
        };
        let admission = match CredentialAdmission::new(
            input.max_concurrent_requests,
            input.max_requests_per_second,
            input.max_websockets,
        ) {
            Ok(admission) => admission,
            Err(_) => return invalid_input("Invalid credential configuration."),
        };
        match self
            .credentials
            .create_api_key(
                CreateApiKeyRequest::new(
                    account_id,
                    input.name,
                    provider_ids,
                    default_provider_id,
                    input.expires_at,
                    status,
                )
                .with_admission(admission),
            )
            .await
        {
            Ok(issued) => {
                let (api_key, credential) = issued.into_parts();
                json_response(
                    StatusCode::CREATED,
                    &ApiKeyIssueView {
                        api_key: ApiKeyAdminView::new(api_key.api_key(), api_key.bindings()),
                        api_key_secret: credential.render(),
                    },
                )
            }
            Err(error) => self.credential_error(error),
        }
    }

    async fn get_api_key(&self, principal: Principal, id: ApiKeyId) -> Response<ApiBody> {
        match self.credentials.get_api_key(id).await {
            Ok(api_key) if self.may_reach(principal, api_key.api_key().account_id()) => {
                json_response(
                    StatusCode::OK,
                    &ApiKeyAdminView::new(api_key.api_key(), api_key.bindings()),
                )
            }
            Ok(_) => forbidden(),
            Err(error) => self.credential_error(error),
        }
    }

    async fn update_api_key<B>(
        &self,
        principal: Principal,
        id: ApiKeyId,
        request: Request<B>,
    ) -> Response<ApiBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let current = match self.credentials.get_api_key(id).await {
            Ok(api_key) => api_key,
            Err(error) => return self.credential_error(error),
        };
        if !self.may_reach(principal, current.api_key().account_id()) {
            return forbidden();
        }
        let Ok(input) =
            read_json::<_, UpdateApiKeyBody>(request.into_body(), self.current_body_timeout())
                .await
        else {
            return invalid_input("Invalid credential configuration.");
        };
        let mut change = UpdateApiKeyRequest::new();
        if let Some(name) = input.name {
            change = change.with_name(name);
        }
        if let Some(raw_status) = input.status {
            let Some(status) = parse_api_key_status(&raw_status) else {
                return invalid_input("Invalid credential status.");
            };
            change = change.with_status(status);
        }
        if input.expires_at.is_some() {
            change = change.with_expires_at(input.expires_at.flatten());
        }
        if let Some(raw) = input.provider_ids {
            let mut provider_ids = Vec::with_capacity(raw.len());
            for value in raw {
                let Some(id) = ProviderId::try_from(value).ok() else {
                    return invalid_input("Invalid provider identifier.");
                };
                provider_ids.push(id);
            }
            change = change.with_provider_ids(provider_ids);
        }
        if let Some(raw) = input.default_provider_id {
            let default = match raw {
                Some(value) => match ProviderId::try_from(value).ok() {
                    Some(id) => Some(id),
                    None => return invalid_input("Invalid default provider identifier."),
                },
                None => None,
            };
            change = change.with_default_provider_id(default);
        }
        if let Some(admission) = input.admission {
            // An edit that names only bounds is a real edit, and an edit that
            // names a zero bound is refused before anything is written.
            let admission = match admission.admission() {
                Ok(admission) => admission,
                Err(_) => return invalid_input("Invalid credential configuration."),
            };
            change = change.with_admission(admission);
        }
        match self.credentials.update_api_key(id, &current, change).await {
            Ok(api_key) => json_response(
                StatusCode::OK,
                &ApiKeyAdminView::new(api_key.api_key(), api_key.bindings()),
            ),
            Err(error) => self.credential_error(error),
        }
    }

    async fn rotate_api_key(&self, principal: Principal, id: ApiKeyId) -> Response<ApiBody> {
        let current = match self.credentials.get_api_key(id).await {
            Ok(api_key) => api_key,
            Err(error) => return self.credential_error(error),
        };
        if !self.may_reach(principal, current.api_key().account_id()) {
            return forbidden();
        }
        match self.credentials.rotate_api_key(id).await {
            Ok(issued) => {
                let (api_key, credential) = issued.into_parts();
                json_response(
                    StatusCode::OK,
                    &ApiKeyIssueView {
                        api_key: ApiKeyAdminView::new(api_key.api_key(), api_key.bindings()),
                        api_key_secret: credential.render(),
                    },
                )
            }
            Err(error) => self.credential_error(error),
        }
    }

    async fn delete_api_key(&self, principal: Principal, id: ApiKeyId) -> Response<ApiBody> {
        let current = match self.credentials.get_api_key(id).await {
            Ok(api_key) => api_key,
            Err(error) => return self.credential_error(error),
        };
        if !self.may_reach(principal, current.api_key().account_id()) {
            return forbidden();
        }
        match self.credentials.delete_api_key(id).await {
            Ok(()) => empty_response(StatusCode::NO_CONTENT),
            Err(error) => self.credential_error(error),
        }
    }

    /// Whether this principal may reach a resource owned by `owner`.
    ///
    /// An administrator reaches everything; a regular user reaches only what it
    /// owns. This is the single place ownership is decided, so no handler can
    /// widen it by accident.
    fn may_reach(&self, principal: Principal, owner: AccountId) -> bool {
        principal.is_admin() || principal.account_id == owner
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
            read_json::<_, CreateProviderBody>(request.into_body(), self.current_body_timeout())
                .await
        else {
            return invalid_input("Invalid provider configuration.");
        };
        let Some(protocol_type) = parse_protocol(&input.protocol_type) else {
            return invalid_input("Invalid provider protocol.");
        };
        let Some(status) = parse_status(&input.status) else {
            return invalid_input("Invalid provider status.");
        };
        let admission = match ProviderAdmission::new(
            input.max_concurrent_requests,
            input.max_requests_per_second,
        ) {
            Ok(admission) => admission,
            Err(_) => return invalid_input("Invalid provider configuration."),
        };
        let request = CreateProviderRequest::new(
            input.name,
            protocol_type,
            input.endpoint,
            SecretString::new(input.upstream_api_key),
            status,
        )
        .with_admission(admission);
        match self.providers.create(request).await {
            Ok(provider) => json_response(StatusCode::CREATED, &ProviderAdminView::from(&provider)),
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
            read_json::<_, UpdateProviderBody>(request.into_body(), self.current_body_timeout())
                .await
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
        if let Some(admission) = input.admission {
            // An edit that names only bounds is a real edit, and an edit that
            // names a zero bound is refused before anything is written.
            let admission = match admission.admission() {
                Ok(admission) => admission,
                Err(_) => return invalid_input("Invalid provider configuration."),
            };
            change = change.with_admission(admission);
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

    fn list_settings(&self) -> Response<ApiBody> {
        let Some(process) = &self.process else {
            return json_response(StatusCode::OK, &SettingsListView { items: Vec::new() });
        };
        let process = process.lock().expect("settings lock is not poisoned");
        let items = crate::local_state::setting_catalog()
            .iter()
            .map(|spec| setting_view(spec, &process.startup, &process.desired))
            .collect();
        json_response(StatusCode::OK, &SettingsListView { items })
    }

    async fn patch_settings<B>(&self, request: Request<B>) -> Response<ApiBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        let Some(process) = &self.process else {
            return api_error(
                StatusCode::NOT_FOUND,
                "not_found",
                "Process settings are not available.",
            );
        };
        let Ok(input) = read_json::<_, HashMap<String, String>>(
            request.into_body(),
            self.current_body_timeout(),
        )
        .await
        else {
            return invalid_input("Invalid settings.");
        };
        if input.is_empty() {
            return invalid_input("No setting was supplied.");
        }
        for name in input.keys() {
            if crate::local_state::spec_for(name).is_none() {
                return invalid_input("Unknown setting.");
            }
        }

        let (mut values, data_dir) = {
            let process = process.lock().expect("settings lock is not poisoned");
            (
                process.desired.to_env_map(),
                process.desired.data_dir().map(ToOwned::to_owned),
            )
        };
        let mut new_password_hash = None;
        let mut new_master = None;
        for (name, value) in &input {
            let spec = crate::local_state::spec_for(name).expect("catalog name");
            if spec.secret && value.is_empty() {
                continue;
            }
            match name.as_str() {
                "TOKENSTREAM_ADMIN_PASSWORD" => {
                    let hash = match crate::local_state::hash_admin_password(value) {
                        Ok(hash) => hash,
                        Err(_) => return invalid_input("Invalid administrator password."),
                    };
                    values.insert("TOKENSTREAM_ADMIN_PASSWORD_HASH".to_owned(), hash.clone());
                    new_password_hash = Some(hash);
                }
                "TOKENSTREAM_MASTER_KEY" => {
                    new_master = Some(value.clone());
                    values.insert(name.clone(), value.clone());
                }
                _ => {
                    values.insert(name.clone(), value.clone());
                }
            }
        }
        let desired = match Config::from_map(&values) {
            Ok(config) => config.with_data_dir(data_dir.clone()),
            Err(_) => return invalid_input("Invalid setting value."),
        };

        // The configured administrator password is the bootstrap account's
        // password once an account exists, so changing it resets that account.
        // Doing it here keeps one source of truth: there is no second
        // passphrase that can drift from the account it stands for.
        if let Some(hash) = new_password_hash {
            if let Some(data_dir) = data_dir.as_deref()
                && crate::local_state::save_admin_hash_file(data_dir, &hash).is_err()
            {
                return internal_error();
            }
            let bootstrap = match AccountRepository::find_bootstrap(&self.repository).await {
                Ok(bootstrap) => bootstrap,
                Err(_) => return internal_error(),
            };
            if let Some(bootstrap) = bootstrap {
                let mut change = UpdateAccountRequest::new();
                change = change.with_password(SecretString::new(
                    input
                        .get("TOKENSTREAM_ADMIN_PASSWORD")
                        .cloned()
                        .unwrap_or_default(),
                ));
                if self
                    .credentials
                    .update_account(bootstrap.id(), change)
                    .await
                    .is_err()
                {
                    return internal_error();
                }
            }
            *self
                .bootstrap_password_hash
                .lock()
                .expect("password hash lock is not poisoned") = Arc::from(hash);
        }

        if let Some(hex) = new_master {
            let key = match crate::config::decode_master_key_for_admin(&hex) {
                Ok(key) => key,
                Err(_) => return invalid_input("Invalid master key."),
            };
            let next = AesGcmCipher::new(&key);
            if self.providers.reencrypt_upstream_keys(&next).await.is_err() {
                return internal_error();
            }
            self.providers.cipher().install_master_key(&key);
            if let Some(data_dir) = data_dir.as_deref()
                && crate::local_state::save_master_key_file(data_dir, &hex).is_err()
            {
                return internal_error();
            }
        }

        {
            let mut process = process.lock().expect("settings lock is not poisoned");
            for (name, value) in &input {
                let spec = crate::local_state::spec_for(name).expect("catalog name");
                if spec.secret {
                    continue;
                }
                process.overlay.insert(name.clone(), value.clone());
            }
            let overlay_dir = desired
                .data_dir()
                .map(ToOwned::to_owned)
                .or_else(|| process.desired.data_dir().map(ToOwned::to_owned));
            if let Some(data_dir) = overlay_dir.as_deref()
                && crate::local_state::save_overlay(data_dir, &process.overlay).is_err()
            {
                return internal_error();
            }
            *self
                .body_timeout
                .lock()
                .expect("body timeout lock is not poisoned") = desired.admin_body_timeout();
            *self
                .session_ttl
                .lock()
                .expect("session ttl lock is not poisoned") = desired.admin_session_ttl();
            *self
                .development_mode
                .lock()
                .expect("development mode lock is not poisoned") = desired.development_mode();
            process.desired = desired;
        }
        self.list_settings()
    }

    async fn list_request_logs(
        &self,
        principal: Principal,
        query: Option<&str>,
    ) -> Response<ApiBody> {
        let Ok(query) = parse_log_query(query) else {
            return invalid_input("Invalid request-log query.");
        };
        // A regular user reads only its own traffic. The scope is applied here
        // rather than trusted from the query, so naming another account in
        // `account_id` cannot widen the result set.
        let query = if principal.is_admin() {
            query
        } else {
            match RequestLogQuery::new(
                query.after_id(),
                query.limit(),
                Some(principal.account_id),
                query.provider_id(),
                query.transport_type(),
                query.start_time_gte(),
                query.start_time_lt(),
            ) {
                Ok(query) => query,
                Err(_) => return invalid_input("Invalid request-log query."),
            }
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
            | ProviderServiceError::InvalidUpstreamApiKey
            | ProviderServiceError::InvalidAdmissionBound => {
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
            ProviderServiceError::Bound => api_error(
                StatusCode::CONFLICT,
                "provider_in_use",
                "Provider is bound to a credential.",
            ),
            ProviderServiceError::NoFieldsToUpdate => {
                invalid_input("No provider field was supplied.")
            }
            ProviderServiceError::Busy => {
                self.metrics
                    .record_failure(ProxyFailureCategory::ResourceExhausted);
                resource_exhausted()
            }
            ProviderServiceError::Cipher | ProviderServiceError::Storage => internal_error(),
        }
    }

    fn credential_error(&self, error: CredentialServiceError) -> Response<ApiBody> {
        match error {
            CredentialServiceError::InvalidName
            | CredentialServiceError::InvalidPassword
            | CredentialServiceError::InvalidRoleOrStatus
            | CredentialServiceError::InvalidProviders
            | CredentialServiceError::DefaultNotInProviderSet
            | CredentialServiceError::InvalidExpiry
            | CredentialServiceError::InvalidAdmissionBound
            | CredentialServiceError::NoFieldsToUpdate => {
                invalid_input("Invalid account or credential configuration.")
            }
            CredentialServiceError::ProviderNotFound => api_error(
                StatusCode::NOT_FOUND,
                "provider_not_found",
                "Provider not found.",
            ),
            CredentialServiceError::NotOwner | CredentialServiceError::BootstrapProtected => {
                forbidden()
            }
            CredentialServiceError::InvalidCredentials => api_error(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "Invalid credentials.",
            ),
            CredentialServiceError::Conflict => api_error(
                StatusCode::CONFLICT,
                "credential_conflict",
                "The record conflicts with an existing account or credential.",
            ),
            CredentialServiceError::NotFound => api_error(
                StatusCode::NOT_FOUND,
                "not_found",
                "Account or credential not found.",
            ),
            CredentialServiceError::InUse => api_error(
                StatusCode::CONFLICT,
                "in_use",
                "The record is referenced by request logs.",
            ),
            CredentialServiceError::Busy => {
                self.metrics
                    .record_failure(ProxyFailureCategory::ResourceExhausted);
                resource_exhausted()
            }
            CredentialServiceError::Storage => internal_error(),
        }
    }
}

impl ControlPlaneService for AdminApi<Database, SharedCipher, Argon2GatewaySecretVerifier> {
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
    name: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateAccountBody {
    name: String,
    /// Absent or empty means the process generates one and returns it once.
    password: Option<String>,
    role: String,
    status: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateAccountBody {
    name: Option<String>,
    password: Option<String>,
    role: Option<String>,
    status: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateApiKeyBody {
    account_id: Option<i64>,
    name: String,
    provider_ids: Vec<i64>,
    default_provider_id: Option<i64>,
    expires_at: Option<DateTime<Utc>>,
    status: String,
    /// Admission bounds. Absent on create means unbounded; an explicit null is
    /// the same as absent, because "no bound" is what null already means.
    max_concurrent_requests: Option<u32>,
    max_requests_per_second: Option<u32>,
    max_websockets: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateApiKeyBody {
    name: Option<String>,
    status: Option<String>,
    /// Present-and-null clears the expiration; absent leaves it unchanged.
    expires_at: Option<Option<DateTime<Utc>>>,
    provider_ids: Option<Vec<i64>>,
    default_provider_id: Option<Option<i64>>,
    /// Admission bounds. All three are set together or not at all: an absent
    /// object leaves every bound unchanged, and a present one names all three,
    /// so a single edit can widen, narrow, or clear them together.
    admission: Option<CredentialAdmissionFields>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateProviderBody {
    name: String,
    protocol_type: String,
    endpoint: String,
    upstream_api_key: String,
    status: String,
    /// Admission bounds. Absent on create means unbounded; an explicit null is
    /// the same as absent, because "no bound" is what null already means.
    max_concurrent_requests: Option<u32>,
    max_requests_per_second: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateProviderBody {
    name: Option<String>,
    endpoint: Option<String>,
    upstream_api_key: Option<String>,
    status: Option<String>,
    /// Admission bounds. Both are set together or not at all: an absent object
    /// leaves every bound unchanged, and a present one names both, so a single
    /// edit can widen, narrow, or clear them together.
    admission: Option<ProviderAdmissionFields>,
}

/// The admission bounds a request may name on a provider.
///
/// A bound is a positive count or absent. Zero is refused rather than clamped,
/// because a bound of zero forbids all traffic instead of bounding it, and is
/// never what an operator meant.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderAdmissionFields {
    max_concurrent_requests: Option<u32>,
    max_requests_per_second: Option<u32>,
}

impl ProviderAdmissionFields {
    /// Builds both bounds, refusing a zero or a value beyond the ceiling.
    fn admission(&self) -> Result<ProviderAdmission, InvalidAdmissionBound> {
        ProviderAdmission::new(self.max_concurrent_requests, self.max_requests_per_second)
    }
}

/// The admission bounds a request may name on a credential.
///
/// A bound is a positive count or absent. Zero is refused rather than clamped,
/// because a bound of zero forbids all traffic instead of bounding it, and is
/// never what an operator meant.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialAdmissionFields {
    max_concurrent_requests: Option<u32>,
    max_requests_per_second: Option<u32>,
    max_websockets: Option<u32>,
}

impl CredentialAdmissionFields {
    /// Builds all three bounds, refusing a zero or a value beyond the ceiling.
    fn admission(&self) -> Result<CredentialAdmission, InvalidAdmissionBound> {
        CredentialAdmission::new(
            self.max_concurrent_requests,
            self.max_requests_per_second,
            self.max_websockets,
        )
    }
}

#[derive(Serialize)]
struct SessionView<'a> {
    signed_in: bool,
    csrf_token: &'a str,
    /// The signed-in account, so the page renders only what its role reaches.
    account_name: &'a str,
    role: AccountRole,
}

#[derive(Serialize)]
struct AccountListView {
    items: Vec<AccountAdminView>,
    next_after_id: Option<i64>,
}

#[derive(Serialize)]
struct AccountCreateView {
    account: AccountAdminView,
    /// Present only when the request supplied no password; shown once.
    generated_password: Option<String>,
}

#[derive(Serialize)]
struct ApiKeyListView {
    items: Vec<ApiKeyAdminView>,
    next_after_id: Option<i64>,
}

#[derive(Serialize)]
struct ApiKeyIssueView {
    api_key: ApiKeyAdminView,
    /// The one-time plaintext, present only at creation and rotation.
    api_key_secret: String,
}

#[derive(Serialize)]
struct ProviderListView {
    items: Vec<ProviderAdminView>,
    next_after_id: Option<i64>,
}

#[derive(Serialize)]
struct SettingsListView {
    items: Vec<SettingItemView>,
}

#[derive(Serialize)]
struct SettingItemView {
    name: &'static str,
    label: &'static str,
    value: Option<String>,
    configured: bool,
    secret: bool,
    restart_required: bool,
    pending_restart: bool,
}

fn setting_view(
    spec: &crate::local_state::SettingSpec,
    startup: &Config,
    desired: &Config,
) -> SettingItemView {
    if spec.secret {
        return SettingItemView {
            name: spec.name,
            label: spec.label,
            value: None,
            configured: true,
            secret: true,
            restart_required: spec.restart_required,
            pending_restart: false,
        };
    }
    let desired_map = desired.to_env_map();
    let startup_map = startup.to_env_map();
    let value = desired_map.get(spec.name).cloned();
    let pending_restart = spec.restart_required && startup_map.get(spec.name) != value.as_ref();
    SettingItemView {
        name: spec.name,
        label: spec.label,
        value,
        configured: true,
        secret: false,
        restart_required: spec.restart_required,
        pending_restart,
    }
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
    account_id: i64,
    api_key_id: i64,
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
            account_id: log.account_id().get(),
            api_key_id: log.api_key_id().get(),
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

fn parse_account_page(query: Option<&str>) -> Result<AccountListRequest, ()> {
    let params = unique_query(query, &["after_id", "limit"])?;
    let after_id = params
        .get("after_id")
        .map(|v| parse_positive(v).and_then(|id| AccountCursor::try_from(id).map_err(|_| ())))
        .transpose()?;
    let limit = params
        .get("limit")
        .map(|v| v.parse::<usize>().map_err(|_| ()))
        .transpose()?
        .unwrap_or(100);
    AccountListRequest::new(after_id, limit).map_err(|_| ())
}

fn parse_api_key_page(query: Option<&str>) -> Result<ApiKeyListRequest, ()> {
    let params = unique_query(query, &["after_id", "limit", "account_id"])?;
    let after_id = params
        .get("after_id")
        .map(|v| parse_positive(v).and_then(|id| ApiKeyCursor::try_from(id).map_err(|_| ())))
        .transpose()?;
    let limit = params
        .get("limit")
        .map(|v| v.parse::<usize>().map_err(|_| ()))
        .transpose()?
        .unwrap_or(100);
    let account_id = params
        .get("account_id")
        .map(|v| parse_positive(v).and_then(|id| AccountId::try_from(id).map_err(|_| ())))
        .transpose()?;
    ApiKeyListRequest::new(after_id, limit, account_id).map_err(|_| ())
}

fn parse_log_query(query: Option<&str>) -> Result<RequestLogQuery, ()> {
    let params = unique_query(
        query,
        &[
            "after_id",
            "limit",
            "account_id",
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
    let account_id = params
        .get("account_id")
        .map(|v| parse_positive(v).and_then(|id| AccountId::try_from(id).map_err(|_| ())))
        .transpose()?;
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
    RequestLogQuery::new(after_id, limit, account_id, provider_id, transport, gte, lt)
        .map_err(|_| ())
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

fn parse_account_role(value: &str) -> Option<AccountRole> {
    match value {
        "admin" => Some(AccountRole::Admin),
        "user" => Some(AccountRole::User),
        _ => None,
    }
}

fn parse_account_status(value: &str) -> Option<AccountStatus> {
    match value {
        "enabled" => Some(AccountStatus::Enabled),
        "disabled" => Some(AccountStatus::Disabled),
        _ => None,
    }
}

fn parse_api_key_status(value: &str) -> Option<ApiKeyStatus> {
    match value {
        "enabled" => Some(ApiKeyStatus::Enabled),
        "disabled" => Some(ApiKeyStatus::Disabled),
        _ => None,
    }
}

fn parse_account_id(value: &str) -> AccountId {
    value
        .parse::<i64>()
        .ok()
        .and_then(|id| AccountId::try_from(id).ok())
        .expect("the path parser admitted only positive identifiers")
}

fn parse_api_key_id(value: &str) -> ApiKeyId {
    value
        .parse::<i64>()
        .ok()
        .and_then(|id| ApiKeyId::try_from(id).ok())
        .expect("the path parser admitted only positive identifiers")
}

/// Splits `/admin/api/accounts/{id}` into its identifier.
fn account_item_path(path: &str) -> Option<&str> {
    let id = path.strip_prefix("/admin/api/accounts/")?;
    (!id.is_empty() && !id.contains('/')).then_some(id)
}

/// Splits `/admin/api/api-keys/{id}` and its `:rotate` action.
fn api_key_item_path(path: &str) -> Option<(&str, bool)> {
    let suffix = path.strip_prefix("/admin/api/api-keys/")?;
    let (id, rotate) = match suffix.strip_suffix(":rotate") {
        Some(id) => (id, true),
        None => (suffix, false),
    };
    (!id.is_empty() && !id.contains('/')).then_some((id, rotate))
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

/// The response for a principal that may not reach a surface at all.
///
/// A forbidden surface answers `403` rather than `404`, so a regular user is
/// told the resource exists and is out of reach instead of being misled about
/// whether it exists.
fn forbidden() -> Response<ApiBody> {
    api_error(
        StatusCode::FORBIDDEN,
        "forbidden",
        "This account may not access that resource.",
    )
}

fn method_not_allowed() -> Response<ApiBody> {
    api_error(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "Method not allowed.",
    )
}
