//! Structured process diagnostics and isolated one-time credential delivery.

use std::fmt;
use std::io::{self, Write};
use std::net::SocketAddr;

use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use tracing::field::{Field, Visit};
use tracing::{Event, Metadata, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt as tracing_fmt;
use tracing_subscriber::layer::{Context, Filter};
use tracing_subscriber::prelude::*;

pub const DEFAULT_FILTER: &str = "info";

macro_rules! closed_value {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum $name { $($variant),+ }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $value),+ }
            }

            fn contains(value: &str) -> bool {
                matches!(value, $($value)|+)
            }
        }
    };
}

closed_value!(StartupStage {
    Configuration => "configuration",
    DiagnosticInitialization => "diagnostic_initialization",
    DatabaseConnection => "database_connection",
    Migration => "migration",
    AdministrationAssets => "administration_assets",
    Bootstrap => "bootstrap",
    Runtime => "runtime",
});

closed_value!(StartupErrorKind {
    MissingSetting => "missing_setting",
    InvalidSetting => "invalid_setting",
    SubscriberUnavailable => "subscriber_unavailable",
    StorageUnavailable => "storage_unavailable",
    MigrationFailed => "migration_failed",
    AssetsUnavailable => "assets_unavailable",
    CredentialGenerationFailed => "credential_generation_failed",
    AccountCreationFailed => "account_creation_failed",
    CredentialDeliveryFailed => "credential_delivery_failed",
    ListenerOrRuntimeFailed => "listener_or_runtime_failed",
});

closed_value!(RepositoryBackend {
    Generic => "database",
    Sqlite => "sqlite",
    Postgresql => "postgresql",
});

closed_value!(RepositoryOperation {
    DecodeRequestLog => "decode_request_log",
    ReadQuery => "read_query",
    WriteQuery => "write_query",
    Transaction => "transaction",
});

closed_value!(RepositoryErrorKind {
    InvalidStoredData => "invalid_stored_data",
    Database => "database",
    Protocol => "protocol",
    Io => "io",
    Tls => "tls",
    Decode => "decode",
    PoolClosed => "pool_closed",
    WorkerCrashed => "worker_crashed",
    Unknown => "unknown",
});

#[derive(Clone, Copy, Debug)]
pub struct ConfigFailure<'a> {
    setting: &'a str,
    requirement: Option<&'a str>,
}

impl<'a> ConfigFailure<'a> {
    pub fn sanitized(setting: &'a str, requirement: Option<&'a str>) -> Self {
        Self {
            setting: if is_config_setting(setting) {
                setting
            } else {
                "unknown_setting"
            },
            requirement: requirement.map(|value| {
                if is_config_requirement(value) {
                    value
                } else {
                    "invalid configuration value"
                }
            }),
        }
    }
}

#[derive(Debug)]
pub struct InstallError;

impl fmt::Display for InstallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the process diagnostic subscriber could not be installed")
    }
}

impl std::error::Error for InstallError {}

pub fn validate_filter(value: &str) -> bool {
    EnvFilter::try_new(value).is_ok()
}

pub fn install(filter: &str) -> Result<(), InstallError> {
    let subscriber = subscriber_with_writer(filter, io::stderr)?;
    tracing::subscriber::set_global_default(subscriber).map_err(|_| InstallError)
}

pub fn subscriber_with_writer<W>(
    filter: &str,
    writer: W,
) -> Result<impl tracing::Subscriber + Send + Sync, InstallError>
where
    W: for<'writer> tracing_subscriber::fmt::MakeWriter<'writer> + Send + Sync + 'static,
{
    let filter = EnvFilter::try_new(filter).map_err(|_| InstallError)?;
    Ok(tracing_subscriber::registry().with(
        tracing_fmt::layer()
            .json()
            .with_writer(writer)
            .with_current_span(false)
            .with_span_list(false)
            .with_filter(filter)
            .with_filter(filter_fn(is_diagnostic_metadata))
            .with_filter(DiagnosticEventFilter),
    ))
}

fn is_diagnostic_metadata(metadata: &Metadata<'_>) -> bool {
    matches!(
        metadata.target(),
        "tokenstream::admin"
            | "tokenstream::events"
            | "tokenstream::logging"
            | "tokenstream::persistence"
            | "tokenstream::process"
    ) && metadata.fields().field("event").is_some()
        && metadata.fields().field("message").is_some()
        && metadata.fields().iter().all(|field| {
            matches!(
                field.name(),
                "event"
                    | "message"
                    | "stage"
                    | "error_kind"
                    | "backend"
                    | "operation"
                    | "subscriber"
                    | "data_address"
                    | "control_address"
                    | "configured"
            )
        })
}

#[derive(Clone, Copy, Debug)]
struct DiagnosticEventFilter;

impl<S> Filter<S> for DiagnosticEventFilter
where
    S: Subscriber,
{
    fn enabled(&self, metadata: &Metadata<'_>, _context: &Context<'_, S>) -> bool {
        is_diagnostic_metadata(metadata)
    }

    fn event_enabled(&self, event: &Event<'_>, _context: &Context<'_, S>) -> bool {
        let mut visitor = DiagnosticEventVisitor::new(event.metadata().target());
        event.record(&mut visitor);
        visitor.is_approved()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiagnosticEvent {
    AdministrationRequestFailed,
    BootstrapAccountCreated,
    BootstrapCredentialDelivered,
    DataDirectoryResolved,
    DefaultAdminPasswordEnabled,
    EventSubscriberBatchFailed,
    InvalidRequestLogRow,
    ProcessStartFailed,
    ProcessStarting,
    RepositoryOperationFailed,
    RequestLogBatchFailed,
}

impl DiagnosticEvent {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "administration_request_failed" => Some(Self::AdministrationRequestFailed),
            "bootstrap_account_created" => Some(Self::BootstrapAccountCreated),
            "bootstrap_credential_delivered" => Some(Self::BootstrapCredentialDelivered),
            "data_directory_resolved" => Some(Self::DataDirectoryResolved),
            "default_admin_password_enabled" => Some(Self::DefaultAdminPasswordEnabled),
            "event_subscriber_batch_failed" => Some(Self::EventSubscriberBatchFailed),
            "invalid_request_log_row" => Some(Self::InvalidRequestLogRow),
            "process_start_failed" => Some(Self::ProcessStartFailed),
            "process_starting" => Some(Self::ProcessStarting),
            "repository_operation_failed" => Some(Self::RepositoryOperationFailed),
            "request_log_batch_failed" => Some(Self::RequestLogBatchFailed),
            _ => None,
        }
    }

    fn target(self) -> &'static str {
        match self {
            Self::AdministrationRequestFailed => "tokenstream::admin",
            Self::EventSubscriberBatchFailed => "tokenstream::events",
            Self::RequestLogBatchFailed => "tokenstream::logging",
            Self::InvalidRequestLogRow | Self::RepositoryOperationFailed => {
                "tokenstream::persistence"
            }
            Self::BootstrapAccountCreated
            | Self::BootstrapCredentialDelivered
            | Self::DataDirectoryResolved
            | Self::DefaultAdminPasswordEnabled
            | Self::ProcessStartFailed
            | Self::ProcessStarting => "tokenstream::process",
        }
    }

    fn from_message(message: &str) -> Option<Self> {
        [
            Self::AdministrationRequestFailed,
            Self::BootstrapAccountCreated,
            Self::BootstrapCredentialDelivered,
            Self::DataDirectoryResolved,
            Self::DefaultAdminPasswordEnabled,
            Self::EventSubscriberBatchFailed,
            Self::InvalidRequestLogRow,
            Self::ProcessStartFailed,
            Self::ProcessStarting,
            Self::RepositoryOperationFailed,
            Self::RequestLogBatchFailed,
        ]
        .into_iter()
        .find(|event| event.message() == message)
    }

    fn context_fields(self) -> u16 {
        match self {
            Self::AdministrationRequestFailed => OPERATION | ERROR_KIND,
            Self::BootstrapAccountCreated
            | Self::BootstrapCredentialDelivered
            | Self::DefaultAdminPasswordEnabled => 0,
            Self::DataDirectoryResolved => CONFIGURED,
            Self::EventSubscriberBatchFailed | Self::RequestLogBatchFailed => SUBSCRIBER,
            Self::InvalidRequestLogRow | Self::RepositoryOperationFailed => {
                BACKEND | OPERATION | ERROR_KIND
            }
            Self::ProcessStartFailed => STAGE | ERROR_KIND,
            Self::ProcessStarting => DATA_ADDRESS | CONTROL_ADDRESS,
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::AdministrationRequestFailed => "An administration request failed internally.",
            Self::BootstrapAccountCreated => "The bootstrap administrator account was created.",
            Self::BootstrapCredentialDelivered => {
                "The generated bootstrap credential was delivered on standard output."
            }
            Self::DataDirectoryResolved => "The process data directory is ready.",
            Self::DefaultAdminPasswordEnabled => {
                "The documented default administrator password is enabled and should be changed."
            }
            Self::EventSubscriberBatchFailed => {
                "An event subscriber failed to handle a batch; retry and isolation are bounded."
            }
            Self::InvalidRequestLogRow => "A stored request-log row contains invalid data.",
            Self::ProcessStartFailed => "Tokenstream failed to start.",
            Self::ProcessStarting => "Tokenstream is starting.",
            Self::RepositoryOperationFailed => "A repository operation failed.",
            Self::RequestLogBatchFailed => {
                "A request-log batch write failed; retry and isolation are bounded."
            }
        }
    }
}

struct DiagnosticEventVisitor<'a> {
    target: &'a str,
    event: Option<DiagnosticEvent>,
    message_event: Option<DiagnosticEvent>,
    context_fields: u16,
    stage: Option<String>,
    error_kind: Option<String>,
    backend: Option<String>,
    operation: Option<String>,
    subscriber: Option<String>,
    data_address: Option<bool>,
    control_address: Option<bool>,
    configured: Option<bool>,
    invalid: bool,
}

const STAGE: u16 = 1 << 0;
const ERROR_KIND: u16 = 1 << 1;
const BACKEND: u16 = 1 << 2;
const OPERATION: u16 = 1 << 3;
const SUBSCRIBER: u16 = 1 << 4;
const DATA_ADDRESS: u16 = 1 << 5;
const CONTROL_ADDRESS: u16 = 1 << 6;
const CONFIGURED: u16 = 1 << 7;

impl<'a> DiagnosticEventVisitor<'a> {
    fn new(target: &'a str) -> Self {
        Self {
            target,
            event: None,
            message_event: None,
            context_fields: 0,
            stage: None,
            error_kind: None,
            backend: None,
            operation: None,
            subscriber: None,
            data_address: None,
            control_address: None,
            configured: None,
            invalid: false,
        }
    }

    fn is_approved(&self) -> bool {
        self.event.is_some_and(|event| {
            event.target() == self.target
                && self.message_event == Some(event)
                && self.context_fields == event.context_fields()
                && self.values_are_approved(event)
        }) && !self.invalid
    }

    fn values_are_approved(&self, event: DiagnosticEvent) -> bool {
        fn value(field: &Option<String>) -> Option<&str> {
            field.as_deref()
        }
        match event {
            DiagnosticEvent::AdministrationRequestFailed => {
                value(&self.operation) == Some("request")
                    && value(&self.error_kind) == Some("internal")
            }
            DiagnosticEvent::BootstrapAccountCreated
            | DiagnosticEvent::BootstrapCredentialDelivered
            | DiagnosticEvent::DefaultAdminPasswordEnabled => true,
            DiagnosticEvent::DataDirectoryResolved => self.configured.is_some(),
            DiagnosticEvent::EventSubscriberBatchFailed
            | DiagnosticEvent::RequestLogBatchFailed => {
                value(&self.subscriber) == Some("request_log")
            }
            DiagnosticEvent::InvalidRequestLogRow => {
                value(&self.backend) == Some("database")
                    && value(&self.operation) == Some("decode_request_log")
                    && value(&self.error_kind) == Some("invalid_stored_data")
            }
            DiagnosticEvent::RepositoryOperationFailed => {
                matches!(value(&self.backend), Some("sqlite" | "postgresql"))
                    && matches!(
                        value(&self.operation),
                        Some("read_query" | "write_query" | "transaction")
                    )
                    && matches!(
                        value(&self.error_kind),
                        Some(
                            "database"
                                | "protocol"
                                | "io"
                                | "tls"
                                | "decode"
                                | "pool_closed"
                                | "worker_crashed"
                                | "unknown"
                        )
                    )
            }
            DiagnosticEvent::ProcessStartFailed => {
                matches!(
                    (value(&self.stage), value(&self.error_kind)),
                    (
                        Some("configuration"),
                        Some("missing_setting" | "invalid_setting")
                    ) | (
                        Some("diagnostic_initialization"),
                        Some("subscriber_unavailable")
                    ) | (Some("database_connection"), Some("storage_unavailable"))
                        | (Some("migration"), Some("migration_failed"))
                        | (Some("administration_assets"), Some("assets_unavailable"))
                        | (
                            Some("bootstrap"),
                            Some(
                                "credential_generation_failed"
                                    | "account_creation_failed"
                                    | "credential_delivery_failed"
                            )
                        )
                        | (Some("runtime"), Some("listener_or_runtime_failed"))
                )
            }
            DiagnosticEvent::ProcessStarting => {
                self.data_address == Some(true) && self.control_address == Some(true)
            }
        }
    }

    fn record_context(&mut self, field: &Field) {
        let field = match field.name() {
            "stage" => STAGE,
            "error_kind" => ERROR_KIND,
            "backend" => BACKEND,
            "operation" => OPERATION,
            "subscriber" => SUBSCRIBER,
            "data_address" => DATA_ADDRESS,
            "control_address" => CONTROL_ADDRESS,
            "configured" => CONFIGURED,
            _ => {
                self.invalid = true;
                return;
            }
        };
        self.context_fields |= field;
    }
}

impl Visit for DiagnosticEventVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "event" => self.event = DiagnosticEvent::from_name(value),
            "message" => self.message_event = DiagnosticEvent::from_message(value),
            "stage" => {
                self.record_context(field);
                self.stage = StartupStage::contains(value).then(|| value.to_owned());
            }
            "error_kind" => {
                self.record_context(field);
                self.error_kind = (matches!(value, "internal")
                    || StartupErrorKind::contains(value)
                    || RepositoryErrorKind::contains(value))
                .then(|| value.to_owned());
            }
            "backend" => {
                self.record_context(field);
                self.backend = RepositoryBackend::contains(value).then(|| value.to_owned());
            }
            "operation" => {
                self.record_context(field);
                self.operation = (matches!(value, "request")
                    || RepositoryOperation::contains(value))
                .then(|| value.to_owned());
            }
            "subscriber" => {
                self.record_context(field);
                self.subscriber = (value == "request_log").then(|| value.to_owned());
            }
            "data_address" => {
                self.record_context(field);
                self.data_address = Some(value.parse::<SocketAddr>().is_ok());
            }
            "control_address" => {
                self.record_context(field);
                self.control_address = Some(value.parse::<SocketAddr>().is_ok());
            }
            _ => {
                self.record_context(field);
                self.invalid = true;
            }
        }
    }

    fn record_debug(&mut self, field: &Field, _value: &dyn fmt::Debug) {
        self.record_context(field);
        self.invalid = true;
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_context(field);
        if field.name() == "configured" {
            self.configured = Some(value);
        } else {
            self.invalid = true;
        }
    }

    fn record_i64(&mut self, field: &Field, _value: i64) {
        self.record_context(field);
        self.invalid = true;
    }

    fn record_u64(&mut self, field: &Field, _value: u64) {
        self.record_context(field);
        self.invalid = true;
    }
}

#[derive(Serialize)]
struct FallbackFields<'a> {
    event: &'static str,
    message: &'static str,
    stage: &'a str,
    error_kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    setting: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requirement: Option<&'a str>,
}

#[derive(Serialize)]
struct FallbackEvent<'a> {
    timestamp: String,
    level: &'static str,
    target: &'static str,
    fields: FallbackFields<'a>,
}

pub fn write_fatal(
    stage: StartupStage,
    error_kind: StartupErrorKind,
    config: Option<ConfigFailure<'_>>,
) -> io::Result<()> {
    write_fatal_to(io::stderr().lock(), stage, error_kind, config)
}

pub fn write_fatal_to(
    mut writer: impl Write,
    stage: StartupStage,
    error_kind: StartupErrorKind,
    config: Option<ConfigFailure<'_>>,
) -> io::Result<()> {
    let event = FallbackEvent {
        timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true),
        level: "ERROR",
        target: "tokenstream::process",
        fields: FallbackFields {
            event: "process_start_failed",
            message: "Tokenstream failed to start.",
            stage: stage.as_str(),
            error_kind: error_kind.as_str(),
            setting: config.map(|value| value.setting),
            requirement: config.and_then(|value| value.requirement),
        },
    };
    serde_json::to_writer(&mut writer, &event)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

pub fn repository_operation_failed(
    backend: RepositoryBackend,
    operation: RepositoryOperation,
    error_kind: RepositoryErrorKind,
) {
    tracing::error!(
        target: "tokenstream::persistence",
        event = "repository_operation_failed",
        message = "A repository operation failed.",
        backend = backend.as_str(),
        operation = operation.as_str(),
        error_kind = error_kind.as_str(),
    );
}

fn is_config_setting(value: &str) -> bool {
    matches!(
        value,
        "TOKENSTREAM_ADMIN_BODY_TIMEOUT_MS"
            | "TOKENSTREAM_ADMIN_DB_TIMEOUT_MS"
            | "TOKENSTREAM_ADMIN_LISTEN_ADDR"
            | "TOKENSTREAM_ADMIN_MAX_CONNECTIONS"
            | "TOKENSTREAM_ADMIN_PASSWORD"
            | "TOKENSTREAM_ADMIN_PASSWORD_CONCURRENCY"
            | "TOKENSTREAM_ADMIN_PASSWORD_HASH"
            | "TOKENSTREAM_ADMIN_SESSION_TTL_MS"
            | "TOKENSTREAM_AUTH_DATABASE_CONNECTIONS"
            | "TOKENSTREAM_AUTH_DB_TIMEOUT_MS"
            | "TOKENSTREAM_BOOTSTRAP_ACCOUNT"
            | "TOKENSTREAM_DATABASE_MAX_CONNECTIONS"
            | "TOKENSTREAM_DATABASE_URL"
            | "TOKENSTREAM_DATA_DIR"
            | "TOKENSTREAM_DATA_LISTEN_ADDR"
            | "TOKENSTREAM_DATA_MAX_CONNECTIONS"
            | "TOKENSTREAM_DEVELOPMENT_MODE"
            | "TOKENSTREAM_DOWNSTREAM_HEADER_TIMEOUT_MS"
            | "TOKENSTREAM_HTTP_BUFFER_BYTES"
            | "TOKENSTREAM_LOG_BATCH_INTERVAL_MS"
            | "TOKENSTREAM_LOG_BATCH_SIZE"
            | "TOKENSTREAM_LOG_DB_TIMEOUT_MS"
            | "TOKENSTREAM_LOG_FILTER"
            | "TOKENSTREAM_LOG_FLUSH_TIMEOUT_MS"
            | "TOKENSTREAM_LOG_QUEUE_CAPACITY"
            | "TOKENSTREAM_MASTER_KEY"
            | "TOKENSTREAM_MAX_PROXY_CONNECTIONS"
            | "TOKENSTREAM_PASSWORD_MAX_CONCURRENCY"
            | "TOKENSTREAM_SHUTDOWN_DRAIN_TIMEOUT_MS"
            | "TOKENSTREAM_STREAM_IDLE_TIMEOUT_MS"
            | "TOKENSTREAM_UPSTREAM_CONNECT_TIMEOUT_MS"
            | "TOKENSTREAM_UPSTREAM_HEADER_TIMEOUT_MS"
            | "TOKENSTREAM_UPSTREAM_IDLE_PER_HOST"
            | "TOKENSTREAM_UPSTREAM_POOL_IDLE_TIMEOUT_MS"
            | "TOKENSTREAM_WEBSOCKET_MAX_FRAME_BYTES"
            | "TOKENSTREAM_WEBSOCKET_MAX_MESSAGE_BYTES"
            | "TOKENSTREAM_WEBSOCKET_QUEUE_CAPACITY"
    )
}

fn is_config_requirement(value: &str) -> bool {
    matches!(
        value,
        "must be non-empty when present"
            | "must contain valid Unicode"
            | "has an invalid format"
            | "must be either true or false"
            | "must be a positive integer"
            | "is outside the supported range"
            | "must be an integer number of milliseconds"
            | "is outside the supported timeout range"
            | "must contain a non-empty SQLite path"
            | "must be a SQLite or PostgreSQL URL"
            | "must be exactly 32 bytes encoded as 64 hexadecimal characters"
            | "must be a valid Argon2id password hash"
            | "must be a short, non-empty account name"
            | "must be a valid tracing filter directive"
            | "must differ from TOKENSTREAM_DATA_LISTEN_ADDR"
            | "must not exceed TOKENSTREAM_LOG_QUEUE_CAPACITY"
            | "must not exceed TOKENSTREAM_WEBSOCKET_MAX_MESSAGE_BYTES"
    )
}

#[derive(Serialize)]
struct BootstrapCredential<'a> {
    record: &'static str,
    password: &'a str,
}

pub fn write_bootstrap_password(password: &str) -> io::Result<()> {
    write_bootstrap_password_to(io::stdout().lock(), password)
}

pub fn write_bootstrap_password_to(mut writer: impl Write, password: &str) -> io::Result<()> {
    serde_json::to_writer(
        &mut writer,
        &BootstrapCredential {
            record: "tokenstream_bootstrap_credential",
            password,
        },
    )?;
    writer.write_all(b"\n")?;
    writer.flush()
}

#[cfg(test)]
pub(crate) fn capture_for_test(run: impl FnOnce()) -> String {
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("diagnostic output lock").write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let output = Arc::new(Mutex::new(Vec::new()));
    let writer = {
        let output = output.clone();
        move || Buffer(output.clone())
    };
    let subscriber = subscriber_with_writer("trace", writer).expect("test subscriber");
    tracing::subscriber::with_default(subscriber, run);
    let bytes = output.lock().expect("diagnostic output lock").clone();
    String::from_utf8(bytes).expect("UTF-8 diagnostic output")
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use serde_json::Value;

    use super::*;

    #[test]
    fn validates_default_and_target_filters() {
        assert!(validate_filter(DEFAULT_FILTER));
        assert!(validate_filter("tokenstream=debug,sqlx=warn"));
        assert!(!validate_filter("not a filter ["));
    }

    #[test]
    fn fallback_has_the_process_envelope_and_never_accepts_an_error_value() {
        let mut output = Vec::new();
        write_fatal_to(
            &mut output,
            StartupStage::Configuration,
            StartupErrorKind::InvalidSetting,
            Some(ConfigFailure::sanitized(
                "TOKENSTREAM_LOG_FILTER",
                Some("must be a valid tracing filter directive"),
            )),
        )
        .expect("write fallback event");
        let text = String::from_utf8(output).expect("UTF-8 diagnostic");
        assert_eq!(text.lines().count(), 1);
        let value: Value = serde_json::from_str(text.trim()).expect("JSON diagnostic");
        assert!(value["timestamp"].is_string());
        assert_eq!(value["level"], "ERROR");
        assert_eq!(value["target"], "tokenstream::process");
        assert_eq!(value["fields"]["event"], "process_start_failed");
        assert_eq!(value["fields"]["stage"], "configuration");
    }

    #[test]
    fn fallback_sanitizes_unrecognized_configuration_context() {
        let secret = "Bearer hostile-secret?payload=fallback";
        let mut output = Vec::new();
        write_fatal_to(
            &mut output,
            StartupStage::Configuration,
            StartupErrorKind::InvalidSetting,
            Some(ConfigFailure::sanitized(secret, Some(secret))),
        )
        .expect("write fallback event");
        let text = String::from_utf8(output).expect("UTF-8 diagnostic");
        let value: Value = serde_json::from_str(text.trim()).expect("JSON diagnostic");
        assert_eq!(value["fields"]["setting"], "unknown_setting");
        assert_eq!(
            value["fields"]["requirement"],
            "invalid configuration value"
        );
        assert!(!text.contains(secret));
    }

    #[test]
    fn migration_exit_emits_only_closed_failure_context() {
        let mut output = Vec::new();
        write_fatal_to(
            &mut output,
            StartupStage::Migration,
            StartupErrorKind::MigrationFailed,
            None,
        )
        .expect("write migration failure");
        let event: Value = serde_json::from_slice(&output).expect("migration diagnostic");
        assert_eq!(event["fields"]["event"], "process_start_failed");
        assert_eq!(event["fields"]["stage"], "migration");
        assert_eq!(event["fields"]["error_kind"], "migration_failed");
    }

    #[test]
    fn audited_boolean_context_keeps_its_recorded_value() {
        let output = capture_for_test(|| {
            tracing::info!(
                target: "tokenstream::process",
                event = "data_directory_resolved",
                message = "The process data directory is ready.",
                configured = false,
            );
        });
        let event: Value = serde_json::from_str(output.trim()).expect("JSON diagnostic");
        assert_eq!(event["fields"]["event"], "data_directory_resolved");
        assert_eq!(event["fields"]["configured"], false);
    }

    #[test]
    fn bootstrap_password_uses_its_own_machine_readable_record() {
        let mut output = Vec::new();
        write_bootstrap_password_to(&mut output, "one-time-secret")
            .expect("write credential record");
        let value: Value = serde_json::from_slice(&output).expect("JSON credential record");
        assert_eq!(value["record"], "tokenstream_bootstrap_credential");
        assert_eq!(value["password"], "one-time-secret");
    }

    #[test]
    fn local_subscriber_writes_one_filtered_json_envelope() {
        #[derive(Clone)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);

        impl Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().expect("output lock").write(bytes)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let output = Arc::new(Mutex::new(Vec::new()));
        let writer = {
            let output = output.clone();
            move || Buffer(output.clone())
        };
        let subscriber =
            subscriber_with_writer("trace,sqlx=trace", writer).expect("local subscriber");
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(
                target: "sqlx::query",
                event = "sqlx_query",
                message = "SELECT secret FROM credentials",
                db.statement = "SELECT secret FROM credentials"
            );
            tracing::warn!(
                target: "tokenstream::process",
                event = "unknown_event",
                message = "Bearer hostile-secret",
                operation = "hostile"
            );
            tracing::error!(
                target: "tokenstream::persistence",
                event = "repository_operation_failed",
                message = "A repository operation failed.",
                backend = "sqlite",
                operation = "Bearer hostile-secret",
                error_kind = "database",
            );
            tracing::debug!(
                target: "tokenstream::process",
                event = "process_starting",
                message = "Tokenstream is starting.",
                data_address = "127.0.0.1:3300",
                control_address = "127.0.0.1:3301"
            );
        });
        let bytes = output.lock().expect("output lock").clone();
        let text = String::from_utf8(bytes).expect("UTF-8 diagnostics");
        assert_eq!(text.lines().count(), 1);
        let event: Value = serde_json::from_str(text.trim()).expect("JSON diagnostic");
        let keys = event
            .as_object()
            .expect("diagnostic object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(keys, ["fields", "level", "target", "timestamp"].into());
        assert_eq!(event["target"], "tokenstream::process");
        assert_eq!(event["fields"]["event"], "process_starting");
        assert_eq!(event["fields"]["message"], "Tokenstream is starting.");
        assert!(!text.contains("SELECT"));
        assert!(!text.contains("hostile-secret"));
    }
}
