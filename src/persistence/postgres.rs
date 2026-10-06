use std::io;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool, Postgres, QueryBuilder, Row};

use crate::MigrationRunner;
use crate::domain::{
    Account, AccountId, ApiKeyBinding, ApiKeyId, ApiKeyWithBindings, GatewayKeyId, ModelAliasId,
    ModelAliasTarget, ModelAliasWithTargets, PasswordHash, Provider, ProviderHealthState,
    ProviderId,
};
use crate::logging::LogEvent;

use super::time::to_epoch_micros;
use super::{
    AccountListRequest, AccountPage, AccountRepository, AccountRow, AccountUpdate,
    ApiKeyBindingRow, ApiKeyListRequest, ApiKeyPage, ApiKeyRepository, ApiKeyRow, ApiKeyUpdate,
    DatabaseBounds, HealthOutcome, ModelAliasListRequest, ModelAliasPage, ModelAliasRepository,
    ModelAliasRow, ModelAliasTargetRow, ModelAliasUpdate, NewAccount, NewApiKey, NewModelAlias,
    NewProvider, ProviderListRequest, ProviderPage, ProviderRepository, ProviderRow,
    ProviderUpdate, RepositoryError, RequestLogCompleted, RequestLogPage, RequestLogQuery,
    RequestLogRepository, RequestLogRow, RequestLogStarted, account_status_value, admission_count,
    api_key_status_value, diagnostic_error_kind, health_name, probe_columns, protocol_value,
    role_value, status_value, timed, transport_value,
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

/// Deadline for one statement that runs inside a caller's transaction.
///
/// A transaction already holds its pooled connection, so this bounds the
/// statement rather than an acquisition, and matches the connection's own busy
/// timeout. A rollback releases the connection immediately.
const BINDING_WRITE_DEADLINE: Duration = Duration::from_secs(5);

const WRITE_OPERATION: crate::diagnostics::RepositoryOperation =
    crate::diagnostics::RepositoryOperation::WriteQuery;

#[derive(Clone, Debug)]
pub struct PostgresDatabase {
    auth: PgPool,
    shared: PgPool,
    auth_timeout: Duration,
    admin_timeout: Duration,
    log_timeout: Duration,
}

impl PostgresDatabase {
    pub async fn connect(database_url: &str, max_connections: usize) -> Result<Self, sqlx::Error> {
        Self::connect_with_bounds(database_url, DatabaseBounds::for_tests(max_connections)).await
    }

    /// Connects with an explicit pooled-connection count and acquisition deadline.
    ///
    /// The connection count is a hard upper bound; the deadline bounds how long a
    /// caller waits when every connection is busy before failing closed.
    pub async fn connect_with_acquire_timeout(
        database_url: &str,
        max_connections: usize,
        acquire_timeout: Duration,
    ) -> Result<Self, sqlx::Error> {
        let mut bounds = DatabaseBounds::for_tests(max_connections);
        bounds.acquire_timeout = acquire_timeout;
        Self::connect_with_bounds(database_url, bounds).await
    }

    pub async fn connect_with_bounds(
        database_url: &str,
        bounds: DatabaseBounds,
    ) -> Result<Self, sqlx::Error> {
        let auth_connections = bounds.auth_connections.min(bounds.max_connections).max(1);
        let partitioned = auth_connections < bounds.max_connections;
        let shared_connections = if partitioned {
            bounds.max_connections - auth_connections
        } else {
            bounds.max_connections
        };
        let auth_acquire = bounds.auth_timeout.min(bounds.acquire_timeout);
        let shared_acquire = bounds
            .acquire_timeout
            .min(bounds.admin_timeout.max(bounds.log_timeout));
        let auth = connect_pool(
            database_url,
            auth_connections,
            auth_acquire,
            bounds.auth_timeout,
        )
        .await?;
        let shared = if partitioned {
            connect_pool(
                database_url,
                shared_connections,
                shared_acquire,
                bounds.admin_timeout.max(bounds.log_timeout),
            )
            .await?
        } else {
            auth.clone()
        };
        Ok(Self {
            auth,
            shared,
            auth_timeout: bounds.auth_timeout,
            admin_timeout: bounds.admin_timeout,
            log_timeout: bounds.log_timeout,
        })
    }

    pub fn pool(&self) -> &PgPool {
        &self.shared
    }

    pub fn auth_pool(&self) -> &PgPool {
        &self.auth
    }

    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        MIGRATOR.run(&self.shared).await
    }

    /// Persists one logger batch atomically so retry never observes a partial batch.
    pub(crate) async fn write_log_batch(&self, events: &[LogEvent]) -> Result<(), RepositoryError> {
        match tokio::time::timeout(self.log_timeout, self.write_log_batch_inner(events)).await {
            Ok(result) => result,
            Err(_) => Err(RepositoryError::Timeout),
        }
    }

    async fn write_log_batch_inner(&self, events: &[LogEvent]) -> Result<(), RepositoryError> {
        let mut transaction = self.shared.begin().await.map_err(map_transaction_error)?;
        for event in events {
            match event {
                LogEvent::Started(event) => {
                    sqlx::query(
                        "INSERT INTO ts_request_log (
                             request_id, account_id, api_key_id, provider_id, protocol_type,
                             transport_type, path, start_time
                         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                    )
                    .bind(event.request_id().as_str())
                    .bind(event.account_id().get())
                    .bind(event.api_key_id().get())
                    .bind(event.provider_id().get())
                    .bind(protocol_value(event.protocol_type()))
                    .bind(transport_value(event.transport_type()))
                    .bind(event.path())
                    .bind(to_epoch_micros(event.start_time()))
                    .execute(&mut *transaction)
                    .await
                    .map_err(|error| map_write_error(error, WRITE_OPERATION))?;
                }
                LogEvent::Completed(event) => {
                    sqlx::query(
                        "UPDATE ts_request_log
                         SET status_code = $1, end_time = $2, error_msg = $3
                         WHERE request_id = $4 AND end_time IS NULL",
                    )
                    .bind(event.status_code().map(i64::from))
                    .bind(to_epoch_micros(event.end_time()))
                    .bind(event.error_msg())
                    .bind(event.request_id().as_str())
                    .execute(&mut *transaction)
                    .await
                    .map_err(map_write_storage_error)?;
                }
            }
        }
        transaction.commit().await.map_err(map_transaction_error)
    }
}

async fn connect_pool(
    database_url: &str,
    max_connections: usize,
    acquire_timeout: Duration,
    statement_timeout: Duration,
) -> Result<PgPool, sqlx::Error> {
    let statement_timeout_ms = statement_timeout.as_millis();
    PgPoolOptions::new()
        .max_connections(max_connections as u32)
        .acquire_timeout(acquire_timeout)
        .after_connect(move |connection, _metadata| {
            Box::pin(async move {
                let sql = format!("SET statement_timeout = '{statement_timeout_ms}ms'");
                connection.execute(sql.as_str()).await?;
                Ok(())
            })
        })
        .connect(database_url)
        .await
}

impl MigrationRunner for PostgresDatabase {
    async fn run(&self) -> io::Result<()> {
        self.migrate().await.map_err(io::Error::other)
    }
}

impl ProviderRepository for PostgresDatabase {
    async fn find_by_id(&self, id: ProviderId) -> Result<Option<Provider>, RepositoryError> {
        timed(
            self.admin_timeout,
            sqlx::query_as::<_, ProviderRow>(
                "SELECT id, name, protocol_type, endpoint, upstream_api_key_ciphertext,
                    status, health, probe_path, probe_interval_ms, probe_timeout_ms, probe_failure_threshold, max_concurrent_requests, max_requests_per_second, created_at
             FROM ts_provider
             WHERE id = $1",
            )
            .bind(id.get())
            .fetch_optional(&self.shared),
        )
        .await
        .map_err(map_read_error)?
        .map(ProviderRow::into_provider)
        .transpose()
    }

    async fn list(&self, request: ProviderListRequest) -> Result<ProviderPage, RepositoryError> {
        let after_id = request.after_id().map_or(0, |cursor| cursor.get());
        let fetch_limit =
            i64::try_from(request.limit() + 1).expect("bounded provider page size fits in i64");
        let mut rows = timed(
            self.admin_timeout,
            sqlx::query_as::<_, ProviderRow>(
                "SELECT id, name, protocol_type, endpoint, upstream_api_key_ciphertext,
                    status, health, probe_path, probe_interval_ms, probe_timeout_ms, probe_failure_threshold, max_concurrent_requests, max_requests_per_second, created_at
             FROM ts_provider
             WHERE id > $1
             ORDER BY id ASC
             LIMIT $2",
            )
            .bind(after_id)
            .bind(fetch_limit)
            .fetch_all(&self.shared),
        )
        .await
        .map_err(map_read_error)?;
        let has_more = rows.len() > request.limit();
        rows.truncate(request.limit());
        let items = rows
            .into_iter()
            .map(ProviderRow::into_provider)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ProviderPage::new(items, has_more))
    }

    async fn create(&self, provider: NewProvider) -> Result<Provider, RepositoryError> {
        // Read the bounds before the record is partially moved into the binds.
        let max_concurrent_requests =
            admission_count(provider.admission().max_concurrent_requests());
        let max_requests_per_second =
            admission_count(provider.admission().max_requests_per_second());
        // The probe is stored as its path and its three numbers rather than as
        // the URL it resolved to, so the row stays origin-relative.
        let probe = provider.probe().map(probe_columns).transpose()?;
        timed(
            self.admin_timeout,
            sqlx::query_as::<_, ProviderRow>(
                "INSERT INTO ts_provider (
                 name, protocol_type, endpoint, upstream_api_key_ciphertext, status,
                 max_concurrent_requests, max_requests_per_second,
                 probe_path, probe_interval_ms, probe_timeout_ms, probe_failure_threshold,
                 created_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             RETURNING id, name, protocol_type, endpoint, upstream_api_key_ciphertext,
                       status, health, probe_path, probe_interval_ms, probe_timeout_ms, probe_failure_threshold, max_concurrent_requests, max_requests_per_second, created_at",
            )
            .bind(provider.name)
            .bind(protocol_value(provider.protocol_type))
            .bind(provider.endpoint.as_str())
            .bind(provider.upstream_api_key_ciphertext.expose())
            .bind(status_value(provider.status))
            .bind(max_concurrent_requests)
            .bind(max_requests_per_second)
            .bind(probe.as_ref().map(|probe| probe.path.clone()))
            .bind(probe.as_ref().map(|probe| probe.interval_ms))
            .bind(probe.as_ref().map(|probe| probe.timeout_ms))
            .bind(probe.as_ref().map(|probe| probe.failure_threshold))
            .bind(to_epoch_micros(provider.created_at))
            .fetch_one(&self.shared),
        )
        .await
        .map_err(|error| map_write_error(error, WRITE_OPERATION))?
        .into_provider()
    }

    /// Writes only the named fields and returns the complete reloaded row.
    ///
    /// The `SET` clause is built from the change set itself, so a column the
    /// caller did not name keeps its stored value in the same statement.
    /// Writes only the named fields and returns the complete reloaded row.
    ///
    /// The `SET` clause is built from the change set itself, so a column the
    /// caller did not name keeps its stored value in the same statement. No
    /// gateway key column is writable through this path, so a configuration
    /// edit can never restore a rotated credential.
    async fn update(
        &self,
        id: ProviderId,
        update: ProviderUpdate,
    ) -> Result<Provider, RepositoryError> {
        if update.is_empty() {
            return Err(RepositoryError::NoFieldsToUpdate);
        }
        let mut builder = QueryBuilder::<Postgres>::new("UPDATE ts_provider SET ");
        {
            let mut assignments = builder.separated(", ");
            if let Some(name) = update.name() {
                assignments.push("name = ").push_bind_unseparated(name);
            }
            if let Some(endpoint) = update.endpoint() {
                assignments
                    .push("endpoint = ")
                    .push_bind_unseparated(endpoint.as_str());
            }
            if let Some(ciphertext) = update.upstream_api_key_ciphertext() {
                assignments
                    .push("upstream_api_key_ciphertext = ")
                    .push_bind_unseparated(ciphertext.expose());
            }
            if let Some(status) = update.status() {
                assignments
                    .push("status = ")
                    .push_bind_unseparated(status_value(status));
            }
            if let Some(admission) = update.admission() {
                assignments
                    .push("max_concurrent_requests = ")
                    .push_bind_unseparated(admission_count(admission.max_concurrent_requests()));
                assignments
                    .push("max_requests_per_second = ")
                    .push_bind_unseparated(admission_count(admission.max_requests_per_second()));
            }
            // A probe edit writes or clears all four columns together, so the
            // stored row can never hold a path without the numbers that make it
            // decidable.
            if let Some(probe) = update.probe() {
                let columns = probe.map(probe_columns).transpose()?;
                if columns.is_none() {
                    // Removing observation must not strand a provider in the
                    // probe-derived isolated state. Maintenance is manual and
                    // remains in force until the operator closes it.
                    assignments.push(
                        "health = CASE WHEN health = 'isolated' THEN 'healthy' ELSE health END",
                    );
                }
                assignments
                    .push("probe_path = ")
                    .push_bind_unseparated(columns.as_ref().map(|columns| columns.path.clone()));
                assignments
                    .push("probe_interval_ms = ")
                    .push_bind_unseparated(columns.as_ref().map(|columns| columns.interval_ms));
                assignments
                    .push("probe_timeout_ms = ")
                    .push_bind_unseparated(columns.as_ref().map(|columns| columns.timeout_ms));
                assignments
                    .push("probe_failure_threshold = ")
                    .push_bind_unseparated(
                        columns.as_ref().map(|columns| columns.failure_threshold),
                    );
            }
        }
        builder.push(" WHERE id = ").push_bind(id.get());
        builder.push(
            " RETURNING id, name, protocol_type, endpoint, upstream_api_key_ciphertext,
                      status, health, probe_path, probe_interval_ms, probe_timeout_ms, probe_failure_threshold, max_concurrent_requests, max_requests_per_second, created_at",
        );
        timed(
            self.admin_timeout,
            builder
                .build_query_as::<ProviderRow>()
                .fetch_optional(&self.shared),
        )
        .await
        .map_err(|error| map_write_error(error, WRITE_OPERATION))?
        .ok_or(RepositoryError::NotFound)?
        .into_provider()
    }

    async fn delete(&self, id: ProviderId) -> Result<(), RepositoryError> {
        let result = timed(
            self.admin_timeout,
            sqlx::query("DELETE FROM ts_provider WHERE id = $1")
                .bind(id.get())
                .execute(&self.shared),
        )
        .await
        .map_err(|error| {
            if is_provider_reference_violation(&error) {
                RepositoryError::ProviderInUse
            } else {
                map_write_storage_error(error)
            }
        })?;
        if result.rows_affected() == 0 {
            Err(RepositoryError::NotFound)
        } else {
            Ok(())
        }
    }

    /// Moves a provider between health states, only from the state the caller
    /// observed.
    ///
    /// A conditional write rather than a blind one: two probes observing the
    /// same provider, or a probe racing an operator closing a maintenance
    /// window, must not silently overwrite each other. A caller whose
    /// expectation no longer holds is told the current state instead, so it can
    /// decide again from what is actually stored.
    async fn set_health(
        &self,
        id: ProviderId,
        expected: ProviderHealthState,
        health: ProviderHealthState,
    ) -> Result<HealthOutcome, RepositoryError> {
        if expected == health {
            return Ok(HealthOutcome::Unchanged(health));
        }
        let result = timed(
            self.admin_timeout,
            sqlx::query("UPDATE ts_provider SET health = $1 WHERE id = $2 AND health = $3")
                .bind(health_name(health))
                .bind(id.get())
                .bind(health_name(expected))
                .execute(&self.shared),
        )
        .await
        .map_err(map_write_storage_error)?;
        if result.rows_affected() == 0 {
            // Either the provider is gone or its state moved under this caller.
            // Either way the expectation no longer holds, and reporting the
            // state now stored is more useful to a probe than a bare conflict.
            return match ProviderRepository::find_by_id(self, id).await? {
                Some(provider) => Ok(HealthOutcome::Moved(provider.health())),
                None => Err(RepositoryError::NotFound),
            };
        }
        Ok(HealthOutcome::Applied(health))
    }
}

impl RequestLogRepository for PostgresDatabase {
    async fn insert_started(&self, event: RequestLogStarted) -> Result<(), RepositoryError> {
        timed(
            self.log_timeout,
            sqlx::query(
                "INSERT INTO ts_request_log (
                 request_id, account_id, api_key_id, provider_id, protocol_type,
                 transport_type, path, start_time
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(event.request_id.as_str())
            .bind(event.account_id.get())
            .bind(event.api_key_id.get())
            .bind(event.provider_id.get())
            .bind(protocol_value(event.protocol_type))
            .bind(transport_value(event.transport_type))
            .bind(event.path)
            .bind(to_epoch_micros(event.start_time))
            .execute(&self.shared),
        )
        .await
        .map_err(|error| map_write_error(error, WRITE_OPERATION))?;
        Ok(())
    }

    async fn apply_completed(&self, event: RequestLogCompleted) -> Result<(), RepositoryError> {
        timed(
            self.log_timeout,
            sqlx::query(
                "UPDATE ts_request_log
             SET status_code = $1, end_time = $2, error_msg = $3
             WHERE request_id = $4 AND end_time IS NULL",
            )
            .bind(event.status_code.map(i64::from))
            .bind(to_epoch_micros(event.end_time))
            .bind(event.error_msg)
            .bind(event.request_id.as_str())
            .execute(&self.shared),
        )
        .await
        .map_err(map_write_storage_error)?;
        Ok(())
    }

    async fn query(&self, query: RequestLogQuery) -> Result<RequestLogPage, RepositoryError> {
        let mut statement = QueryBuilder::<Postgres>::new(
            "SELECT id, request_id, account_id, api_key_id, provider_id, protocol_type,
                    transport_type, path, status_code::BIGINT AS status_code,
                    start_time, end_time, error_msg
             FROM ts_request_log
             WHERE id > ",
        );
        statement.push_bind(query.after_id().map_or(0, |cursor| cursor.get()));
        if let Some(account_id) = query.account_id() {
            statement
                .push(" AND account_id = ")
                .push_bind(account_id.get());
        }
        if let Some(provider_id) = query.provider_id() {
            statement
                .push(" AND provider_id = ")
                .push_bind(provider_id.get());
        }
        if let Some(transport_type) = query.transport_type() {
            statement
                .push(" AND transport_type = ")
                .push_bind(transport_value(transport_type));
        }
        if let Some(start_time) = query.start_time_gte() {
            statement
                .push(" AND start_time >= ")
                .push_bind(to_epoch_micros(start_time));
        }
        if let Some(start_time) = query.start_time_lt() {
            statement
                .push(" AND start_time < ")
                .push_bind(to_epoch_micros(start_time));
        }
        statement.push(" ORDER BY id ASC LIMIT ").push_bind(
            i64::try_from(query.limit() + 1).expect("bounded request log page size fits in i64"),
        );

        let mut rows = timed(
            self.admin_timeout,
            statement
                .build_query_as::<RequestLogRow>()
                .fetch_all(&self.shared),
        )
        .await
        .map_err(map_read_error)?;
        let has_more = rows.len() > query.limit();
        rows.truncate(query.limit());
        let items = rows
            .into_iter()
            .map(RequestLogRow::into_request_log)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RequestLogPage::new(items, has_more))
    }
}

impl AccountRepository for PostgresDatabase {
    async fn find_bootstrap(&self) -> Result<Option<Account>, RepositoryError> {
        timed(
            self.auth_timeout,
            sqlx::query_as::<_, AccountRow>(
                "SELECT id, name, password_hash, role, status, is_bootstrap, created_at
             FROM ts_account
             WHERE is_bootstrap = TRUE",
            )
            .fetch_optional(&self.auth),
        )
        .await
        .map_err(map_read_error)?
        .map(AccountRow::into_account)
        .transpose()
    }

    async fn find_by_name(&self, name: &str) -> Result<Option<Account>, RepositoryError> {
        timed(
            self.admin_timeout,
            sqlx::query_as::<_, AccountRow>(
                "SELECT id, name, password_hash, role, status, is_bootstrap, created_at
             FROM ts_account
             WHERE name = $1",
            )
            .bind(name)
            .fetch_optional(&self.shared),
        )
        .await
        .map_err(map_read_error)?
        .map(AccountRow::into_account)
        .transpose()
    }

    async fn find_by_id(&self, id: AccountId) -> Result<Option<Account>, RepositoryError> {
        timed(
            self.admin_timeout,
            sqlx::query_as::<_, AccountRow>(
                "SELECT id, name, password_hash, role, status, is_bootstrap, created_at
             FROM ts_account
             WHERE id = $1",
            )
            .bind(id.get())
            .fetch_optional(&self.shared),
        )
        .await
        .map_err(map_read_error)?
        .map(AccountRow::into_account)
        .transpose()
    }

    async fn list(&self, request: AccountListRequest) -> Result<AccountPage, RepositoryError> {
        let after_id = request.after_id().map_or(0, |cursor| cursor.get());
        let fetch_limit =
            i64::try_from(request.limit() + 1).expect("bounded account page size fits in i64");
        let mut rows = timed(
            self.admin_timeout,
            sqlx::query_as::<_, AccountRow>(
                "SELECT id, name, password_hash, role, status, is_bootstrap, created_at
             FROM ts_account
             WHERE id > $1
             ORDER BY id ASC
             LIMIT $2",
            )
            .bind(after_id)
            .bind(fetch_limit)
            .fetch_all(&self.shared),
        )
        .await
        .map_err(map_read_error)?;
        let has_more = rows.len() > request.limit();
        rows.truncate(request.limit());
        let items = rows
            .into_iter()
            .map(AccountRow::into_account)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AccountPage::new(items, has_more))
    }

    /// Creates an account and, for the bootstrap one, adopts staged legacy keys.
    ///
    /// A credential issued before accounts existed resolves to a provider, not
    /// to an owner. Adoption rewrites each staged row as a credential of this
    /// account, bound to its original provider as the default, keeping the
    /// stored identifier and hash. A client holding that credential therefore
    /// keeps working across the upgrade. The staging table is cleared in the
    /// same transaction, so the conversion happens exactly once.
    async fn create(&self, account: NewAccount) -> Result<Account, RepositoryError> {
        let mut transaction = self.shared.begin().await.map_err(map_transaction_error)?;
        let created = timed(
            self.admin_timeout,
            sqlx::query_as::<_, AccountRow>(
                "INSERT INTO ts_account (name, password_hash, role, status, is_bootstrap, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, name, password_hash, role, status, is_bootstrap, created_at",
            )
            .bind(account.name())
            .bind(account.password_hash().expose())
            .bind(role_value(account.role()))
            .bind(account_status_value(account.status()))
            .bind(account.is_bootstrap())
            .bind(to_epoch_micros(account.created_at()))
            .fetch_one(&mut *transaction),
        )
        .await
        .map_err(|error| map_write_error(error, WRITE_OPERATION))?
        .into_account()?;

        if account.is_bootstrap() {
            adopt_legacy_keys(&mut transaction, created.id()).await?;
        }
        transaction.commit().await.map_err(map_transaction_error)?;
        Ok(created)
    }

    async fn update(
        &self,
        id: AccountId,
        update: AccountUpdate,
    ) -> Result<Account, RepositoryError> {
        if update.is_empty() {
            return Err(RepositoryError::NoFieldsToUpdate);
        }
        let mut builder = QueryBuilder::<Postgres>::new("UPDATE ts_account SET ");
        {
            let mut assignments = builder.separated(", ");
            if let Some(name) = update.name() {
                assignments.push("name = ").push_bind_unseparated(name);
            }
            if let Some(hash) = update.password_hash() {
                assignments
                    .push("password_hash = ")
                    .push_bind_unseparated(hash.expose());
            }
            if let Some(role) = update.role() {
                assignments
                    .push("role = ")
                    .push_bind_unseparated(role_value(role));
            }
            if let Some(status) = update.status() {
                assignments
                    .push("status = ")
                    .push_bind_unseparated(account_status_value(status));
            }
        }
        builder
            .push(" WHERE id = ")
            .push_bind(id.get())
            .push(" RETURNING id, name, password_hash, role, status, is_bootstrap, created_at");
        timed(
            self.admin_timeout,
            builder
                .build_query_as::<AccountRow>()
                .fetch_optional(&self.shared),
        )
        .await
        .map_err(|error| map_write_error(error, WRITE_OPERATION))?
        .ok_or(RepositoryError::NotFound)?
        .into_account()
    }

    async fn delete(&self, id: AccountId) -> Result<(), RepositoryError> {
        let result = timed(
            self.admin_timeout,
            sqlx::query("DELETE FROM ts_account WHERE id = $1")
                .bind(id.get())
                .execute(&self.shared),
        )
        .await
        .map_err(|error| {
            if is_foreign_key_violation(&error) {
                RepositoryError::InUse
            } else {
                map_write_storage_error(error)
            }
        })?;
        if result.rows_affected() == 0 {
            Err(RepositoryError::NotFound)
        } else {
            Ok(())
        }
    }

    async fn count(&self) -> Result<i64, RepositoryError> {
        timed(
            self.admin_timeout,
            sqlx::query_scalar("SELECT COUNT(*) FROM ts_account").fetch_one(&self.shared),
        )
        .await
        .map_err(map_read_error)
    }
}

impl ApiKeyRepository for PostgresDatabase {
    async fn find_by_key_id(
        &self,
        key_id: &GatewayKeyId,
    ) -> Result<Option<ApiKeyWithBindings>, RepositoryError> {
        let row = timed(
            self.auth_timeout,
            sqlx::query_as::<_, ApiKeyRow>(
                "SELECT id, account_id, name, key_id, secret_hash, status,
                        default_provider_id, expires_at,
                        max_concurrent_requests, max_requests_per_second, max_websockets, created_at
                 FROM ts_api_key
                 WHERE key_id = $1",
            )
            .bind(key_id.as_str())
            .fetch_optional(&self.auth),
        )
        .await
        .map_err(map_read_error)?
        .map(ApiKeyRow::into_api_key)
        .transpose()?;
        let Some(api_key) = row else {
            return Ok(None);
        };
        let bindings = self.bindings_for(api_key.id()).await?;
        Ok(Some(ApiKeyWithBindings::new(api_key, bindings)))
    }

    async fn find_by_id(
        &self,
        id: ApiKeyId,
    ) -> Result<Option<ApiKeyWithBindings>, RepositoryError> {
        let row = timed(
            self.admin_timeout,
            sqlx::query_as::<_, ApiKeyRow>(
                "SELECT id, account_id, name, key_id, secret_hash, status,
                        default_provider_id, expires_at,
                        max_concurrent_requests, max_requests_per_second, max_websockets, created_at
                 FROM ts_api_key
                 WHERE id = $1",
            )
            .bind(id.get())
            .fetch_optional(&self.shared),
        )
        .await
        .map_err(map_read_error)?
        .map(ApiKeyRow::into_api_key)
        .transpose()?;
        let Some(api_key) = row else {
            return Ok(None);
        };
        let bindings = self.bindings_for(api_key.id()).await?;
        Ok(Some(ApiKeyWithBindings::new(api_key, bindings)))
    }

    async fn list(&self, request: ApiKeyListRequest) -> Result<ApiKeyPage, RepositoryError> {
        let after_id = request.after_id().map_or(0, |cursor| cursor.get());
        let fetch_limit =
            i64::try_from(request.limit() + 1).expect("bounded credential page size fits in i64");
        let mut builder = QueryBuilder::<Postgres>::new(
            "SELECT id, account_id, name, key_id, secret_hash, status,
                    default_provider_id, expires_at,
                    max_concurrent_requests, max_requests_per_second, max_websockets, created_at
             FROM ts_api_key
             WHERE id > $1",
        );
        builder.push_bind(after_id);
        if let Some(account_id) = request.account_id() {
            builder
                .push(" AND account_id = $2")
                .push_bind(account_id.get());
        }
        builder
            .push(" ORDER BY id ASC LIMIT $")
            .push_bind(fetch_limit);
        let mut rows = timed(
            self.admin_timeout,
            builder
                .build_query_as::<ApiKeyRow>()
                .fetch_all(&self.shared),
        )
        .await
        .map_err(map_read_error)?;
        let has_more = rows.len() > request.limit();
        rows.truncate(request.limit());
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let api_key = row.into_api_key()?;
            let bindings = self.bindings_for(api_key.id()).await?;
            items.push(ApiKeyWithBindings::new(api_key, bindings));
        }
        Ok(ApiKeyPage::new(items, has_more))
    }

    async fn create(&self, api_key: NewApiKey) -> Result<ApiKeyWithBindings, RepositoryError> {
        let mut transaction = self.shared.begin().await.map_err(map_transaction_error)?;
        let created = timed(
            self.admin_timeout,
            sqlx::query_as::<_, ApiKeyRow>(
                "INSERT INTO ts_api_key (
                     account_id, name, key_id, secret_hash, status,
                     default_provider_id, expires_at,
                     max_concurrent_requests, max_requests_per_second, max_websockets, created_at
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                 RETURNING id, account_id, name, key_id, secret_hash, status,
                           default_provider_id, expires_at,
                           max_concurrent_requests, max_requests_per_second, max_websockets,
                           created_at",
            )
            .bind(api_key.account_id.get())
            .bind(api_key.name.as_str())
            .bind(api_key.key_id.as_str())
            .bind(api_key.secret_hash.expose())
            .bind(api_key_status_value(api_key.status))
            .bind(api_key.default_provider_id.map(ProviderId::get))
            .bind(api_key.expires_at.map(to_epoch_micros))
            .bind(admission_count(
                api_key.admission().max_concurrent_requests(),
            ))
            .bind(admission_count(
                api_key.admission().max_requests_per_second(),
            ))
            .bind(admission_count(api_key.admission().max_websockets()))
            .bind(to_epoch_micros(api_key.created_at))
            .fetch_one(&mut *transaction),
        )
        .await
        .map_err(|error| map_write_error(error, WRITE_OPERATION))?
        .into_api_key()?;
        write_bindings(&mut transaction, created.id(), api_key.provider_ids()).await?;
        transaction.commit().await.map_err(map_transaction_error)?;
        let bindings = self.bindings_for(created.id()).await?;
        Ok(ApiKeyWithBindings::new(created, bindings))
    }

    /// Writes only the named fields, then reloads the credential and its set.
    ///
    /// The binding set and the default are written in one transaction, so a
    /// caller can never observe a default that points outside the allowed set.
    async fn update(
        &self,
        id: ApiKeyId,
        update: ApiKeyUpdate,
    ) -> Result<ApiKeyWithBindings, RepositoryError> {
        if update.is_empty() {
            return Err(RepositoryError::NoFieldsToUpdate);
        }
        let mut transaction = self.shared.begin().await.map_err(map_transaction_error)?;
        if let Some(provider_ids) = update.provider_ids() {
            timed(
                self.admin_timeout,
                sqlx::query("DELETE FROM ts_api_key_provider WHERE api_key_id = $1")
                    .bind(id.get())
                    .execute(&mut *transaction),
            )
            .await
            .map_err(|error| map_write_error(error, WRITE_OPERATION))?;
            write_bindings(&mut transaction, id, provider_ids).await?;
        }
        let mut builder = QueryBuilder::<Postgres>::new("UPDATE ts_api_key SET ");
        {
            let mut assignments = builder.separated(", ");
            if let Some(name) = update.name() {
                assignments.push("name = ").push_bind_unseparated(name);
            }
            if let Some(status) = update.status() {
                assignments
                    .push("status = ")
                    .push_bind_unseparated(api_key_status_value(status));
            }
            if let Some(Some(expires_at)) = update.expires_at() {
                assignments
                    .push("expires_at = ")
                    .push_bind_unseparated(to_epoch_micros(expires_at));
            }
            if let Some(Some(provider_id)) = update.default_provider_id() {
                assignments
                    .push("default_provider_id = ")
                    .push_bind_unseparated(provider_id.get());
            }
            if update.expires_at() == Some(None) {
                assignments.push("expires_at = NULL");
            }
            if update.default_provider_id() == Some(None) {
                assignments.push("default_provider_id = NULL");
            }
            if let Some(admission) = update.admission() {
                assignments
                    .push("max_concurrent_requests = ")
                    .push_bind_unseparated(admission_count(admission.max_concurrent_requests()));
                assignments
                    .push("max_requests_per_second = ")
                    .push_bind_unseparated(admission_count(admission.max_requests_per_second()));
                assignments
                    .push("max_websockets = ")
                    .push_bind_unseparated(admission_count(admission.max_websockets()));
            }
        }
        builder.push(" WHERE id = ").push_bind(id.get()).push(
            " RETURNING id, account_id, name, key_id, secret_hash, status,
                          default_provider_id, expires_at,
                          max_concurrent_requests, max_requests_per_second, max_websockets,
                          created_at",
        );
        let updated = timed(
            self.admin_timeout,
            builder
                .build_query_as::<ApiKeyRow>()
                .fetch_optional(&mut *transaction),
        )
        .await
        .map_err(|error| map_write_error(error, WRITE_OPERATION))?
        .ok_or(RepositoryError::NotFound)?
        .into_api_key()?;
        transaction.commit().await.map_err(map_transaction_error)?;
        let bindings = self.bindings_for(id).await?;
        Ok(ApiKeyWithBindings::new(updated, bindings))
    }

    async fn rotate(
        &self,
        id: ApiKeyId,
        key_id: GatewayKeyId,
        hash: PasswordHash,
    ) -> Result<ApiKeyWithBindings, RepositoryError> {
        let updated = timed(
            self.admin_timeout,
            sqlx::query_as::<_, ApiKeyRow>(
                "UPDATE ts_api_key
                 SET key_id = $1, secret_hash = $2
                 WHERE id = $3
                 RETURNING id, account_id, name, key_id, secret_hash, status,
                           default_provider_id, expires_at,
                           max_concurrent_requests, max_requests_per_second, max_websockets,
                           created_at",
            )
            .bind(key_id.as_str())
            .bind(hash.expose())
            .bind(id.get())
            .fetch_optional(&self.shared),
        )
        .await
        .map_err(|error| map_write_error(error, WRITE_OPERATION))?
        .ok_or(RepositoryError::NotFound)?
        .into_api_key()?;
        let bindings = self.bindings_for(id).await?;
        Ok(ApiKeyWithBindings::new(updated, bindings))
    }

    async fn delete(&self, id: ApiKeyId) -> Result<(), RepositoryError> {
        let result = timed(
            self.admin_timeout,
            sqlx::query("DELETE FROM ts_api_key WHERE id = $1")
                .bind(id.get())
                .execute(&self.shared),
        )
        .await
        .map_err(|error| {
            if is_foreign_key_violation(&error) {
                RepositoryError::InUse
            } else {
                map_write_storage_error(error)
            }
        })?;
        if result.rows_affected() == 0 {
            Err(RepositoryError::NotFound)
        } else {
            Ok(())
        }
    }
}

impl ModelAliasRepository for PostgresDatabase {
    async fn find_model_alias_by_id(
        &self,
        id: ModelAliasId,
    ) -> Result<Option<ModelAliasWithTargets>, RepositoryError> {
        let alias = timed(
            self.admin_timeout,
            sqlx::query_as::<_, ModelAliasRow>(
                "SELECT id, account_id, name, created_at FROM ts_model_alias WHERE id = $1",
            )
            .bind(id.get())
            .fetch_optional(&self.shared),
        )
        .await
        .map_err(map_read_error)?
        .map(ModelAliasRow::into_alias)
        .transpose()?;
        let Some(alias) = alias else {
            return Ok(None);
        };
        let targets = self.model_alias_targets(alias.id()).await?;
        Ok(Some(ModelAliasWithTargets::new(alias, targets)))
    }

    async fn list_model_aliases(
        &self,
        request: ModelAliasListRequest,
    ) -> Result<ModelAliasPage, RepositoryError> {
        let after_id = request.after_id().map_or(0, |cursor| cursor.get());
        let fetch_limit =
            i64::try_from(request.limit() + 1).expect("bounded model alias page size fits in i64");
        let mut builder = QueryBuilder::<Postgres>::new(
            "SELECT id, account_id, name, created_at FROM ts_model_alias WHERE id > ",
        );
        builder.push_bind(after_id);
        if let Some(account_id) = request.account_id() {
            builder
                .push(" AND account_id = ")
                .push_bind(account_id.get());
        }
        builder
            .push(" ORDER BY id ASC LIMIT ")
            .push_bind(fetch_limit);
        let mut rows = timed(
            self.admin_timeout,
            builder
                .build_query_as::<ModelAliasRow>()
                .fetch_all(&self.shared),
        )
        .await
        .map_err(map_read_error)?;
        let has_more = rows.len() > request.limit();
        rows.truncate(request.limit());
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let alias = row.into_alias()?;
            let targets = self.model_alias_targets(alias.id()).await?;
            items.push(ModelAliasWithTargets::new(alias, targets));
        }
        Ok(ModelAliasPage::new(items, has_more))
    }

    async fn create_model_alias(
        &self,
        alias: NewModelAlias,
    ) -> Result<ModelAliasWithTargets, RepositoryError> {
        let mut transaction = self.shared.begin().await.map_err(map_transaction_error)?;
        let created = timed(
            self.admin_timeout,
            sqlx::query_as::<_, ModelAliasRow>(
                "INSERT INTO ts_model_alias (account_id, name, created_at)
                 VALUES ($1, $2, $3)
                 RETURNING id, account_id, name, created_at",
            )
            .bind(alias.account_id().get())
            .bind(alias.name())
            .bind(to_epoch_micros(alias.created_at()))
            .fetch_one(&mut *transaction),
        )
        .await
        .map_err(|error| map_write_error(error, WRITE_OPERATION))?
        .into_alias()?;
        let targets = write_model_alias_targets(
            &mut transaction,
            created.id(),
            alias.targets(),
            self.admin_timeout,
        )
        .await?;
        transaction.commit().await.map_err(map_transaction_error)?;
        Ok(ModelAliasWithTargets::new(created, targets))
    }

    async fn update_model_alias(
        &self,
        id: ModelAliasId,
        update: ModelAliasUpdate,
    ) -> Result<ModelAliasWithTargets, RepositoryError> {
        if update.is_empty() {
            return Err(RepositoryError::NoFieldsToUpdate);
        }
        let mut transaction = self.shared.begin().await.map_err(map_transaction_error)?;
        let updated = match update.name() {
            Some(name) => timed(
                self.admin_timeout,
                sqlx::query_as::<_, ModelAliasRow>(
                    "UPDATE ts_model_alias SET name = $1 WHERE id = $2
                     RETURNING id, account_id, name, created_at",
                )
                .bind(name)
                .bind(id.get())
                .fetch_optional(&mut *transaction),
            )
            .await
            .map_err(|error| map_write_error(error, WRITE_OPERATION))?,
            None => timed(
                self.admin_timeout,
                sqlx::query_as::<_, ModelAliasRow>(
                    "SELECT id, account_id, name, created_at FROM ts_model_alias WHERE id = $1",
                )
                .bind(id.get())
                .fetch_optional(&mut *transaction),
            )
            .await
            .map_err(map_read_error)?,
        }
        .ok_or(RepositoryError::NotFound)?
        .into_alias()?;
        let targets = if let Some(targets) = update.targets() {
            timed(
                self.admin_timeout,
                sqlx::query("DELETE FROM ts_model_alias_target WHERE model_alias_id = $1")
                    .bind(id.get())
                    .execute(&mut *transaction),
            )
            .await
            .map_err(map_write_storage_error)?;
            write_model_alias_targets(&mut transaction, id, targets, self.admin_timeout).await?
        } else {
            let rows = timed(
                self.admin_timeout,
                sqlx::query_as::<_, ModelAliasTargetRow>(
                    "SELECT provider_id, upstream_model, position
                     FROM ts_model_alias_target WHERE model_alias_id = $1 ORDER BY position ASC",
                )
                .bind(id.get())
                .fetch_all(&mut *transaction),
            )
            .await
            .map_err(map_read_error)?;
            rows.into_iter()
                .map(ModelAliasTargetRow::into_target)
                .collect::<Result<Vec<_>, _>>()?
        };
        transaction.commit().await.map_err(map_transaction_error)?;
        Ok(ModelAliasWithTargets::new(updated, targets))
    }

    async fn delete_model_alias(&self, id: ModelAliasId) -> Result<(), RepositoryError> {
        let result = timed(
            self.admin_timeout,
            sqlx::query("DELETE FROM ts_model_alias WHERE id = $1")
                .bind(id.get())
                .execute(&self.shared),
        )
        .await
        .map_err(map_write_storage_error)?;
        if result.rows_affected() == 0 {
            Err(RepositoryError::NotFound)
        } else {
            Ok(())
        }
    }
}

impl PostgresDatabase {
    async fn model_alias_targets(
        &self,
        id: ModelAliasId,
    ) -> Result<Vec<ModelAliasTarget>, RepositoryError> {
        let rows = timed(
            self.admin_timeout,
            sqlx::query_as::<_, ModelAliasTargetRow>(
                "SELECT provider_id, upstream_model, position
                 FROM ts_model_alias_target WHERE model_alias_id = $1 ORDER BY position ASC",
            )
            .bind(id.get())
            .fetch_all(&self.shared),
        )
        .await
        .map_err(map_read_error)?;
        rows.into_iter()
            .map(ModelAliasTargetRow::into_target)
            .collect()
    }
}

async fn write_model_alias_targets(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    id: ModelAliasId,
    targets: &[(ProviderId, String)],
    deadline: Duration,
) -> Result<Vec<ModelAliasTarget>, RepositoryError> {
    let mut stored = Vec::with_capacity(targets.len());
    for (position, (provider_id, upstream_model)) in targets.iter().enumerate() {
        let position = i64::try_from(position).expect("bounded target count fits in i64");
        timed(
            deadline,
            sqlx::query(
                "INSERT INTO ts_model_alias_target
                 (model_alias_id, provider_id, upstream_model, position) VALUES ($1, $2, $3, $4)",
            )
            .bind(id.get())
            .bind(provider_id.get())
            .bind(upstream_model)
            .bind(position)
            .execute(&mut **transaction),
        )
        .await
        .map_err(|error| map_write_error(error, WRITE_OPERATION))?;
        stored.push(ModelAliasTarget::new(
            *provider_id,
            upstream_model.clone(),
            position,
        ));
    }
    Ok(stored)
}

impl PostgresDatabase {
    /// Reads one credential's allowed providers in preference order.
    async fn bindings_for(&self, id: ApiKeyId) -> Result<Vec<ApiKeyBinding>, RepositoryError> {
        let rows = timed(
            self.admin_timeout,
            sqlx::query_as::<_, ApiKeyBindingRow>(
                "SELECT api_key_id, provider_id, position
                 FROM ts_api_key_provider
                 WHERE api_key_id = $1
                 ORDER BY position ASC",
            )
            .bind(id.get())
            .fetch_all(&self.shared),
        )
        .await
        .map_err(map_read_error)?;
        rows.into_iter()
            .map(ApiKeyBindingRow::into_binding)
            .collect()
    }
}

/// Writes a credential's allowed providers in preference order.
///
/// The statements run inside the caller's transaction, so a failure part way
/// through rolls the whole credential back rather than leaving a partial set.
async fn write_bindings(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    api_key_id: ApiKeyId,
    provider_ids: &[ProviderId],
) -> Result<(), RepositoryError> {
    for (position, provider_id) in provider_ids.iter().enumerate() {
        let position = i64::try_from(position).map_err(|_| RepositoryError::InvalidStoredData)?;
        timed(
            BINDING_WRITE_DEADLINE,
            sqlx::query(
                "INSERT INTO ts_api_key_provider (api_key_id, provider_id, position)
                 VALUES ($1, $2, $3)",
            )
            .bind(api_key_id.get())
            .bind(provider_id.get())
            .bind(position)
            .execute(&mut **transaction),
        )
        .await
        .map_err(|error| map_write_error(error, WRITE_OPERATION))?;
    }
    Ok(())
}

/// Rewrites staged provider-issued credentials as credentials of `account_id`.
///
/// Each adopted credential keeps its identifier and hash, and is bound to its
/// original provider as the default, so a running client is never interrupted by
/// the upgrade. The staging rows are deleted, which is what makes the
/// conversion run once.
async fn adopt_legacy_keys(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    account_id: AccountId,
) -> Result<(), RepositoryError> {
    let staged = sqlx::query("SELECT provider_id, key_id, secret_hash FROM ts_legacy_gateway_key")
        .fetch_all(&mut **transaction)
        .await
        .map_err(map_read_error)?;
    for row in staged {
        let provider_id: i64 = row.get("provider_id");
        let key_id: String = row.get("key_id");
        let secret_hash: String = row.get("secret_hash");
        let created = sqlx::query(
            "INSERT INTO ts_api_key (
                 account_id, name, key_id, secret_hash, status,
                 default_provider_id, expires_at,
                 max_concurrent_requests, max_requests_per_second, max_websockets, created_at
             ) VALUES ($1, $2, $3, $4, 'enabled', $5, NULL, $6)
             RETURNING id",
        )
        .bind(account_id.get())
        .bind(format!("migrated-{provider_id}"))
        .bind(&key_id)
        .bind(&secret_hash)
        .bind(provider_id)
        .bind(to_epoch_micros(chrono::Utc::now()))
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| map_write_error(error, WRITE_OPERATION))?;
        let api_key_id: i64 = created.get("id");
        sqlx::query(
            "INSERT INTO ts_api_key_provider (api_key_id, provider_id, position)
             VALUES ($1, $2, 0)",
        )
        .bind(api_key_id)
        .bind(provider_id)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_write_error(error, WRITE_OPERATION))?;
    }
    sqlx::query("DELETE FROM ts_legacy_gateway_key")
        .execute(&mut **transaction)
        .await
        .map_err(map_write_storage_error)?;
    Ok(())
}

fn map_write_error(
    error: sqlx::Error,
    operation: crate::diagnostics::RepositoryOperation,
) -> RepositoryError {
    if is_timeout_error(&error) {
        RepositoryError::Timeout
    } else if error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
    {
        RepositoryError::Conflict
    } else if is_foreign_key_violation(&error) {
        RepositoryError::NotFound
    } else {
        crate::diagnostics::repository_operation_failed(
            crate::diagnostics::RepositoryBackend::Postgresql,
            operation,
            diagnostic_error_kind(&error),
        );
        RepositoryError::Storage
    }
}

fn is_foreign_key_violation(error: &sqlx::Error) -> bool {
    error.as_database_error().is_some_and(|database_error| {
        database_error.is_foreign_key_violation()
            || database_error.code().as_deref() == Some("23503")
    })
}

fn is_provider_reference_violation(error: &sqlx::Error) -> bool {
    is_foreign_key_violation(error)
        || error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref()
            == Some("23001")
}

fn map_storage_error(
    error: sqlx::Error,
    operation: crate::diagnostics::RepositoryOperation,
) -> RepositoryError {
    if is_timeout_error(&error) {
        RepositoryError::Timeout
    } else {
        crate::diagnostics::repository_operation_failed(
            crate::diagnostics::RepositoryBackend::Postgresql,
            operation,
            diagnostic_error_kind(&error),
        );
        RepositoryError::Storage
    }
}

fn map_read_error(error: sqlx::Error) -> RepositoryError {
    map_storage_error(error, crate::diagnostics::RepositoryOperation::ReadQuery)
}

fn map_write_storage_error(error: sqlx::Error) -> RepositoryError {
    map_storage_error(error, crate::diagnostics::RepositoryOperation::WriteQuery)
}

fn map_transaction_error(error: sqlx::Error) -> RepositoryError {
    map_storage_error(error, crate::diagnostics::RepositoryOperation::Transaction)
}

fn is_timeout_error(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::PoolTimedOut)
        || error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref()
            == Some("57014")
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn hostile_storage_errors_keep_their_call_boundary_operation_without_rendering_text() {
        let secret = "postgres://user:password@host/db?payload=postgres";
        for (mapper, operation) in [
            (
                map_read_error as fn(sqlx::Error) -> RepositoryError,
                "read_query",
            ),
            (map_write_storage_error, "write_query"),
            (map_transaction_error, "transaction"),
        ] {
            let output = crate::diagnostics::capture_for_test(|| {
                assert_eq!(
                    mapper(sqlx::Error::Protocol(secret.to_owned())),
                    RepositoryError::Storage
                );
            });
            let event: serde_json::Value =
                serde_json::from_str(output.trim()).expect("repository diagnostic");
            assert_eq!(event["fields"]["event"], "repository_operation_failed");
            assert_eq!(event["fields"]["backend"], "postgresql");
            assert_eq!(event["fields"]["operation"], operation);
            assert_eq!(event["fields"]["error_kind"], "protocol");
            assert!(!output.contains(secret));
        }
    }
}
