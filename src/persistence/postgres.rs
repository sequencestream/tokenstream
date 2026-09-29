use std::io;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool, Postgres, QueryBuilder};

use crate::MigrationRunner;
use crate::domain::{GatewayKeyId, PasswordHash, Provider, ProviderId};
use crate::logging::LogEvent;

use super::time::to_epoch_micros;
use super::{
    DatabaseBounds, NewProvider, ProviderListRequest, ProviderPage, ProviderRepository,
    ProviderRow, ProviderUpdate, RepositoryError, RequestLogCompleted, RequestLogPage,
    RequestLogQuery, RequestLogRepository, RequestLogRow, RequestLogStarted, protocol_value,
    status_value, timed, transport_value,
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

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
        let mut transaction = self.shared.begin().await.map_err(map_storage_error)?;
        for event in events {
            match event {
                LogEvent::Started(event) => {
                    sqlx::query(
                        "INSERT INTO request_log (
                             request_id, provider_id, protocol_type, transport_type, path, start_time
                         ) VALUES ($1, $2, $3, $4, $5, $6)",
                    )
                    .bind(event.request_id().as_str())
                    .bind(event.provider_id().get())
                    .bind(protocol_value(event.protocol_type()))
                    .bind(transport_value(event.transport_type()))
                    .bind(event.path())
                    .bind(to_epoch_micros(event.start_time()))
                    .execute(&mut *transaction)
                    .await
                    .map_err(map_write_error)?;
                }
                LogEvent::Completed(event) => {
                    sqlx::query(
                        "UPDATE request_log
                         SET status_code = $1, end_time = $2, error_msg = $3
                         WHERE request_id = $4 AND end_time IS NULL",
                    )
                    .bind(event.status_code().map(i64::from))
                    .bind(to_epoch_micros(event.end_time()))
                    .bind(event.error_msg())
                    .bind(event.request_id().as_str())
                    .execute(&mut *transaction)
                    .await
                    .map_err(map_storage_error)?;
                }
            }
        }
        transaction.commit().await.map_err(map_storage_error)
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
    async fn find_by_key_id(
        &self,
        key_id: &GatewayKeyId,
    ) -> Result<Option<Provider>, RepositoryError> {
        timed(
            self.auth_timeout,
            sqlx::query_as::<_, ProviderRow>(
                "SELECT id, name, protocol_type, endpoint, upstream_api_key_ciphertext,
                    gateway_key_id, gateway_api_key_hash, status, created_at
             FROM provider
             WHERE gateway_key_id = $1",
            )
            .bind(key_id.as_str())
            .fetch_optional(&self.auth),
        )
        .await
        .map_err(map_storage_error)?
        .map(ProviderRow::into_provider)
        .transpose()
    }

    async fn find_by_id(&self, id: ProviderId) -> Result<Option<Provider>, RepositoryError> {
        timed(
            self.admin_timeout,
            sqlx::query_as::<_, ProviderRow>(
                "SELECT id, name, protocol_type, endpoint, upstream_api_key_ciphertext,
                    gateway_key_id, gateway_api_key_hash, status, created_at
             FROM provider
             WHERE id = $1",
            )
            .bind(id.get())
            .fetch_optional(&self.shared),
        )
        .await
        .map_err(map_storage_error)?
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
                    gateway_key_id, gateway_api_key_hash, status, created_at
             FROM provider
             WHERE id > $1
             ORDER BY id ASC
             LIMIT $2",
            )
            .bind(after_id)
            .bind(fetch_limit)
            .fetch_all(&self.shared),
        )
        .await
        .map_err(map_storage_error)?;
        let has_more = rows.len() > request.limit();
        rows.truncate(request.limit());
        let items = rows
            .into_iter()
            .map(ProviderRow::into_provider)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ProviderPage::new(items, has_more))
    }

    async fn create(&self, provider: NewProvider) -> Result<Provider, RepositoryError> {
        timed(
            self.admin_timeout,
            sqlx::query_as::<_, ProviderRow>(
                "INSERT INTO provider (
                 name, protocol_type, endpoint, upstream_api_key_ciphertext,
                 gateway_key_id, gateway_api_key_hash, status, created_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING id, name, protocol_type, endpoint, upstream_api_key_ciphertext,
                       gateway_key_id, gateway_api_key_hash, status, created_at",
            )
            .bind(provider.name)
            .bind(protocol_value(provider.protocol_type))
            .bind(provider.endpoint.as_str())
            .bind(provider.upstream_api_key_ciphertext.expose())
            .bind(provider.gateway_key_id.as_str())
            .bind(provider.gateway_api_key_hash.expose())
            .bind(status_value(provider.status))
            .bind(to_epoch_micros(provider.created_at))
            .fetch_one(&self.shared),
        )
        .await
        .map_err(map_write_error)?
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
        let mut builder = QueryBuilder::<Postgres>::new("UPDATE provider SET ");
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
        }
        builder.push(" WHERE id = ").push_bind(id.get());
        builder.push(
            " RETURNING id, name, protocol_type, endpoint, upstream_api_key_ciphertext,
                      gateway_key_id, gateway_api_key_hash, status, created_at",
        );
        timed(
            self.admin_timeout,
            builder
                .build_query_as::<ProviderRow>()
                .fetch_optional(&self.shared),
        )
        .await
        .map_err(map_write_error)?
        .ok_or(RepositoryError::NotFound)?
        .into_provider()
    }

    async fn rotate_gateway_key(
        &self,
        id: ProviderId,
        key_id: GatewayKeyId,
        hash: PasswordHash,
    ) -> Result<Provider, RepositoryError> {
        timed(
            self.admin_timeout,
            sqlx::query_as::<_, ProviderRow>(
                "UPDATE provider
             SET gateway_key_id = $1, gateway_api_key_hash = $2
             WHERE id = $3
             RETURNING id, name, protocol_type, endpoint, upstream_api_key_ciphertext,
                       gateway_key_id, gateway_api_key_hash, status, created_at",
            )
            .bind(key_id.as_str())
            .bind(hash.expose())
            .bind(id.get())
            .fetch_optional(&self.shared),
        )
        .await
        .map_err(map_write_error)?
        .ok_or(RepositoryError::NotFound)?
        .into_provider()
    }

    async fn delete(&self, id: ProviderId) -> Result<(), RepositoryError> {
        let result = timed(
            self.admin_timeout,
            sqlx::query("DELETE FROM provider WHERE id = $1")
                .bind(id.get())
                .execute(&self.shared),
        )
        .await
        .map_err(|error| {
            if is_provider_reference_violation(&error) {
                RepositoryError::ProviderInUse
            } else {
                map_storage_error(error)
            }
        })?;
        if result.rows_affected() == 0 {
            Err(RepositoryError::NotFound)
        } else {
            Ok(())
        }
    }
}

impl RequestLogRepository for PostgresDatabase {
    async fn insert_started(&self, event: RequestLogStarted) -> Result<(), RepositoryError> {
        timed(
            self.log_timeout,
            sqlx::query(
                "INSERT INTO request_log (
                 request_id, provider_id, protocol_type, transport_type, path, start_time
             ) VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(event.request_id.as_str())
            .bind(event.provider_id.get())
            .bind(protocol_value(event.protocol_type))
            .bind(transport_value(event.transport_type))
            .bind(event.path)
            .bind(to_epoch_micros(event.start_time))
            .execute(&self.shared),
        )
        .await
        .map_err(map_write_error)?;
        Ok(())
    }

    async fn apply_completed(&self, event: RequestLogCompleted) -> Result<(), RepositoryError> {
        timed(
            self.log_timeout,
            sqlx::query(
                "UPDATE request_log
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
        .map_err(map_storage_error)?;
        Ok(())
    }

    async fn query(&self, query: RequestLogQuery) -> Result<RequestLogPage, RepositoryError> {
        let mut statement = QueryBuilder::<Postgres>::new(
            "SELECT id, request_id, provider_id, protocol_type, transport_type, path,
                    status_code::BIGINT AS status_code, start_time, end_time, error_msg
             FROM request_log
             WHERE id > ",
        );
        statement.push_bind(query.after_id().map_or(0, |cursor| cursor.get()));
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
        .map_err(map_storage_error)?;
        let has_more = rows.len() > query.limit();
        rows.truncate(query.limit());
        let items = rows
            .into_iter()
            .map(RequestLogRow::into_request_log)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RequestLogPage::new(items, has_more))
    }
}

fn map_write_error(error: sqlx::Error) -> RepositoryError {
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

fn map_storage_error(error: sqlx::Error) -> RepositoryError {
    if is_timeout_error(&error) {
        RepositoryError::Timeout
    } else {
        RepositoryError::Storage
    }
}

fn is_timeout_error(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::PoolTimedOut)
        || error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref()
            == Some("57014")
}
