use std::io;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, QueryBuilder};

use crate::MigrationRunner;
use crate::domain::{GatewayKeyId, Provider, ProviderId};

use super::time::to_epoch_micros;
use super::{
    DEFAULT_POOL_ACQUIRE_TIMEOUT, NewProvider, ProviderListRequest, ProviderPage,
    ProviderRepository, ProviderRow, ProviderUpdate, RepositoryError, RequestLogCompleted,
    RequestLogPage, RequestLogQuery, RequestLogRepository, RequestLogRow, RequestLogStarted,
    protocol_value, status_value, transport_value,
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

#[derive(Clone, Debug)]
pub struct PostgresDatabase {
    pool: PgPool,
}

impl PostgresDatabase {
    pub async fn connect(database_url: &str, max_connections: usize) -> Result<Self, sqlx::Error> {
        Self::connect_with_acquire_timeout(
            database_url,
            max_connections,
            DEFAULT_POOL_ACQUIRE_TIMEOUT,
        )
        .await
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
        let pool = PgPoolOptions::new()
            .max_connections(max_connections as u32)
            .acquire_timeout(acquire_timeout)
            .connect(database_url)
            .await?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        MIGRATOR.run(&self.pool).await
    }
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
        sqlx::query_as::<_, ProviderRow>(
            "SELECT id, name, protocol_type, endpoint, upstream_api_key_ciphertext,
                    gateway_key_id, gateway_api_key_hash, status, created_at
             FROM provider
             WHERE gateway_key_id = $1",
        )
        .bind(key_id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_storage_error)?
        .map(ProviderRow::into_provider)
        .transpose()
    }

    async fn list(&self, request: ProviderListRequest) -> Result<ProviderPage, RepositoryError> {
        let after_id = request.after_id().map_or(0, |cursor| cursor.get());
        let fetch_limit =
            i64::try_from(request.limit() + 1).expect("bounded provider page size fits in i64");
        let mut rows = sqlx::query_as::<_, ProviderRow>(
            "SELECT id, name, protocol_type, endpoint, upstream_api_key_ciphertext,
                    gateway_key_id, gateway_api_key_hash, status, created_at
             FROM provider
             WHERE id > $1
             ORDER BY id ASC
             LIMIT $2",
        )
        .bind(after_id)
        .bind(fetch_limit)
        .fetch_all(&self.pool)
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
        .fetch_one(&self.pool)
        .await
        .map_err(map_write_error)?
        .into_provider()
    }

    async fn update(
        &self,
        id: ProviderId,
        update: ProviderUpdate,
    ) -> Result<Provider, RepositoryError> {
        sqlx::query_as::<_, ProviderRow>(
            "UPDATE provider
             SET name = $1, protocol_type = $2, endpoint = $3,
                 upstream_api_key_ciphertext = $4, gateway_key_id = $5,
                 gateway_api_key_hash = $6, status = $7
             WHERE id = $8
             RETURNING id, name, protocol_type, endpoint, upstream_api_key_ciphertext,
                       gateway_key_id, gateway_api_key_hash, status, created_at",
        )
        .bind(update.name)
        .bind(protocol_value(update.protocol_type))
        .bind(update.endpoint.as_str())
        .bind(update.upstream_api_key_ciphertext.expose())
        .bind(update.gateway_key_id.as_str())
        .bind(update.gateway_api_key_hash.expose())
        .bind(status_value(update.status))
        .bind(id.get())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_write_error)?
        .ok_or(RepositoryError::NotFound)?
        .into_provider()
    }

    async fn delete(&self, id: ProviderId) -> Result<(), RepositoryError> {
        let result = sqlx::query("DELETE FROM provider WHERE id = $1")
            .bind(id.get())
            .execute(&self.pool)
            .await
            .map_err(|error| {
                if error
                    .as_database_error()
                    .is_some_and(sqlx::error::DatabaseError::is_foreign_key_violation)
                {
                    RepositoryError::ProviderInUse
                } else {
                    RepositoryError::Storage
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
        .execute(&self.pool)
        .await
        .map_err(map_write_error)?;
        Ok(())
    }

    async fn apply_completed(&self, event: RequestLogCompleted) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE request_log
             SET status_code = $1, end_time = $2, error_msg = $3
             WHERE request_id = $4 AND end_time IS NULL",
        )
        .bind(event.status_code.map(i64::from))
        .bind(to_epoch_micros(event.end_time))
        .bind(event.error_msg)
        .bind(event.request_id.as_str())
        .execute(&self.pool)
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

        let mut rows = statement
            .build_query_as::<RequestLogRow>()
            .fetch_all(&self.pool)
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
    if error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
    {
        RepositoryError::Conflict
    } else if error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_foreign_key_violation)
    {
        RepositoryError::NotFound
    } else {
        RepositoryError::Storage
    }
}

fn map_storage_error(_: sqlx::Error) -> RepositoryError {
    RepositoryError::Storage
}
