use std::io;
use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Executor, QueryBuilder, Sqlite, SqliteConnection, SqlitePool};

use crate::MigrationRunner;
use crate::domain::{GatewayKeyId, Provider, ProviderId};

use super::{
    NewProvider, ProviderListRequest, ProviderPage, ProviderRepository, ProviderRow,
    ProviderUpdate, RepositoryError, RequestLogCompleted, RequestLogPage, RequestLogQuery,
    RequestLogRepository, RequestLogRow, RequestLogStarted, protocol_value, status_value,
    transport_value,
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");

#[derive(Clone, Debug)]
pub struct SqliteDatabase {
    pool: SqlitePool,
}

impl SqliteDatabase {
    pub async fn connect(database_url: &str, max_connections: usize) -> Result<Self, sqlx::Error> {
        let options = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections as u32)
            .after_connect(|connection, _metadata| {
                Box::pin(async move {
                    connection.execute("PRAGMA foreign_keys = ON").await?;
                    verify_foreign_keys(connection).await
                })
            })
            .connect_with(options)
            .await?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        MIGRATOR.run(&self.pool).await
    }
}

impl MigrationRunner for SqliteDatabase {
    async fn run(&self) -> io::Result<()> {
        self.migrate().await.map_err(io::Error::other)
    }
}

async fn verify_foreign_keys(connection: &mut SqliteConnection) -> Result<(), sqlx::Error> {
    let enabled: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(&mut *connection)
        .await?;
    if enabled == 1 {
        Ok(())
    } else {
        Err(sqlx::Error::Protocol(
            "SQLite foreign-key enforcement is unavailable".to_owned(),
        ))
    }
}

impl ProviderRepository for SqliteDatabase {
    async fn find_by_key_id(
        &self,
        key_id: &GatewayKeyId,
    ) -> Result<Option<Provider>, RepositoryError> {
        sqlx::query_as::<_, ProviderRow>(
            "SELECT id, name, protocol_type, endpoint, upstream_api_key_ciphertext,
                    gateway_key_id, gateway_api_key_hash, status, created_at
             FROM provider
             WHERE gateway_key_id = ?",
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
             WHERE id > ?
             ORDER BY id ASC
             LIMIT ?",
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
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
        .bind(provider.created_at.timestamp_micros())
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
             SET name = ?, protocol_type = ?, endpoint = ?, upstream_api_key_ciphertext = ?,
                 gateway_key_id = ?, gateway_api_key_hash = ?, status = ?
             WHERE id = ?
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
        let result = sqlx::query("DELETE FROM provider WHERE id = ?")
            .bind(id.get())
            .execute(&self.pool)
            .await
            .map_err(|error| {
                if is_foreign_key_violation(&error) {
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

impl RequestLogRepository for SqliteDatabase {
    async fn insert_started(&self, event: RequestLogStarted) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO request_log (
                 request_id, provider_id, protocol_type, transport_type, path, start_time
             ) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(event.request_id.as_str())
        .bind(event.provider_id.get())
        .bind(protocol_value(event.protocol_type))
        .bind(transport_value(event.transport_type))
        .bind(event.path)
        .bind(event.start_time.timestamp_micros())
        .execute(&self.pool)
        .await
        .map_err(map_write_error)?;
        Ok(())
    }

    async fn apply_completed(&self, event: RequestLogCompleted) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE request_log
             SET status_code = ?, end_time = ?, error_msg = ?
             WHERE request_id = ? AND end_time IS NULL",
        )
        .bind(event.status_code.map(i64::from))
        .bind(event.end_time.timestamp_micros())
        .bind(event.error_msg)
        .bind(event.request_id.as_str())
        .execute(&self.pool)
        .await
        .map_err(map_storage_error)?;
        Ok(())
    }

    async fn query(&self, query: RequestLogQuery) -> Result<RequestLogPage, RepositoryError> {
        let mut statement = QueryBuilder::<Sqlite>::new(
            "SELECT id, request_id, provider_id, protocol_type, transport_type, path,
                    status_code, start_time, end_time, error_msg
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
                .push_bind(start_time.timestamp_micros());
        }
        if let Some(start_time) = query.start_time_lt() {
            statement
                .push(" AND start_time < ")
                .push_bind(start_time.timestamp_micros());
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
    if error.as_database_error().is_some_and(|database_error| {
        database_error.is_unique_violation()
            || matches!(database_error.code().as_deref(), Some("1555" | "2067"))
    }) {
        RepositoryError::Conflict
    } else if is_foreign_key_violation(&error) {
        RepositoryError::NotFound
    } else {
        RepositoryError::Storage
    }
}

fn map_storage_error(_: sqlx::Error) -> RepositoryError {
    RepositoryError::Storage
}

fn is_foreign_key_violation(error: &sqlx::Error) -> bool {
    error.as_database_error().is_some_and(|database_error| {
        database_error.is_foreign_key_violation()
            || matches!(database_error.code().as_deref(), Some("787" | "1811"))
    })
}
