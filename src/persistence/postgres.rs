use std::io;

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::MigrationRunner;
use crate::domain::{GatewayKeyId, Provider, ProviderId};

use super::{
    NewProvider, ProviderListRequest, ProviderPage, ProviderRepository, ProviderRow,
    ProviderUpdate, RepositoryError, protocol_value, status_value,
};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/postgres");

#[derive(Clone, Debug)]
pub struct PostgresDatabase {
    pool: PgPool,
}

impl PostgresDatabase {
    pub async fn connect(database_url: &str, max_connections: usize) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections as u32)
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

fn map_write_error(error: sqlx::Error) -> RepositoryError {
    if error
        .as_database_error()
        .is_some_and(sqlx::error::DatabaseError::is_unique_violation)
    {
        RepositoryError::Conflict
    } else {
        RepositoryError::Storage
    }
}

fn map_storage_error(_: sqlx::Error) -> RepositoryError {
    RepositoryError::Storage
}
