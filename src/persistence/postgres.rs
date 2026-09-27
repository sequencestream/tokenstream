use std::io;

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

use crate::MigrationRunner;

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
