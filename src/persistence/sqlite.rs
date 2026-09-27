use std::io;
use std::str::FromStr;

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Executor, SqliteConnection, SqlitePool};

use crate::MigrationRunner;

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
