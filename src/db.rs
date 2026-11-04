use std::{io::Read, mem::take, path::Path};

use libsystemd::{credentials::CredentialsLoader, errors::SdError};
use migrations::MigrationHandler;
use rand::Rng;
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbErr, EntityTrait,
    IntoActiveModel, prelude::Expr, sea_query::OnConflict,
};
use sea_orm_migration::MigratorTrait;
use thiserror::Error;
use trustd::{Secret, SecretError};

mod migrations;
mod secret;

pub struct SecretStorage {
    db_conn: DatabaseConnection,
}

#[derive(Debug, Error)]
pub enum OpenError {
    #[error("Systemd credentials are not setup for this application.")]
    NoSystemdCreds(#[from] SdError),
    #[error("Cannot setup the database connection.")]
    CannotSetupDb(#[from] DbErr),
    #[error("Cannot read the database key from the systemd credentials")]
    CannotReadDbKey(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum GetError {
    #[error("Cannot query the database for the secret.")]
    CannotQueryDb(#[from] DbErr),
}

impl From<GetError> for SecretError {
    fn from(error: GetError) -> Self {
        SecretError::CannotGetSecret(error.to_string())
    }
}

impl SecretStorage {
    /// Open a storage, with the actual data residing (encrypted) at `path`.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, OpenError> {
        let mut passkey = Vec::new();
        CredentialsLoader::open()?
            .get("database-key")?
            .read_to_end(&mut passkey)?;
        let mut options = ConnectOptions::new(format!(
            "sqlite://{}?mode=rwc",
            path.as_ref().to_str().unwrap()
        ));
        options
            .sqlcipher_key(hex::encode(passkey))
            .max_connections(1);
        let db_conn = Database::connect(options).await?;
        db_conn
            .execute_unprepared(
                r#"
                    pragma journal_mode = WAL;
                    pragma synchronous = NORMAL;
                "#,
            )
            .await?;
        MigrationHandler::up(&db_conn, None).await?;
        Ok(Self { db_conn })
    }

    pub async fn get_secret(&self, owner: &str) -> Result<Secret, GetError> {
        let mut secret = vec![0u8; 32];
        rand::rng().fill_bytes(&mut *secret);

        let secret = self::secret::Entity::insert(
            secret::Model {
                owner: owner.to_string(),
                secret,
            }
            .into_active_model(),
        )
        .on_conflict(take(OnConflict::column(secret::Column::Owner).value(
            secret::Column::Secret,
            Expr::col((secret::Entity, secret::Column::Secret)),
        )))
        .exec_with_returning(&self.db_conn)
        .await?;

        Ok(secret.secret())
    }
}
