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
use zbus_trust::{Secret, SecretError};

mod migrations;
mod secret;

#[derive(Debug)]
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
        println!("{}", path.as_ref().display());
        let mut passkey = Vec::new();
        CredentialsLoader::open()?
            .get("database-key")?
            .read_to_end(&mut passkey)?;
        Self::open_with(path, passkey).await
    }

    /// `open_with`'s role is to allow an entrypoint for tests, without having to mock systemd's
    /// credential system.
    async fn open_with(
        path: impl AsRef<Path>,
        passkey: impl AsRef<[u8]>,
    ) -> Result<Self, OpenError> {
        let mut options = ConnectOptions::new(format!(
            "sqlite://{}?mode=rwc",
            path.as_ref().to_str().unwrap()
        ));
        options.sqlcipher_key(format!("0x{}", hex::encode(passkey)));
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
        // Dummy "on conflit" clause, which is here just to make SQLite return something even if
        // there is a conflict.  If we had a "on conflict do nothing" policy, SQLite would return
        // nothing on conflict.
        //
        // To solve this, we "update" the `secret` column with itself.
        .on_conflict(take(OnConflict::column(secret::Column::Owner).value(
            secret::Column::Secret,
            Expr::col((secret::Entity, secret::Column::Secret)),
        )))
        .exec_with_returning(&self.db_conn)
        .await?;

        Ok(secret.secret())
    }
}

#[cfg(test)]
mod tests {
    // We use temporary file to spin up the mock environment for tests.
    use tempfile::tempdir;

    use super::*;

    const PASSKEY: &[u8] = b"blopiblop";

    /// Check that asking for the same secret twice indeed gets the same secret.
    #[tokio::test]
    async fn get_secret_idempotent() {
        let dir = tempdir().unwrap();
        let secret_storage = SecretStorage::open_with(dir.path().join("secrets.db"), PASSKEY)
            .await
            .unwrap();
        let first_secret = secret_storage.get_secret("ad._2mon.test").await.unwrap();
        let second_secret = secret_storage.get_secret("ad._2mon.test").await.unwrap();
        assert_eq!(first_secret, second_secret);
    }

    /// Check that distinct owners have distinct secrets.  Note that, in *theory* this could fail
    /// if, by chance, the same secret gets generated for two owners.  However, this is _very_
    /// unlikely.  It's far more likely that the computer on which this test runs has a random
    /// malfunction that leads to a bitflip.
    #[tokio::test]
    async fn get_secret_different() {
        let dir = tempdir().unwrap();
        let secret_storage = SecretStorage::open_with(dir.path().join("secrets.db"), PASSKEY)
            .await
            .unwrap();
        let secret1 = secret_storage.get_secret("ad._2mon.test1").await.unwrap();
        let secret2 = secret_storage.get_secret("ad._2mon.test2").await.unwrap();
        assert_ne!(secret1, secret2);
    }

    /// Check that the database is indeed encrypted, that is, with the wrong password data can't
    /// be accessed.
    #[tokio::test]
    async fn is_encrypted() {
        let dir = tempdir().unwrap();
        let secret_storage = SecretStorage::open_with(dir.path().join("secrets.db"), PASSKEY)
            .await
            .unwrap();
        secret_storage.get_secret("ad._2mon.test").await.unwrap();
        drop(secret_storage);
        SecretStorage::open_with(dir.path().join("secrets.db"), b"wrong password")
            .await
            .unwrap_err();
    }
}
