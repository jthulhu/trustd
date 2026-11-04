use async_trait::async_trait;
use sea_orm::{DbErr, DeriveMigrationName};
use sea_orm_migration::{MigrationTrait, SchemaManager};

mod secret {
    use sea_orm::{
        DbErr, DeriveIden,
        sea_query::{ColumnDef, Index, Table},
    };
    use sea_orm_migration::SchemaManager;

    #[derive(Debug, DeriveIden)]
    pub enum Secret {
        Table,
        Owner,
        Secret,
    }

    pub async fn up(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Secret::Table)
                    .col(ColumnDef::new(Secret::Owner).text().not_null())
                    .col(ColumnDef::new(Secret::Secret).binary_len(32).not_null())
                    .primary_key(Index::create().col(Secret::Owner))
                    .take(),
            )
            .await?;
        Ok(())
    }

    pub async fn down(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Secret::Table).take())
            .await?;
        Ok(())
    }
}

#[derive(Debug, DeriveMigrationName)]
pub struct Migration;

#[async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        secret::up(manager).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        secret::down(manager).await?;
        Ok(())
    }
}
