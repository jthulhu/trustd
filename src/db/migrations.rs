use async_trait::async_trait;
use sea_orm_migration::{MigrationTrait, MigratorTrait};

use self::migration_001::Migration as Migration001;

mod migration_001;

pub struct MigrationHandler;

#[async_trait]
impl MigratorTrait for MigrationHandler {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(Migration001)]
    }
}
