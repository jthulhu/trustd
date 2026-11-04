use sea_orm::prelude::*;
use trustd::Secret;

#[sea_orm::model]
#[derive(Debug, Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "secret")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub owner: String,
    pub secret: Vec<u8>,
}

impl ActiveModelBehavior for ActiveModel {}

impl Model {
    pub fn secret(self) -> Secret {
        // This is enforced by the database type, which is not reflected in the Rust type.
        self.secret.try_into().unwrap()
    }
}
