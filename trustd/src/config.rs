use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Cannot read the configuration file.")]
    CannotReadFile(#[from] std::io::Error),
    #[error("The configuration file is invalid.")]
    SyntaxError(#[from] toml::de::Error),
}

#[derive(Debug, Deserialize)]
pub struct Config {
    policy_path: PathBuf,
    #[serde(default = "Config::default_database_file")]
    database_file: PathBuf,
}

impl Config {
    fn default_database_file() -> PathBuf {
        PathBuf::from("secrets.db")
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(toml::from_slice(&buffer)?)
    }

    pub fn policy_path(&self) -> &PathBuf {
        &self.policy_path
    }

    pub fn database_file(&self) -> &PathBuf {
        &self.database_file
    }
}
