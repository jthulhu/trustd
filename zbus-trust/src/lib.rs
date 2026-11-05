#![doc = include_str!("../README.md")]

use zbus::{
    DBusError, OwnedFd,
    names::{OwnedUniqueName, OwnedWellKnownName},
    proxy,
};

pub type Secret = Box<[u8; 32]>;

#[derive(Debug, DBusError)]
#[zbus(prefix = "ad._2mon.Trust.AuthenticationError")]
pub enum AuthenticationError {
    NoWellKnownName,
    CannotCanonicalize(String),
    NotAuthorized,
    #[zbus(error)]
    DBus(zbus::Error),
}

#[derive(Debug, DBusError)]
#[zbus(prefix = "ad._2mon.Trust.SecretError")]
pub enum SecretError {
    NoSender,
    NoPidFd,
    Transport(String),
    DBusInterface(String),
    Authentication(String),
    CannotGetSecret(String),
    #[zbus(error)]
    DBus(zbus::Error),
}

impl From<zbus::fdo::Error> for SecretError {
    fn from(value: zbus::fdo::Error) -> Self {
        Self::DBusInterface(value.to_string())
    }
}

impl From<AuthenticationError> for SecretError {
    fn from(value: AuthenticationError) -> Self {
        if let AuthenticationError::DBus(error) = value {
            Self::DBus(error)
        } else {
            Self::Authentication(value.to_string())
        }
    }
}

#[proxy(
    interface = "ad._2mon.Trust",
    default_service = "ad._2mon.Trust",
    default_path = "/ad/_2mon/Trust"
)]
pub trait Trust {
    async fn get_auth_name(
        &self,
        name: OwnedUniqueName,
        pid_fd: OwnedFd,
    ) -> Result<OwnedWellKnownName, AuthenticationError>;

    async fn get_secret(&self) -> Result<Secret, SecretError>;

    #[zbus(signal)]
    async fn clear_cache(&self) -> Result<(), zbus::Error>;
}
