//! `trustd` is a library to communicate with the trust broker.  The trust broker is a service
//! whose purpose is to allow your sandboxed applications to:
//!  - Get an authenticated well-known name for other applications that it communicates with,
//!    that is, both a well-known name that the application owns and that it has the right to
//!    own.  This allows your applications to store a permission map, associating permissions
//!    to well-known names.
//!  - Get a persistent, 256-bits secret, that no other (sandboxed) application has
//!    access to.  You can use this secret to subsequently encrypt your local storage.

use thiserror::Error;
use zbus::{
    Connection, DBusError, OwnedFd,
    fdo::DBusProxy,
    message::Header,
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

#[derive(Debug, Error)]
pub enum ErrorKind {
    #[error("Trust error")]
    Trust(#[from] AuthenticationError),
    #[error("DBus error")]
    DBusFdo(#[from] zbus::fdo::Error),
    #[error("IO error")]
    Io(#[from] std::io::Error),
    #[error("method has no authenticated sender")]
    NoSender,
    #[error("DBus broker doesn't support PID FD")]
    NoPidFd,
}

impl From<zbus::Error> for ErrorKind {
    fn from(value: zbus::Error) -> Self {
        AuthenticationError::from(value).into()
    }
}

#[proxy(
    interface = "ad._2mon.Trust",
    default_service = "ad._2mon.Trust",
    default_path = "/ad/_2mon/Trust"
)]
trait Trust {
    async fn get_auth_name(
        &self,
        name: OwnedUniqueName,
        pid_fd: OwnedFd,
    ) -> Result<OwnedWellKnownName, AuthenticationError>;

    async fn get_secret(&self) -> Result<Secret, SecretError>;
}

/// Returns the well-known name of the client, that has been authenticated.  This means you can
/// trust that the client is who you think it is.  Returns `None` if no such name can be
/// authenticated.
pub async fn authenticated_name(header: Header<'_>) -> Result<OwnedWellKnownName, ErrorKind> {
    let sender = header.sender().ok_or(ErrorKind::NoSender)?;

    let connection = Connection::session().await?;
    let dbus_proxy = DBusProxy::new(&connection).await?;
    let trust_proxy = TrustProxy::new(&connection).await?;

    let process_fd = dbus_proxy
        .get_connection_credentials(sender.to_owned().into())
        .await?
        .into_process_fd()
        .ok_or(ErrorKind::NoPidFd)?;

    let name = trust_proxy
        .get_auth_name(sender.to_owned().into(), process_fd)
        .await?;
    Ok(name)
}

/// Retrieve a unique, persistent 256-bit secret key.
///
/// You will only get a secret if the trust broker is capable of authenticating you.  The
/// authentication doesn't require you to provide any information, it is based on information
/// that the kernel provides about your process, and that you cannot spoof.
///
/// The secret is unique per-application, and is persistent, meaning you will always get the same
/// secret, as long as your authentication doesn't change, even across reboots.
pub async fn get_secret() -> Result<Secret, SecretError> {
    let connection = Connection::session().await?;
    let trust_proxy = TrustProxy::new(&connection).await?;
    let secret = trust_proxy.get_secret().await?;
    Ok(secret)
}
