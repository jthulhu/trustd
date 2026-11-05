#![doc = include_str!("../README.md")]

use std::{fmt::Display, sync::Arc};

use futures_util::StreamExt;
use papaya::HashMap as CHashMap;
use thiserror::Error;
use zbus::{
    Connection,
    fdo::DBusProxy,
    message::Header,
    names::{OwnedUniqueName, OwnedWellKnownName},
};
use zbus_trust::{AuthenticationError, Secret, SecretError, TrustProxy};

#[derive(Debug)]
#[non_exhaustive]
pub struct AuthError {
    pub kind: Box<AuthErrorKind>,
}

impl<T: Into<AuthErrorKind>> From<T> for AuthError {
    fn from(error_kind: T) -> Self {
        Self {
            kind: Box::new(error_kind.into()),
        }
    }
}

impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.kind.fmt(f)
    }
}

impl std::error::Error for AuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.kind.source()
    }
}

#[derive(Debug, Error)]
pub enum AuthErrorKind {
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

impl From<zbus::Error> for AuthErrorKind {
    fn from(value: zbus::Error) -> Self {
        AuthenticationError::from(value).into()
    }
}

type NameCache = CHashMap<OwnedUniqueName, OwnedWellKnownName>;

#[derive(Debug, Error)]
pub enum NewError {
    #[error("Could not establish a connection to the trust broker.")]
    DBus(#[from] zbus::Error),
}

/// A high-level access to the authenticator's feature of the trust broker.  Note that
/// authenticator objects are much cheaper to clone than to create (which is reflected by the
/// fact that creating one such object might fail), so you are advised to create the
/// authenticator only once, and share it.
#[derive(Debug, Clone)]
pub struct Authenticator {
    /// Cache of authenticated names.  This is safe, because unique names are truly unique: D-Bus
    /// never allocates them again after a process disconnects.
    ///
    /// The cache has to be cleared if the Trust broker restarts, because certain authenticated
    /// names might not be authenticated anymore.
    cache: Arc<NameCache>,
}

impl Authenticator {
    /// Creates a new [`Authenticator`] object.
    pub async fn new() -> Result<Self, NewError> {
        let cache: Arc<NameCache> = Arc::default();

        tokio::spawn({
            let connection = Connection::session().await?;
            let trust_proxy = TrustProxy::new(&connection).await?;
            let mut stream = trust_proxy.receive_clear_cache().await?;
            let cache = cache.clone();
            async move {
                loop {
                    if stream.next().await.is_some() {
                        cache.pin().clear();
                    };
                }
            }
        });
        Ok(Self { cache })
    }

    /// Returns the well-known name of the client, that has been authenticated.  This means you
    /// can trust that the client is who you think it is.  Fails is no such name can be
    /// authenticated for the client.
    pub async fn authenticated_name(
        &self,
        header: &Header<'_>,
    ) -> Result<OwnedWellKnownName, AuthError> {
        let sender = header.sender().ok_or(AuthErrorKind::NoSender)?;

        let cache = self.cache.pin();
        if let Some(wkn) = cache.get(sender) {
            return Ok(wkn.to_owned().into());
        }

        let connection = Connection::session().await?;
        let dbus_proxy = DBusProxy::new(&connection).await?;
        let trust_proxy = TrustProxy::new(&connection).await?;

        let process_fd = dbus_proxy
            .get_connection_credentials(sender.to_owned().into())
            .await?
            .into_process_fd()
            .ok_or(AuthErrorKind::NoPidFd)?;

        let name = trust_proxy
            .get_auth_name(sender.to_owned().into(), process_fd)
            .await?;
        cache.insert(sender.to_owned().into(), name.clone());
        Ok(name)
    }
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
