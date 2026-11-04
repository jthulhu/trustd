use std::{
    collections::HashMap,
    error::Error,
    fs::File,
    io::Read,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::Parser;
use cli::Cli;
use config::Config;
use db::{OpenError, SecretStorage};
use futures_util::StreamExt;
use papaya::HashMap as CHashMap;
use thiserror::Error;
use trie_rs::{
    Trie as TrieSet, TrieBuilder as TrieSetBuilder,
    map::{Trie as TrieMap, TrieBuilder as TrieMapBuilder},
};
use trustd::{AuthenticationError, Secret, SecretError};
use xdg::BaseDirectories;
use zbus::{
    Connection, OwnedFd,
    fdo::DBusProxy,
    interface,
    message::Header,
    names::{BusName, OwnedUniqueName, OwnedWellKnownName},
};

mod cli;
mod config;
mod db;

#[derive(Debug, Error)]
pub enum TrustInitError {
    #[error("Could not initialize the name cache.")]
    NameCacheInit(#[from] NameCacheInitError),
    #[error("Cannot access the database file.")]
    XdgFile(#[from] std::io::Error),
    #[error("Could not initialize the secret storage.")]
    OpenStorage(#[from] OpenError),
    #[error("Could not load the policy data.")]
    AuthorizedPaths(#[from] AuthorizedPathsError),
}

#[derive(Debug, Error)]
pub enum NameCacheInitError {
    #[error("Cannot establish a DBus connection.")]
    DBusInit(#[from] zbus::Error),
    #[error("Cannot retrieve well-known names from the DBus session.")]
    DBusConn(#[from] zbus::fdo::Error),
}

#[derive(Debug, Error)]
pub enum AuthorizedPathsError {
    #[error("Cannot read the policy file.")]
    Io(#[from] std::io::Error),
    #[error("The policy file is invalid.")]
    Toml(#[from] toml::de::Error),
}

type NameCache = Arc<CHashMap<OwnedUniqueName, OwnedWellKnownName>>;

struct TrustBroker {
    authorized_paths: TrieMap<u8, TrieSet<u8>>,
    name_cache: NameCache,
    secret_storage: SecretStorage,
}

impl TrustBroker {
    async fn mk_authorized_paths(
        policy_path: &Path,
    ) -> Result<TrieMap<u8, TrieSet<u8>>, AuthorizedPathsError> {
        let buffer = {
            let mut file = File::open(policy_path)?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            buffer
        };
        let mut map_builder = TrieMapBuilder::new();
        for (name, paths) in toml::from_slice::<HashMap<String, Vec<String>>>(&buffer)? {
            let mut builder = TrieSetBuilder::new();
            for path in paths {
                let path = PathBuf::from(path);
                let path = path.canonicalize()?;
                builder.insert(path.as_os_str().as_bytes().iter().copied());
            }
            map_builder.insert(name.bytes(), builder.build());
        }
        Ok(map_builder.build())
    }

    async fn mk_name_cache() -> Result<NameCache, NameCacheInitError> {
        let connection = Connection::session().await?;
        let dbus_proxy = DBusProxy::new(&connection).await?;

        let name_cache: Arc<CHashMap<_, _>> = Arc::new({
            let map = CHashMap::new();
            let pinned_map = map.pin();
            for name in dbus_proxy.list_names().await? {
                if name.starts_with(':') {
                    continue;
                }
                let BusName::WellKnown(name) = name.into() else {
                    continue;
                };
                let Ok(owner) = dbus_proxy.get_name_owner(name.clone().into()).await else {
                    continue;
                };
                pinned_map.insert(owner, name.into());
            }
            drop(pinned_map);
            map
        });

        tokio::spawn({
            let mut stream = dbus_proxy.receive_name_owner_changed().await?;
            let name_cache = name_cache.clone();

            async move {
                while let Some(signal) = stream.next().await {
                    if let Ok(args) = signal.args() {
                        let name_cache = name_cache.pin();

                        let old_name = args.old_owner();

                        if let Some(ref name) = **old_name {
                            name_cache.remove(name.as_str());
                        }

                        let new_name = args.new_owner();
                        let BusName::WellKnown(well_known_name) = args.name().to_owned() else {
                            // Weird situation (I'm not sure this can happen), where the "owner" of a
                            // unique name is a unique name.
                            continue;
                        };

                        if let Some(ref name) = **new_name {
                            name_cache
                                .insert(name.to_owned().into(), well_known_name.to_owned().into());
                        }
                    }
                }
            }
        });

        Ok(name_cache)
    }

    pub async fn new(config: Config) -> Result<Self, TrustInitError> {
        let authorized_paths = Self::mk_authorized_paths(config.policy_path()).await?;

        // Building the secret storage.
        let base_dirs = BaseDirectories::with_prefix("ad._2mon.trustd");
        let db_path = base_dirs.place_data_file(config.database_file())?;
        let secret_storage = SecretStorage::open(db_path).await?;

        // Building the name cache.
        let name_cache = Self::mk_name_cache().await?;

        Ok(Self {
            authorized_paths,
            name_cache,
            secret_storage,
        })
    }
}

#[interface(name = "ad._2mon.Trust")]
impl TrustBroker {
    async fn is_authentic(&self, name: String, executable: PathBuf) -> bool {
        let Some(paths) = self.authorized_paths.exact_match(name) else {
            return false;
        };
        let Ok(executable) = executable.canonicalize() else {
            return false;
        };
        paths.exact_match(executable.as_os_str().as_bytes())
    }

    async fn get_auth_name(
        &self,
        name: OwnedUniqueName,
        pid_fd: OwnedFd,
    ) -> Result<OwnedWellKnownName, AuthenticationError> {
        let wkn = self
            .name_cache
            .pin()
            .get(&name)
            .ok_or(AuthenticationError::NoWellKnownName)?
            .to_owned();
        let path = PathBuf::from(format!("/proc/self/fd/{pid_fd}/exe"))
            .canonicalize()
            .map_err(|error| AuthenticationError::CannotCanonicalize(error.to_string()))?;
        let Some(paths) = self.authorized_paths.exact_match(wkn.as_bytes()) else {
            return Err(AuthenticationError::NotAuthorized);
        };
        if paths.exact_match(path.as_os_str().as_bytes()) {
            Ok(wkn.into())
        } else {
            return Err(AuthenticationError::NotAuthorized);
        }
    }

    async fn get_secret(&self, #[zbus(header)] header: Header<'_>) -> Result<Secret, SecretError> {
        let sender = header.sender().ok_or(SecretError::NoSender)?.to_owned();
        let connection = Connection::session().await?;
        let dbus_proxy = DBusProxy::new(&connection).await?;
        let process_fd = dbus_proxy
            .get_connection_credentials(sender.clone().into())
            .await?
            .into_process_fd()
            .ok_or(SecretError::NoPidFd)?;
        let wkn = self.get_auth_name(sender.into(), process_fd).await?;
        let secret = self.secret_storage.get_secret(wkn.as_str()).await?;
        Ok(secret)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let Cli {
        config: config_path,
    } = Cli::parse();

    let config = Config::load(config_path)?;
    let broker = TrustBroker::new(config).await?;

    let conn = zbus::connection::Builder::session()
        .name("ad._2mon.Trust")
        .serve_at("/ad/_2mon/Trust", broker)
        .build()
        .await?;

    conn.closed().await;

    Ok(())
}
