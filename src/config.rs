use atomic_write_file::AtomicWriteFile;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use rootcause::prelude::*;
use serde::{Deserialize, Serialize};

use crate::identity::PublicKey;

pub const DEFAULT_PORT: u16 = 41641;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub network_key: PublicKey,
    // Key spec, e.g. `soft:/var/lib/backscale/identity.key`.
    pub identity: String,
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    #[serde(default)]
    pub peers: Vec<SocketAddr>,
    #[serde(default = "default_true")]
    pub dht: bool,
    #[serde(default = "default_true")]
    pub tun: bool,
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
}

fn default_tun_name() -> String {
    "backscale0".into()
}

fn default_listen() -> SocketAddr {
    SocketAddr::from((crate::net::socket::DUAL_STACK_ANY, DEFAULT_PORT))
}

fn default_true() -> bool {
    true
}

pub struct StateDir(pub PathBuf);

impl StateDir {
    pub fn config(&self) -> PathBuf {
        self.0.join("config.toml")
    }

    pub fn identity_key(&self) -> PathBuf {
        self.0.join("identity.key")
    }

    pub fn manifest(&self) -> PathBuf {
        self.0.join("manifest.bsm")
    }

    pub fn session_keys(&self) -> PathBuf {
        self.0.join("session.keys")
    }

    pub fn peer_cache(&self) -> PathBuf {
        self.0.join("peers.cache")
    }

    pub fn dht_nodes(&self) -> PathBuf {
        self.0.join("dht.nodes")
    }

    pub fn control_socket(&self) -> PathBuf {
        self.0.join("control.sock")
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Report> {
        let text = std::fs::read_to_string(path)
            .context("failed to read config")
            .attach(format!("path: {}", path.display()))?;
        Ok(toml::from_str(&text)
            .context("failed to parse config")
            .attach(format!("path: {}", path.display()))?)
    }

    pub fn save(&self, path: &Path) -> Result<(), Report> {
        let text = toml::to_string_pretty(self).context("failed to encode config")?;
        let mut f = AtomicWriteFile::open(path)
            .context("failed to write config")
            .attach(format!("path: {}", path.display()))?;
        f.write_all(text.as_bytes())?;
        f.commit()?;
        Ok(())
    }
}
