use atomic_write_file::AtomicWriteFile;
use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;

use rootcause::prelude::*;
use serde::{Deserialize, Serialize};

use crate::identity::PublicKey;

pub const MAX_ENDPOINTS: usize = 8;

// Last known endpoints of each member, so a restarted node can dial members
// directly before gossip or the DHT topic turn them up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedPeer {
    pub endpoints: Vec<SocketAddr>,
    pub last_seen: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PeerCache {
    pub peers: HashMap<PublicKey, CachedPeer>,
}

impl PeerCache {
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|b| postcard::from_bytes(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<(), Report> {
        let mut f = AtomicWriteFile::open(path).context("failed to write peer cache")?;
        f.write_all(&postcard::to_stdvec(self)?)?;
        f.commit()?;
        Ok(())
    }

    // Gossip from other members is unverified: it may add peers we don't know
    // yet but never overrides what we learned from a verified session.
    pub fn insert_if_absent(&mut self, identity: &PublicKey, endpoints: &[SocketAddr], now: u64) {
        if !self.peers.contains_key(identity) {
            self.update(identity, endpoints, now);
        }
    }

    // Newest endpoints first, older ones kept behind them up to the limit.
    pub fn update(&mut self, identity: &PublicKey, endpoints: &[SocketAddr], now: u64) {
        let e = self
            .peers
            .entry(identity.clone())
            .or_insert_with(|| CachedPeer {
                endpoints: Vec::new(),
                last_seen: now,
            });
        e.last_seen = now;
        let mut merged: Vec<SocketAddr> = endpoints.to_vec();
        merged.extend(e.endpoints.iter().filter(|a| !endpoints.contains(a)));
        merged.truncate(MAX_ENDPOINTS);
        e.endpoints = merged;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Signer;
    use crate::identity::soft::SoftSigner;

    #[test]
    fn cache_merges_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.cache");
        let id = SoftSigner::generate().public_key();
        let a: SocketAddr = "1.1.1.1:1".parse().unwrap();
        let b: SocketAddr = "2.2.2.2:2".parse().unwrap();
        let mut cache = PeerCache::default();
        cache.update(&id, &[a], 10);
        cache.update(&id, &[b], 20);
        assert_eq!(cache.peers[&id].endpoints, vec![b, a]);
        cache.insert_if_absent(&id, &["3.3.3.3:3".parse().unwrap()], 30);
        assert_eq!(
            cache.peers[&id].endpoints,
            vec![b, a],
            "gossip must not override"
        );
        cache.save(&path).unwrap();
        assert_eq!(PeerCache::load(&path).peers[&id].endpoints, vec![b, a]);
        assert!(
            PeerCache::load(&dir.path().join("missing"))
                .peers
                .is_empty()
        );
    }
}
