use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

use crate::identity::PublicKey;
use crate::net::socket::{Datagram, Endpoint, PacketTx};

// Fits inside a 1500-byte path with IPv6, UDP, our prefix byte and WireGuard overhead.
pub const MTU: u16 = 1280;
const BUF: usize = 65536;
const KEEPALIVE_SECS: u16 = 25;
const TIMER_TICK: Duration = Duration::from_millis(250);
const MSG_COOKIE_REPLY: u8 = 3;
const MSG_DATA: u8 = 4;

pub trait TunDevice: Send + Sync + 'static {
    fn recv(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;
    fn send(&self, pkt: &[u8]) -> impl Future<Output = io::Result<usize>> + Send;
}

impl TunDevice for tun_rs::AsyncDevice {
    fn recv(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send {
        tun_rs::AsyncDevice::recv(self, buf)
    }

    fn send(&self, pkt: &[u8]) -> impl Future<Output = io::Result<usize>> + Send {
        tun_rs::AsyncDevice::send(self, pkt)
    }
}

pub fn dst_addr(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first()? >> 4 {
        4 => {
            let b: [u8; 4] = pkt.get(16..20)?.try_into().ok()?;
            Some(IpAddr::V4(b.into()))
        }
        6 => {
            let b: [u8; 16] = pkt.get(24..40)?.try_into().ok()?;
            Some(IpAddr::V6(b.into()))
        }
        _ => None,
    }
}

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub identity: PublicKey,
    pub name: String,
    pub wg_public: [u8; 32],
    pub endpoint: SocketAddr,
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
}

#[derive(Debug, Clone)]
pub struct PeerStats {
    pub name: String,
    pub endpoint: SocketAddr,
    pub last_handshake: Option<Duration>,
    pub tx_bytes: usize,
    pub rx_bytes: usize,
}

struct Peer {
    config: PeerConfig,
    // Members can be renamed in the manifest without rekeying.
    name: Mutex<String>,
    index: u32,
    tunn: Mutex<Tunn>,
    endpoint: Mutex<SocketAddr>,
}

#[derive(Default)]
struct Table {
    by_identity: HashMap<PublicKey, Arc<Peer>>,
    by_ip: HashMap<IpAddr, Arc<Peer>>,
    by_index: HashMap<u32, Arc<Peer>>,
    by_key: HashMap<[u8; 32], Arc<Peer>>,
}

impl Table {
    fn insert(&mut self, p: Arc<Peer>) {
        self.by_ip.insert(p.config.ipv4.into(), p.clone());
        self.by_ip.insert(p.config.ipv6.into(), p.clone());
        self.by_index.insert(p.index, p.clone());
        self.by_key.insert(p.config.wg_public, p.clone());
        self.by_identity.insert(p.config.identity.clone(), p);
    }

    fn remove(&mut self, identity: &PublicKey) -> Option<Arc<Peer>> {
        let p = self.by_identity.remove(identity)?;
        let same = |q: &Arc<Peer>| Arc::ptr_eq(q, &p);
        if self.by_ip.get(&p.config.ipv4.into()).is_some_and(same) {
            self.by_ip.remove(&p.config.ipv4.into());
        }
        if self.by_ip.get(&p.config.ipv6.into()).is_some_and(same) {
            self.by_ip.remove(&p.config.ipv6.into());
        }
        self.by_index.remove(&p.index);
        if self.by_key.get(&p.config.wg_public).is_some_and(same) {
            self.by_key.remove(&p.config.wg_public);
        }
        Some(p)
    }
}

struct Engine<T> {
    tun: T,
    tx: PacketTx,
    secret: [u8; 32],
    public: x25519::PublicKey,
    table: RwLock<Table>,
    next_index: AtomicU32,
}

pub struct WgEngine<T> {
    inner: Arc<Engine<T>>,
    tasks: Vec<JoinHandle<()>>,
}

impl<T> Drop for WgEngine<T> {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl<T: TunDevice> WgEngine<T> {
    pub fn new(tun: T, endpoint: Endpoint, wg_secret: [u8; 32]) -> Self {
        let public = x25519::PublicKey::from(&x25519::StaticSecret::from(wg_secret));
        let start: u32 = rand::random();
        let inner = Arc::new(Engine {
            tun,
            tx: endpoint.tx,
            secret: wg_secret,
            public,
            table: RwLock::new(Table::default()),
            next_index: AtomicU32::new(start),
        });
        let tasks = vec![
            tokio::spawn(tun_loop(inner.clone())),
            tokio::spawn(net_loop(inner.clone(), endpoint.rx)),
            tokio::spawn(timer_loop(inner.clone())),
        ];
        WgEngine { inner, tasks }
    }

    pub fn upsert_peer(&self, config: PeerConfig) {
        let mut table = self.inner.table.write().unwrap();
        if let Some(existing) = table.by_identity.get(&config.identity)
            && existing.config.wg_public == config.wg_public
        {
            *existing.endpoint.lock().unwrap() = config.endpoint;
            *existing.name.lock().unwrap() = config.name.clone();
            if existing.config.ipv4 == config.ipv4 && existing.config.ipv6 == config.ipv6 {
                return;
            }
        }
        if table
            .by_key
            .get(&config.wg_public)
            .is_some_and(|p| p.config.identity != config.identity)
        {
            warn!(peer = %config.name, "WireGuard key already belongs to another peer, ignoring");
            return;
        }
        table.remove(&config.identity);
        // boringtun shifts the index left by 8 to make room for session ids.
        let index = loop {
            let i = self.inner.next_index.fetch_add(1, Ordering::Relaxed) & 0x00ff_ffff;
            if !table.by_index.contains_key(&i) {
                break i;
            }
        };
        let tunn = Tunn::new(
            x25519::StaticSecret::from(self.inner.secret),
            x25519::PublicKey::from(config.wg_public),
            None,
            Some(KEEPALIVE_SECS),
            index,
            None,
        );
        info!(peer = %config.name, endpoint = %config.endpoint, ipv4 = %config.ipv4, "wireguard peer added");
        table.insert(Arc::new(Peer {
            name: Mutex::new(config.name.clone()),
            index,
            tunn: Mutex::new(tunn),
            endpoint: Mutex::new(config.endpoint),
            config,
        }));
    }

    pub fn remove_peer(&self, identity: &PublicKey) {
        if let Some(p) = self.inner.table.write().unwrap().remove(identity) {
            info!(peer = %p.name(), "wireguard peer removed");
        }
    }

    pub fn peer_config(&self, identity: &PublicKey) -> Option<PeerConfig> {
        let table = self.inner.table.read().unwrap();
        let p = table.by_identity.get(identity)?;
        Some(PeerConfig {
            name: p.name(),
            endpoint: *p.endpoint.lock().unwrap(),
            ..p.config.clone()
        })
    }

    pub fn identities(&self) -> Vec<PublicKey> {
        self.inner
            .table
            .read()
            .unwrap()
            .by_identity
            .keys()
            .cloned()
            .collect()
    }

    pub fn stats(&self) -> Vec<PeerStats> {
        self.inner
            .table
            .read()
            .unwrap()
            .by_identity
            .values()
            .map(|p| {
                let (last_handshake, tx_bytes, rx_bytes, ..) = p.tunn.lock().unwrap().stats();
                PeerStats {
                    name: p.name(),
                    endpoint: *p.endpoint.lock().unwrap(),
                    last_handshake,
                    tx_bytes,
                    rx_bytes,
                }
            })
            .collect()
    }
}

impl Peer {
    fn name(&self) -> String {
        self.name.lock().unwrap().clone()
    }

    // A peer may only send from its own overlay addresses.
    fn inner_source_ok(&self, src: IpAddr) -> bool {
        let ok = src == IpAddr::V4(self.config.ipv4) || src == IpAddr::V6(self.config.ipv6);
        if !ok {
            debug!(peer = %self.name(), %src, "dropping packet with spoofed source");
        }
        ok
    }
}

impl<T> Engine<T> {
    fn peer_for_ip(&self, ip: IpAddr) -> Option<Arc<Peer>> {
        self.table.read().unwrap().by_ip.get(&ip).cloned()
    }

    fn peer_for_packet(&self, data: &[u8]) -> Option<Arc<Peer>> {
        let table = self.table.read().unwrap();
        match Tunn::parse_incoming_packet(data).ok()? {
            Packet::HandshakeInit(p) => {
                let secret = x25519::StaticSecret::from(self.secret);
                let half = parse_handshake_anon(&secret, &self.public, &p).ok()?;
                table.by_key.get(&half.peer_static_public).cloned()
            }
            Packet::HandshakeResponse(p) => table.by_index.get(&(p.receiver_idx >> 8)).cloned(),
            Packet::PacketCookieReply(p) => table.by_index.get(&(p.receiver_idx >> 8)).cloned(),
            Packet::PacketData(p) => table.by_index.get(&(p.receiver_idx >> 8)).cloned(),
        }
    }

    fn peers(&self) -> Vec<Arc<Peer>> {
        self.table
            .read()
            .unwrap()
            .by_identity
            .values()
            .cloned()
            .collect()
    }
}

async fn tun_loop<T: TunDevice>(e: Arc<Engine<T>>) {
    let mut pkt = vec![0u8; BUF];
    let mut out = vec![0u8; BUF];
    loop {
        let n = match e.tun.recv(&mut pkt).await {
            Ok(n) => n,
            Err(err) => {
                debug!(error = %err, "tun read failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Some(dst) = dst_addr(&pkt[..n]) else {
            continue;
        };
        let Some(peer) = e.peer_for_ip(dst) else {
            trace!(%dst, "no peer for destination");
            continue;
        };
        let mut tunn = peer.tunn.lock().unwrap();
        match tunn.encapsulate(&pkt[..n], &mut out) {
            TunnResult::WriteToNetwork(p) => e.tx.send(*peer.endpoint.lock().unwrap(), p.to_vec()),
            TunnResult::Err(err) => trace!(peer = %peer.name(), ?err, "encapsulate failed"),
            _ => {}
        }
    }
}

async fn net_loop<T: TunDevice>(e: Arc<Engine<T>>, mut rx: mpsc::Receiver<Datagram>) {
    let mut buf = vec![0u8; BUF];
    while let Some((from, data)) = rx.recv().await {
        let Some(peer) = e.peer_for_packet(&data) else {
            trace!(addr = %from, "wireguard packet from unknown peer");
            continue;
        };
        let deliver = {
            let mut tunn = peer.tunn.lock().unwrap();
            // Only packets that prove the peer's keys may move its endpoint.
            // A cookie reply goes out to unverified senders under load, and a
            // bare cookie reply or handshake response proves nothing either.
            let authenticated;
            let deliver = match tunn.decapsulate(Some(from.ip()), &data, &mut buf) {
                TunnResult::WriteToNetwork(p) => {
                    authenticated = p.first() != Some(&MSG_COOKIE_REPLY);
                    e.tx.send(from, p.to_vec());
                    // Flush packets queued while the handshake was pending.
                    while let TunnResult::WriteToNetwork(p) = tunn.decapsulate(None, &[], &mut buf)
                    {
                        e.tx.send(from, p.to_vec());
                    }
                    None
                }
                TunnResult::WriteToTunnelV4(p, src) => {
                    authenticated = true;
                    peer.inner_source_ok(IpAddr::V4(src)).then(|| p.to_vec())
                }
                TunnResult::WriteToTunnelV6(p, src) => {
                    authenticated = true;
                    peer.inner_source_ok(IpAddr::V6(src)).then(|| p.to_vec())
                }
                // A decrypted keepalive.
                TunnResult::Done => {
                    authenticated = data.first() == Some(&MSG_DATA);
                    None
                }
                TunnResult::Err(err) => {
                    trace!(peer = %peer.name(), ?err, "decapsulate failed");
                    authenticated = false;
                    None
                }
            };

            // WireGuard roaming: follow the peer to wherever authenticated packets come from.
            if authenticated {
                *peer.endpoint.lock().unwrap() = from;
            }
            deliver
        };
        if let Some(p) = deliver
            && let Err(err) = e.tun.send(&p).await
        {
            debug!(error = %err, "tun write failed");
        }
    }
}

async fn timer_loop<T: TunDevice>(e: Arc<Engine<T>>) {
    let mut buf = vec![0u8; BUF];
    let mut tick = tokio::time::interval(TIMER_TICK);
    loop {
        tick.tick().await;
        for peer in e.peers() {
            let mut tunn = peer.tunn.lock().unwrap();
            if let TunnResult::WriteToNetwork(p) = tunn.update_timers(&mut buf) {
                e.tx.send(*peer.endpoint.lock().unwrap(), p.to_vec());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dst_parsing() {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[16..20].copy_from_slice(&[5, 6, 7, 8]);
        assert_eq!(dst_addr(&p), Some(IpAddr::V4([5, 6, 7, 8].into())));
        let mut p6 = vec![0u8; 40];
        p6[0] = 0x60;
        p6[39] = 1;
        assert_eq!(dst_addr(&p6), Some(IpAddr::V6(Ipv6Addr::from(1u128))));
        assert_eq!(dst_addr(&[0x45; 10]), None);
        assert_eq!(dst_addr(&[]), None);
        assert_eq!(dst_addr(&[0x10; 60]), None);
    }
}
