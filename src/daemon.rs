use atomic_write_file::AtomicWriteFile;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rootcause::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::binding::{DEFAULT_BINDING_LIFETIME_SECS, SessionKeys};
use crate::config::{Config, StateDir};
use crate::control::{ControlConfig, ControlEvent, ControlNode, PeerInfo};
use crate::discovery::{self, PeerCache};
use crate::identity::{KeySpec, PublicKey, Signer};
use crate::manifest::{NetworkManifest, SignedManifest};
use crate::net::dht::{Dht, DhtConfig};
use crate::net::socket::{Endpoint, UdpMux};
use crate::wg::{self, PeerConfig, WgEngine};
use backscale_utp::{UtpConfig, UtpSocket};

type Engine = WgEngine<tun_rs::AsyncDevice>;

const DISCOVERY_TICK: Duration = Duration::from_secs(30);
const DHT_ANNOUNCE_EVERY: Duration = Duration::from_secs(5 * 60);
const LAN_RETRY: Duration = Duration::from_secs(5 * 60);
const MAX_REQUEST: usize = 4 << 20;

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Status,
    Publish(SignedManifest),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Status(Box<Status>),
    Published(u64),
    Error(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
    pub identity: PublicKey,
    pub name: Option<String>,
    pub net_id: String,
    pub manifest_seq: u64,
    pub manifest_expires: Option<u64>,
    pub members: usize,
    // None: no ACL, every member may reach every member.
    pub acl_rules: Option<usize>,
    pub listen: SocketAddr,
    pub overlay: Option<(std::net::Ipv4Addr, std::net::Ipv6Addr)>,
    pub tun: Option<String>,
    pub dht_nodes: Option<usize>,
    pub external_ip: Option<Ipv4Addr>,
    pub peers: Vec<PeerStatus>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerStatus {
    pub name: String,
    pub identity: PublicKey,
    pub addr: SocketAddr,
    pub overlay: Option<std::net::Ipv4Addr>,
    // Connected, but the ACL forbids overlay traffic with it.
    pub blocked: bool,
    pub wg: Option<WgStatus>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WgStatus {
    pub endpoint: SocketAddr,
    pub handshake_secs_ago: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

struct Daemon {
    control: ControlNode,
    dht: Option<Arc<Dht>>,
    local: SocketAddr,
    wg: OnceLock<Arc<Engine>>,
    tun_name: String,
    dht_nodes_path: std::path::PathBuf,
    cache: Mutex<PeerCache>,
    cache_dirty: std::sync::atomic::AtomicBool,
    cache_path: std::path::PathBuf,
}

impl Daemon {
    fn save_cache(&self) {
        if self
            .cache_dirty
            .swap(false, std::sync::atomic::Ordering::Relaxed)
            && let Err(e) = self.cache.lock().unwrap().save(&self.cache_path)
        {
            warn!(error = %e, "failed to save peer cache");
        }
    }
}

pub async fn run(dir: StateDir) -> Result<(), Report> {
    let config = Config::load(&dir.config())?;
    let spec: KeySpec = config.identity.parse()?;
    let identity: Arc<dyn Signer> = Arc::from(spec.open().context("failed to open identity key")?);

    let mux = UdpMux::bind(config.listen).await?;
    let local = mux.local_addr;
    let utp = Arc::new(UtpSocket::new(mux.utp, UtpConfig::default()));
    let control = ControlNode::new(
        ControlConfig {
            network_key: config.network_key.clone(),
            manifest_path: Some(dir.manifest()),
        },
        identity.as_ref(),
        load_or_create_keys(&dir)?,
        utp,
    )?;
    control.start();
    let dht = config.dht.then(|| {
        let config = DhtConfig {
            nodes: load_dht_nodes(&dir),
            ..Default::default()
        };
        Arc::new(Dht::new(config, mux.dht))
    });
    let wg_endpoint = mux.wg;
    let _tasks = mux.tasks;

    info!(
        identity = %control.identity(),
        net_id = %control.net_id(),
        %local,
        manifest_seq = control.manifest_seq(),
        "backscale up"
    );

    let daemon = Arc::new(Daemon {
        control,
        dht,
        local,
        wg: OnceLock::new(),
        tun_name: config.tun_name.clone(),
        dht_nodes_path: dir.dht_nodes(),
        cache: Mutex::new(PeerCache::load(&dir.peer_cache())),
        cache_dirty: Default::default(),
        cache_path: dir.peer_cache(),
    });
    if config.tun {
        let d = daemon.clone();
        tokio::spawn(async move {
            if let Err(e) = dataplane(&d, wg_endpoint).await {
                tracing::error!(error = %e, "data plane failed");
            }
        });
    }
    tokio::spawn(refresh_binding(daemon.control.clone(), identity));
    let listener = bind_control_socket(&dir)?;
    tokio::spawn(serve_control(listener, daemon.clone()));
    let (lan_tx, lan_rx) = tokio::sync::mpsc::channel(64);
    if config.lan_discovery {
        tokio::spawn(crate::net::lan::run(
            daemon.control.net_id(),
            local.port(),
            lan_tx,
        ));
    }
    tokio::spawn(discovery(daemon.clone(), config.peers.clone(), lan_rx));
    tokio::spawn(track_events(daemon.clone()));

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        r = tokio::signal::ctrl_c() => r.context("failed to wait for ctrl-c")?,
        _ = term.recv() => {}
    }
    info!("shutting down");
    let _ = std::fs::remove_file(dir.control_socket());
    Ok(())
}

async fn refresh_binding(control: ControlNode, identity: Arc<dyn Signer>) {
    let every = Duration::from_secs(DEFAULT_BINDING_LIFETIME_SECS / 2);
    // A failed refresh must not wait a full period: by then the binding expires.
    let retry = Duration::from_secs(600);
    let mut wait = every;
    loop {
        tokio::time::sleep(wait).await;
        let control = control.clone();
        let identity = identity.clone();
        // Hardware keys may block for PIN entry or touch.
        let res =
            tokio::task::spawn_blocking(move || control.refresh_binding(identity.as_ref())).await;
        wait = match res {
            Ok(Ok(())) => {
                info!("device binding refreshed");
                every
            }
            Ok(Err(e)) => {
                warn!(error = %e, "failed to refresh device binding, retrying in 10 minutes");
                retry
            }
            Err(e) => {
                warn!(error = %e, "binding refresh task failed, retrying in 10 minutes");
                retry
            }
        };
    }
}

// Peers the ACL doesn't allow get no WireGuard peer at all, so neither side
// can send overlay traffic; the control session stays up.
fn peer_config(manifest: &NetworkManifest, me: &PublicKey, info: &PeerInfo) -> Option<PeerConfig> {
    if !manifest.allows(me, &info.identity) {
        return None;
    }
    let member = manifest.member(&info.identity)?;
    Some(PeerConfig {
        identity: info.identity.clone(),
        name: member.name.clone(),
        wg_public: info.binding.wg_public,
        endpoint: info.addr,
        ipv4: member.ipv4,
        ipv6: member.ipv6,
    })
}

fn reconcile(engine: &Engine, control: &ControlNode) {
    let Some(manifest) = control.manifest() else {
        return;
    };
    let me = control.identity();
    for id in engine.identities() {
        let Some(member) = manifest.member(&id).filter(|_| manifest.allows(me, &id)) else {
            engine.remove_peer(&id);
            continue;
        };
        // Tunnels outlive control sessions, so apply address and name
        // changes here too, not only for peers with a live session.
        if let Some(mut cfg) = engine.peer_config(&id) {
            cfg.name = member.name.clone();
            cfg.ipv4 = member.ipv4;
            cfg.ipv6 = member.ipv6;
            engine.upsert_peer(cfg);
        }
    }
    for info in control.peers() {
        if let Some(cfg) = peer_config(&manifest, me, &info) {
            engine.upsert_peer(cfg);
        }
    }
}

async fn dataplane(d: &Daemon, endpoint: Endpoint) -> Result<(), Report> {
    let mut events = d.control.subscribe();
    let (me, settings) = loop {
        if let Some(m) = d.control.manifest()
            && let Some(me) = m.member(d.control.identity())
        {
            break (me.clone(), m.settings.clone());
        }
        info!("waiting for a manifest that lists this node");
        loop {
            match events.recv().await {
                Ok(ControlEvent::ManifestUpdated { .. })
                | Err(broadcast::error::RecvError::Lagged(_)) => break,
                Ok(_) => {}
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            }
        }
    };
    let dev = tun_rs::DeviceBuilder::new()
        .name(&d.tun_name)
        .mtu(wg::MTU)
        .ipv4(me.ipv4, settings.ipv4_prefix.prefix_len(), None)
        .ipv6(me.ipv6, settings.ipv6_prefix.prefix_len())
        .build_async()
        .context("failed to create TUN device (needs root or CAP_NET_ADMIN)")
        .attach(format!("device: {}", d.tun_name))?;
    info!(dev = %d.tun_name, ipv4 = %me.ipv4, ipv6 = %me.ipv6, "TUN device up");
    let engine = Arc::new(WgEngine::new(
        dev,
        endpoint,
        d.control.session_keys().wg.to_bytes(),
    ));
    let _ = d.wg.set(engine.clone());
    reconcile(&engine, &d.control);

    loop {
        match events.recv().await {
            Ok(ControlEvent::PeerUp(info)) => {
                if let Some(m) = d.control.manifest()
                    && let Some(cfg) = peer_config(&m, d.control.identity(), &info)
                {
                    engine.upsert_peer(cfg);
                }
            }
            Ok(ControlEvent::ManifestUpdated { .. }) => {
                if let Some(m) = d.control.manifest()
                    && let Some(new_me) = m.member(d.control.identity())
                    && (new_me.ipv4 != me.ipv4 || new_me.ipv6 != me.ipv6)
                {
                    warn!(ipv4 = %new_me.ipv4, ipv6 = %new_me.ipv6, "our overlay address changed; restart to apply");
                }
                reconcile(&engine, &d.control);
            }
            // The tunnel outlives the control session; membership is what counts.
            Ok(ControlEvent::PeerDown(_) | ControlEvent::Advertised(_)) => {}
            Err(broadcast::error::RecvError::Lagged(_)) => reconcile(&engine, &d.control),
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

// Previously seen DHT nodes make the next bootstrap independent of the
// public routers.
fn load_dht_nodes(dir: &StateDir) -> Vec<SocketAddr> {
    std::fs::read(dir.dht_nodes())
        .ok()
        .and_then(|b| postcard::from_bytes(&b).ok())
        .unwrap_or_default()
}

fn save_dht_nodes(d: &Daemon, dht: &Dht) {
    let nodes: Vec<SocketAddr> = dht.nodes().into_iter().map(|n| n.addr).take(200).collect();
    if nodes.is_empty() {
        return;
    }
    let bytes = postcard::to_stdvec(&nodes).expect("addresses always encode");
    let write = || -> std::io::Result<()> {
        let mut f = AtomicWriteFile::open(&d.dht_nodes_path)?;
        f.write_all(&bytes)?;
        f.commit()
    };
    if let Err(e) = write() {
        debug!(error = %e, "failed to save DHT nodes");
    }
}

fn load_or_create_keys(dir: &StateDir) -> Result<SessionKeys, Report> {
    let path = dir.session_keys();
    if path.exists() {
        return SessionKeys::load(&path);
    }
    let keys = SessionKeys::generate();
    keys.save(&path)?;
    Ok(keys)
}

async fn track_events(d: Arc<Daemon>) {
    let mut rx = d.control.subscribe();
    loop {
        let ev = match rx.recv().await {
            Ok(ev) => ev,
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => return,
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        match ev {
            ControlEvent::PeerUp(p) => {
                info!(peer = %p.name, addr = %p.addr, "peer up");
                d.cache
                    .lock()
                    .unwrap()
                    .update(&p.identity, &p.endpoints(), now);
                d.cache_dirty
                    .store(true, std::sync::atomic::Ordering::Relaxed);
            }
            ControlEvent::PeerDown(id) => info!(peer = %id.fingerprint(), "peer down"),
            ControlEvent::ManifestUpdated { seq, .. } => info!(seq, "manifest updated"),
            ControlEvent::Advertised(ad) => {
                let member = d
                    .control
                    .manifest()
                    .is_some_and(|m| m.member(&ad.identity).is_some());
                if member {
                    d.cache
                        .lock()
                        .unwrap()
                        .insert_if_absent(&ad.identity, &ad.endpoints, now);
                    d.cache_dirty
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
    }
}

fn local_addrs(local: SocketAddr, manifest: Option<&NetworkManifest>) -> Vec<SocketAddr> {
    if !local.ip().is_unspecified() {
        return vec![local];
    }
    let overlay4 = manifest.map(|m| m.settings.ipv4_prefix);
    let overlay6 = manifest.map(|m| m.settings.ipv6_prefix);
    // An IPv4-only socket (no IPv6 on the host) can't use IPv6 endpoints.
    let dual_stack = local.is_ipv6();
    let mut addrs: Vec<SocketAddr> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback())
        .filter_map(|i| match i.ip() {
            IpAddr::V4(v4) if !v4.is_link_local() && !overlay4.is_some_and(|p| p.contains(&v4)) => {
                Some(SocketAddr::new(v4.into(), local.port()))
            }
            IpAddr::V6(v6)
                if dual_stack
                    && !v6.is_unicast_link_local()
                    && !v6.is_multicast()
                    && !overlay6.is_some_and(|p| p.contains(&v6)) =>
            {
                Some(SocketAddr::new(v6.into(), local.port()))
            }
            _ => None,
        })
        .collect();
    // IPv4 first: it is what most peers can reach.
    addrs.sort_by_key(|a| a.is_ipv6());
    addrs.dedup();
    addrs.truncate(discovery::MAX_ENDPOINTS);
    addrs
}

async fn discovery(
    d: Arc<Daemon>,
    static_peers: Vec<SocketAddr>,
    mut lan: tokio::sync::mpsc::Receiver<SocketAddr>,
) {
    let connecting: Arc<Mutex<HashSet<SocketAddr>>> = Arc::default();
    let try_connect = |addr: SocketAddr| {
        if addr == d.local
            || d.control.is_self(addr)
            || d.control.is_connected_to(addr)
            || !connecting.lock().unwrap().insert(addr)
        {
            return;
        }
        let d = d.clone();
        let connecting = connecting.clone();
        tokio::spawn(async move {
            if let Err(e) = d.control.connect(addr).await {
                debug!(%addr, error = %e, "connect failed");
            }
            connecting.lock().unwrap().remove(&addr);
        });
    };

    let mut bootstrapped = false;
    let mut last_announce: Option<Instant> = None;
    // Peers re-announce every 30s, also when already connected over another address.
    let mut lan_tried: HashMap<SocketAddr, Instant> = HashMap::new();
    let mut tick = tokio::time::interval(DISCOVERY_TICK);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            Some(addr) = lan.recv() => {
                let known = d.control.peers().iter().any(|p| p.endpoints().contains(&addr));
                let recent = lan_tried.get(&addr).is_some_and(|t| t.elapsed() < LAN_RETRY);
                if !known && !recent {
                    lan_tried.insert(addr, Instant::now());
                    try_connect(addr);
                }
                continue;
            }
        }
        lan_tried.retain(|_, t| t.elapsed() < LAN_RETRY);
        let manifest = d.control.manifest();
        d.control
            .set_local_addrs(local_addrs(d.local, manifest.as_ref()));
        for p in &static_peers {
            try_connect(*p);
        }
        let unconnected: Vec<(PublicKey, Vec<SocketAddr>)> = {
            let cache = d.cache.lock().unwrap();
            manifest
                .iter()
                .flat_map(|m| m.members.iter())
                .filter(|m| {
                    &m.identity != d.control.identity() && !d.control.is_verified(&m.identity)
                })
                .filter_map(|m| {
                    cache
                        .peers
                        .get(&m.identity)
                        .map(|c| (m.identity.clone(), c.endpoints.clone()))
                })
                .collect()
        };
        for (id, endpoints) in &unconnected {
            d.control.dial(id, endpoints);
        }
        d.save_cache();

        let Some(dht) = &d.dht else { continue };
        if !bootstrapped {
            match dht.bootstrap().await {
                Ok(_) => bootstrapped = true,
                Err(e) => {
                    warn!(error = %e, "DHT bootstrap failed");
                    continue;
                }
            }
        }
        if last_announce.is_some_and(|t| t.elapsed() < DHT_ANNOUNCE_EVERY) {
            continue;
        }
        last_announce = Some(Instant::now());
        save_dht_nodes(&d, dht);
        let topic = crate::net::topic(
            &d.control.net_id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        let announced = dht.announce(topic, d.local.port(), true).await;
        if announced.stored == 0 {
            debug!("DHT announce was not accepted by any node");
        }
        // Our own entry (with the NAT-mapped port) is dialed at most once:
        // the handshake reveals it and the control plane remembers it.
        for peer in announced.peers {
            try_connect(peer);
        }
    }
}

fn bind_control_socket(dir: &StateDir) -> Result<UnixListener, Report> {
    let path = dir.control_socket();
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)
        .context("failed to bind control socket")
        .attach(format!("path: {}", path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

async fn serve_control(listener: UnixListener, d: Arc<Daemon>) {
    loop {
        let mut stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                // e.g. out of file descriptors; back off rather than spin.
                warn!(error = %e, "control socket accept failed");
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
        };
        let d = d.clone();
        tokio::spawn(async move {
            let resp = match read_frame::<Request>(&mut stream).await {
                Ok(req) => handle(&d, req),
                Err(e) => Response::Error(e.to_string()),
            };
            let _ = write_frame(&mut stream, &resp).await;
        });
    }
}

fn handle(d: &Daemon, req: Request) -> Response {
    match req {
        Request::Status => {
            let manifest = d.control.manifest();
            let name = manifest
                .as_ref()
                .and_then(|m| m.member(d.control.identity()))
                .map(|m| m.name.clone());
            let wg_stats: std::collections::HashMap<String, wg::PeerStats> =
                d.wg.get()
                    .map(|e| e.stats().into_iter().map(|s| (s.name.clone(), s)).collect())
                    .unwrap_or_default();
            let mut peers: Vec<PeerStatus> = d
                .control
                .peers()
                .into_iter()
                .map(|p| PeerStatus {
                    overlay: manifest
                        .as_ref()
                        .and_then(|m| m.member(&p.identity))
                        .map(|m| m.ipv4),
                    blocked: manifest
                        .as_ref()
                        .is_some_and(|m| !m.allows(d.control.identity(), &p.identity)),
                    wg: wg_stats.get(&p.name).map(|s| WgStatus {
                        endpoint: s.endpoint,
                        handshake_secs_ago: s.last_handshake.map(|d| d.as_secs()),
                        tx_bytes: s.tx_bytes as u64,
                        rx_bytes: s.rx_bytes as u64,
                    }),
                    name: p.name,
                    identity: p.identity,
                    addr: p.addr,
                })
                .collect();
            peers.sort_by(|a, b| a.name.cmp(&b.name));
            Response::Status(Box::new(Status {
                identity: d.control.identity().clone(),
                name,
                net_id: d.control.net_id().to_string(),
                manifest_seq: d.control.manifest_seq(),
                manifest_expires: manifest.as_ref().map(|m| m.expires_at),
                members: manifest.as_ref().map_or(0, |m| m.members.len()),
                acl_rules: manifest
                    .as_ref()
                    .and_then(|m| m.acl.as_ref())
                    .map(|a| a.len()),
                listen: d.local,
                overlay: manifest
                    .as_ref()
                    .and_then(|m| m.member(d.control.identity()))
                    .map(|m| (m.ipv4, m.ipv6)),
                tun: d.wg.get().map(|_| d.tun_name.clone()),
                dht_nodes: d.dht.as_ref().map(|d| d.table_size()),
                external_ip: d.dht.as_ref().and_then(|d| d.external_ip()),
                peers,
            }))
        }
        Request::Publish(signed) => match d.control.publish(signed) {
            Ok(seq) => Response::Published(seq),
            Err(e) => Response::Error(e.to_string()),
        },
    }
}

async fn read_frame<T: serde::de::DeserializeOwned>(s: &mut UnixStream) -> Result<T, Report> {
    let len = s.read_u32().await? as usize;
    if len > MAX_REQUEST {
        bail!("control request too large");
    }
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await?;
    Ok(postcard::from_bytes(&buf).context("malformed control request")?)
}

async fn write_frame<T: Serialize>(s: &mut UnixStream, msg: &T) -> Result<(), Report> {
    let buf = postcard::to_stdvec(msg)?;
    s.write_u32(buf.len() as u32).await?;
    s.write_all(&buf).await?;
    Ok(())
}

pub async fn request(dir: &StateDir, req: Request) -> Result<Response, Report> {
    let path = dir.control_socket();
    let mut s = UnixStream::connect(&path)
        .await
        .context("failed to reach the daemon (is `backscale up` running?)")
        .attach(format!("socket: {}", path.display()))?;
    write_frame(&mut s, &req).await?;
    read_frame(&mut s).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::DeviceBinding;
    use crate::identity::soft::SoftSigner;
    use crate::manifest::ManifestDraft;

    fn info(identity: PublicKey, net: &NetworkManifest) -> PeerInfo {
        let addr: SocketAddr = "192.0.2.1:41641".parse().unwrap();
        PeerInfo {
            name: String::new(),
            addr,
            binding: DeviceBinding {
                net_id: net.net_id,
                identity: identity.clone(),
                wg_public: [7; 32],
                noise_public: [8; 32],
                issued_at: 0,
                expires_at: u64::MAX,
            },
            identity,
            observed_us: addr,
            local_addrs: vec![],
        }
    }

    #[test]
    fn peer_config_honours_acl() {
        let net = SoftSigner::generate();
        let ids: Vec<PublicKey> = (0..3)
            .map(|_| SoftSigner::generate().public_key())
            .collect();
        let mut d = ManifestDraft::new(net.public_key(), "home".into()).unwrap();
        for (i, id) in ids.iter().enumerate() {
            d.add_member(id.clone(), format!("node{i}"), None, None, vec![])
                .unwrap();
        }
        let open = d.next_manifest(1, 100);
        assert!(peer_config(&open, &ids[0], &info(ids[2].clone(), &open)).is_some());

        d.add_acl(
            vec!["node0".parse().unwrap()],
            vec!["node1".parse().unwrap()],
        )
        .unwrap();
        let m = d.next_manifest(1, 100);
        let cfg = peer_config(&m, &ids[0], &info(ids[1].clone(), &m)).unwrap();
        assert_eq!(cfg.name, "node1");
        assert!(peer_config(&m, &ids[0], &info(ids[2].clone(), &m)).is_none());
        assert!(peer_config(&m, &ids[2], &info(ids[1].clone(), &m)).is_none());
    }
}
