//! A BitTorrent mainline DHT node (BEP 5, 32, 42) over any datagram
//! transport: a plain UDP socket via [`Transport::udp`], or one protocol's
//! share of a multiplexed socket.

#![forbid(unsafe_code)]

pub mod krpc;
pub mod lookup;
pub mod node_id;
pub mod routing;
pub mod server;
pub mod wire;

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_bytes::ByteBuf;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, trace};

use self::krpc::Rpc;
pub use self::krpc::RpcError;
use self::lookup::{Kind, LookupResult, lookup};
pub use self::node_id::NodeId;
use self::routing::{K, RoutingTable};
use self::server::Server;
pub use self::wire::NodeInfo;
use self::wire::{Args, Message, Resp};

const UDP_QUEUE: usize = 1024;

pub type Datagram = (SocketAddr, Vec<u8>);

/// Where KRPC messages come from and go to. Senders never block: a full queue
/// drops the message, as a congested link would.
pub struct Transport {
    pub rx: mpsc::Receiver<Datagram>,
    pub tx: mpsc::Sender<Datagram>,
}

impl Transport {
    /// A transport owning `socket` exclusively. The returned task receives;
    /// sending runs in its own task (so both can use separate threads) and
    /// ends once every sender is dropped.
    pub fn udp(socket: Arc<UdpSocket>) -> (Self, JoinHandle<()>) {
        let (in_tx, rx) = mpsc::channel(UDP_QUEUE);
        let (tx, mut out_rx) = mpsc::channel::<Datagram>(UDP_QUEUE);
        let v6 = socket.local_addr().is_ok_and(|a| a.is_ipv6());
        let send_sock = socket.clone();
        tokio::spawn(async move {
            while let Some((to, data)) = out_rx.recv().await {
                if to.is_ipv6() && !v6 {
                    continue;
                }
                let to = if v6 { mapped(to) } else { to };
                let _ = send_sock.send_to(&data, to).await;
            }
        });
        let recv = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                    continue;
                };
                let _ = in_tx.try_send((canonical(from), buf[..n].to_vec()));
            }
        });
        (Transport { rx, tx }, recv)
    }
}

fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(v4.into(), addr.port()),
            None => addr,
        },
        IpAddr::V4(_) => addr,
    }
}

fn mapped(addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(v4) => SocketAddr::new(v4.to_ipv6_mapped().into(), addr.port()),
        IpAddr::V6(_) => addr,
    }
}

#[derive(Clone)]
pub(crate) struct PacketTx(mpsc::Sender<Datagram>);

impl PacketTx {
    pub(crate) fn send(&self, addr: SocketAddr, data: Vec<u8>) {
        if self.0.try_send((addr, data)).is_err() {
            trace!(%addr, "outgoing queue full, dropping packet");
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhtError {
    NoBootstrapNodes,
    BootstrapFailed,
}

impl fmt::Display for DhtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DhtError::NoBootstrapNodes => "no bootstrap nodes available",
            DhtError::BootstrapFailed => "bootstrap failed: no nodes responded",
        })
    }
}

impl std::error::Error for DhtError {}

pub const DEFAULT_ROUTERS: &[&str] = &[
    "router.bittorrent.com:6881",
    "dht.transmissionbt.com:6881",
    "router.utorrent.com:6881",
    "dht.libtorrent.org:25401",
];

const MAINTAIN_EVERY: Duration = Duration::from_secs(30);
const BUCKET_REFRESH: Duration = Duration::from_secs(15 * 60);
const IP_VOTES: usize = 32;
const MAX_VERIFYING: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    V4 = 0,
    V6 = 1,
}

impl Family {
    pub const ALL: [Family; 2] = [Family::V4, Family::V6];

    pub fn of(addr: &SocketAddr) -> Self {
        if addr.is_ipv6() {
            Family::V6
        } else {
            Family::V4
        }
    }

    pub fn want_tag(self) -> &'static [u8] {
        match self {
            Family::V4 => b"n4",
            Family::V6 => b"n6",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DhtConfig {
    // host:port strings, resolved at bootstrap.
    pub routers: Vec<String>,
    // Previously known nodes (e.g. persisted routing table).
    pub nodes: Vec<SocketAddr>,
    pub query_timeout: Duration,
    // Fixed node id; otherwise a BEP 42 id is derived once our external IP is known.
    pub id: Option<NodeId>,
    // The KRPC `v` field: a two-letter client code and a version (BEP 20 style).
    pub client_version: Option<Vec<u8>>,
}

impl Default for DhtConfig {
    fn default() -> Self {
        DhtConfig {
            routers: DEFAULT_ROUTERS.iter().map(|s| s.to_string()).collect(),
            nodes: Vec::new(),
            query_timeout: Duration::from_secs(2),
            id: None,
            client_version: None,
        }
    }
}

pub struct Inner {
    rpc: Rpc,
    // Indexed by `Family`; both share our node id.
    tables: [Mutex<RoutingTable>; 2],
    server: Mutex<Server>,
    votes: Mutex<VecDeque<IpAddr>>,
    verifying: Mutex<HashSet<SocketAddr>>,
    config: DhtConfig,
}

impl Inner {
    fn table(&self, f: Family) -> MutexGuard<'_, RoutingTable> {
        self.tables[f as usize].lock().unwrap()
    }

    fn own_id(&self) -> NodeId {
        self.table(Family::V4).own_id()
    }

    fn total_nodes(&self) -> usize {
        Family::ALL.iter().map(|f| self.table(*f).len()).sum()
    }

    async fn query(
        &self,
        addr: SocketAddr,
        expect: Option<NodeId>,
        q: &[u8],
        args: Args,
    ) -> Result<Resp, RpcError> {
        let family = Family::of(&addr);
        match self.rpc.query(addr, self.own_id(), q, args).await {
            Ok(reply) => {
                if let Some(seen) = reply.seen_as {
                    let mut votes = self.votes.lock().unwrap();
                    votes.push_back(seen.ip());
                    if votes.len() > IP_VOTES * 2 {
                        votes.pop_front();
                    }
                }
                let info = NodeInfo {
                    id: reply.resp.id,
                    addr,
                };
                let mut table = self.table(family);
                if let Some(old) = expect.filter(|id| *id != info.id) {
                    table.remove(&old);
                }
                table.insert_responded(info, Instant::now());
                Ok(reply.resp)
            }
            Err(e) => {
                if let Some(id) = expect
                    && e == RpcError::Timeout
                {
                    self.table(family).mark_failed(&id);
                }
                Err(e)
            }
        }
    }

    // Queriers are only inserted after they answer a ping of ours, so spoofed
    // source addresses can't poison the table.
    fn maybe_verify(self: &Arc<Self>, addr: SocketAddr, id: NodeId) {
        {
            let table = self.table(Family::of(&addr));
            if table.contains_addr(&addr) || !table.has_room(&id) {
                return;
            }
        }
        {
            // Spoofed queries must not be able to start unlimited pings.
            let mut verifying = self.verifying.lock().unwrap();
            if verifying.len() >= MAX_VERIFYING || !verifying.insert(addr) {
                return;
            }
        }
        let inner = self.clone();
        tokio::spawn(async move {
            let _ = inner.query(addr, None, krpc::PING, Args::default()).await;
            inner.verifying.lock().unwrap().remove(&addr);
        });
    }

    fn external_ip(&self, f: Family) -> Option<IpAddr> {
        let votes = self.votes.lock().unwrap();
        let mut counts: HashMap<IpAddr, usize> = HashMap::new();
        for ip in votes.iter().filter(|ip| ip.is_ipv6() == (f == Family::V6)) {
            *counts.entry(*ip).or_default() += 1;
        }
        counts.into_iter().max_by_key(|(_, n)| *n).map(|(ip, _)| ip)
    }

    fn handle_datagram(self: &Arc<Self>, (from, data): Datagram) {
        let msg = match Message::decode(&data) {
            Ok(m) => m,
            Err(e) => {
                trace!(%from, error = %e, "undecodable KRPC packet");
                return;
            }
        };
        match &msg.y[..] {
            b"r" | b"e" => self.rpc.on_reply(from, msg),
            b"q" => {
                let (Some(q), Some(a)) = (&msg.q, &msg.a) else {
                    self.rpc
                        .respond(from, msg.t, Err((wire::ERR_PROTOCOL, "missing q or a")));
                    return;
                };
                let result = {
                    let v4 = self.table(Family::V4);
                    let v6 = self.table(Family::V6);
                    self.server
                        .lock()
                        .unwrap()
                        .handle(from, q, a, [&v4, &v6], Instant::now())
                };
                trace!(%from, q = %String::from_utf8_lossy(q), ok = result.is_ok(), "query");
                self.rpc.respond(from, msg.t, result);
                if msg.ro != Some(1) {
                    self.maybe_verify(from, a.id);
                }
            }
            _ => {}
        }
    }
}

// An announce walks the same lookup as get_peers, so it reports the peers too.
pub struct Announced {
    pub stored: usize,
    pub peers: Vec<SocketAddr>,
}

pub struct Dht {
    inner: Arc<Inner>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Dht {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

async fn lookup_both(inner: &Arc<Inner>, target: NodeId, kind: Kind) -> [LookupResult; 2] {
    let (a, b) = tokio::join!(
        lookup(inner, target, kind.clone(), Family::V4),
        lookup(inner, target, kind, Family::V6)
    );
    [a, b]
}

impl Dht {
    pub fn new(config: DhtConfig, transport: Transport) -> Self {
        let now = Instant::now();
        let id = config.id.unwrap_or_else(NodeId::random);
        let inner = Arc::new(Inner {
            rpc: Rpc::new(
                PacketTx(transport.tx),
                config.query_timeout,
                config.client_version.clone(),
            ),
            tables: [
                Mutex::new(RoutingTable::new(id)),
                Mutex::new(RoutingTable::new(id)),
            ],
            server: Mutex::new(Server::new(now)),
            votes: Mutex::new(VecDeque::new()),
            verifying: Mutex::new(HashSet::new()),
            config,
        });
        let recv = tokio::spawn(recv_loop(inner.clone(), transport.rx));
        let maint = tokio::spawn(maintain_loop(inner.clone()));
        Dht {
            inner,
            tasks: vec![recv, maint],
        }
    }

    pub fn id(&self) -> NodeId {
        self.inner.own_id()
    }

    pub fn table_size(&self) -> usize {
        self.inner.total_nodes()
    }

    pub fn nodes(&self) -> Vec<NodeInfo> {
        Family::ALL
            .iter()
            .flat_map(|f| self.inner.table(*f).nodes())
            .collect()
    }

    pub fn external_ip(&self) -> Option<Ipv4Addr> {
        match self.inner.external_ip(Family::V4)? {
            IpAddr::V4(ip) => Some(ip),
            IpAddr::V6(_) => None,
        }
    }

    pub fn external_ip6(&self) -> Option<Ipv6Addr> {
        match self.inner.external_ip(Family::V6)? {
            IpAddr::V6(ip) => Some(ip),
            IpAddr::V4(_) => None,
        }
    }

    pub async fn bootstrap(&self) -> Result<usize, DhtError> {
        bootstrap(&self.inner).await
    }

    pub async fn find_node(&self, target: NodeId) -> Vec<NodeInfo> {
        let mut all: Vec<NodeInfo> = lookup_both(&self.inner, target, Kind::FindNode)
            .await
            .into_iter()
            .flat_map(|r| r.closest.into_iter().map(|r| r.node))
            .collect();
        all.sort_by_key(|n| target.distance(&n.id));
        all.dedup_by_key(|n| n.id);
        all.truncate(K);
        all
    }

    pub async fn get_peers(&self, info_hash: NodeId) -> Vec<SocketAddr> {
        let mut peers: Vec<SocketAddr> = lookup_both(&self.inner, info_hash, Kind::GetPeers)
            .await
            .into_iter()
            .flat_map(|r| r.peers)
            .collect();
        peers.sort();
        peers.dedup();
        peers
    }

    // With `implied_port`, nodes record the source port of our packets, which
    // is the NAT-mapped port of the shared socket.
    pub async fn announce(&self, info_hash: NodeId, port: u16, implied_port: bool) -> Announced {
        let res = lookup_both(&self.inner, info_hash, Kind::GetPeers).await;
        let args = Args {
            info_hash: Some(info_hash),
            port: Some(port.into()),
            implied_port: implied_port.then_some(1),
            ..Default::default()
        };
        let mut peers: Vec<SocketAddr> = res.iter().flat_map(|r| r.peers.iter().copied()).collect();
        peers.sort();
        peers.dedup();
        let closest = res.into_iter().flat_map(|r| r.closest).collect();
        let stored = self.store_at(closest, args, krpc::ANNOUNCE_PEER).await;
        debug!(%info_hash, stored, peers = peers.len(), "announced");
        Announced { stored, peers }
    }

    async fn store_at(&self, nodes: Vec<lookup::Responder>, args: Args, q: &'static [u8]) -> usize {
        let mut set = tokio::task::JoinSet::new();
        for r in nodes {
            let Some(token) = r.token else { continue };
            let mut args = args.clone();
            args.token = Some(ByteBuf::from(token));
            let inner = self.inner.clone();
            set.spawn(async move { inner.query(r.node.addr, Some(r.node.id), q, args).await });
        }
        let mut ok = 0;
        while let Some(res) = set.join_next().await {
            match res {
                Ok(Ok(_)) => ok += 1,
                Ok(Err(e)) => trace!(error = %e, q = %String::from_utf8_lossy(q), "store failed"),
                Err(_) => {}
            }
        }
        ok
    }
}

async fn resolve(routers: &[String]) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for r in routers {
        match tokio::net::lookup_host(r.as_str()).await {
            Ok(addrs) => out.extend(addrs),
            Err(e) => debug!(router = %r, error = %e, "failed to resolve router"),
        }
    }
    out
}

async fn bootstrap(inner: &Arc<Inner>) -> Result<usize, DhtError> {
    let mut seeds = inner.config.nodes.clone();
    seeds.extend(resolve(&inner.config.routers).await);
    if seeds.is_empty() && inner.total_nodes() == 0 {
        return Err(DhtError::NoBootstrapNodes);
    }

    // Ping seeds first to learn our external IP before choosing a BEP 42 id.
    let mut set = tokio::task::JoinSet::new();
    for addr in seeds {
        let inner = inner.clone();
        set.spawn(async move {
            inner
                .query(addr, None, krpc::PING, Args::default())
                .await
                .is_ok()
        });
    }
    while set.join_next().await.is_some() {}

    if inner.config.id.is_none()
        && let Some(ip) = inner
            .external_ip(Family::V4)
            .or_else(|| inner.external_ip(Family::V6))
        && !inner.own_id().is_secure_for(ip)
    {
        let id = NodeId::secure(ip);
        info!(%ip, %id, "switching to BEP 42 node id");
        let now = Instant::now();
        for f in Family::ALL {
            let mut table = inner.table(f);
            let nodes = table.nodes();
            *table = RoutingTable::new(id);
            for n in nodes {
                table.insert_responded(n, now);
            }
        }
    }

    let own = inner.own_id();
    lookup_both(inner, own, Kind::FindNode).await;
    // An own-id lookup only discovers our neighbourhood; fill the far buckets too.
    let mut set = tokio::task::JoinSet::new();
    for f in Family::ALL {
        for target in inner.table(f).sparse_bucket_targets() {
            let inner = inner.clone();
            set.spawn(async move { lookup(&inner, target, Kind::FindNode, f).await });
        }
    }
    while set.join_next().await.is_some() {}
    let n = inner.total_nodes();
    if n == 0 {
        return Err(DhtError::BootstrapFailed);
    }
    info!(
        ipv4_nodes = inner.table(Family::V4).len(),
        ipv6_nodes = inner.table(Family::V6).len(),
        external_ipv4 = ?inner.external_ip(Family::V4),
        external_ipv6 = ?inner.external_ip(Family::V6),
        "DHT bootstrapped"
    );
    Ok(n)
}

async fn recv_loop(inner: Arc<Inner>, mut rx: mpsc::Receiver<Datagram>) {
    while let Some(dg) = rx.recv().await {
        inner.handle_datagram(dg);
    }
}

async fn maintain_loop(inner: Arc<Inner>) {
    let mut tick = tokio::time::interval(MAINTAIN_EVERY);
    tick.tick().await;
    loop {
        tick.tick().await;
        let now = Instant::now();
        inner.server.lock().unwrap().maintain(now);
        if inner.total_nodes() == 0 {
            if let Err(e) = bootstrap(&inner).await {
                debug!(error = %e, "re-bootstrap failed");
            }
            continue;
        }
        for f in Family::ALL {
            let questionable: Vec<_> = inner
                .table(f)
                .questionable(now)
                .into_iter()
                .take(8)
                .collect();
            for n in questionable {
                let inner = inner.clone();
                tokio::spawn(async move {
                    let _ = inner
                        .query(n.addr, Some(n.id), krpc::PING, Args::default())
                        .await;
                });
            }
            let stale = inner.table(f).stale_bucket_targets(now, BUCKET_REFRESH);
            for target in stale.into_iter().take(3) {
                lookup(&inner, target, Kind::FindNode, f).await;
            }
        }
    }
}
