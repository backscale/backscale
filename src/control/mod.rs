pub mod noise;

use atomic_write_file::AtomicWriteFile;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rootcause::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::Instant;
use tracing::{Instrument, debug, info, info_span, warn};

use self::noise::Side;
use crate::binding::{DEFAULT_BINDING_LIFETIME_SECS, DeviceBinding, SessionKeys, SignedBinding};
use crate::discovery::MAX_ENDPOINTS;
use crate::identity::{PublicKey, Signer};
use crate::manifest::{self, ManifestDiff, ManifestError, NetId, NetworkManifest, SignedManifest};
use crate::net::utp::{UtpSocket, UtpStream};

const PROLOGUE: &[u8] = b"backscale/control/v1";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
// How long a peer we can't verify may stay connected to sync the manifest.
const UNVERIFIED_GRACE: Duration = Duration::from_secs(30);
// A peer that doesn't take a message within this long is dropped.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const OUTBOX: usize = 64;
const MAX_SESSIONS: usize = 512;
const BINDING_CHECK: Duration = Duration::from_secs(60);
const GOSSIP_EVERY: Duration = Duration::from_secs(30);
const DIAL_BACKOFF: Duration = Duration::from_secs(60);
// A punch only works if we dial while the other side does, so allow it sooner.
const PUNCH_DIAL_BACKOFF: Duration = Duration::from_secs(5);
const PUNCH_RELAY_LIMIT: Duration = Duration::from_secs(10);
const MAX_ADS: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub identity: PublicKey,
    pub binding: SignedBinding,
    pub manifest_seq: u64,
    // The peer's address as we see it, for NAT discovery.
    pub observed: SocketAddr,
    // Our own interface addresses, for peers on the same LAN.
    pub local_addrs: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAd {
    pub identity: PublicKey,
    pub endpoints: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Msg {
    Hello(Hello),
    ManifestSeq(u64),
    GetManifest,
    Manifest(SignedManifest),
    Bye(String),
    Binding(SignedBinding),
    Peers(Vec<PeerAd>),
    // Ask the receiver to tell `target` to dial us now.
    Punch(PublicKey),
    PunchRequest {
        from: PublicKey,
        endpoints: Vec<SocketAddr>,
    },
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub identity: PublicKey,
    pub name: String,
    pub addr: SocketAddr,
    pub binding: DeviceBinding,
    pub observed_us: SocketAddr,
    pub local_addrs: Vec<SocketAddr>,
}

impl PeerInfo {
    // Where others can try to reach this peer: the address we see it at
    // first, then its LAN addresses.
    pub fn endpoints(&self) -> Vec<SocketAddr> {
        let mut out = vec![self.addr];
        for a in &self.local_addrs {
            if !out.contains(a) {
                out.push(*a);
            }
        }
        out.truncate(MAX_ENDPOINTS);
        out
    }
}

#[derive(Debug, Clone)]
pub enum ControlEvent {
    PeerUp(Box<PeerInfo>),
    PeerDown(PublicKey),
    ManifestUpdated { seq: u64, diff: Arc<ManifestDiff> },
    // A peer told us how to reach another member (unverified until we connect).
    Advertised(PeerAd),
}

#[derive(Debug, Clone)]
pub struct ControlConfig {
    pub network_key: PublicKey,
    pub manifest_path: Option<PathBuf>,
}

// Orders duplicate sessions to the same peer. Both ends compute the same key
// for a session, so both keep the same one.
type Rank = (PublicKey, [u8; 32]);

struct Session {
    // Outbound messages; best-effort for gossip and punches.
    out: mpsc::Sender<Msg>,
    close: watch::Sender<Option<&'static str>>,
    addr: SocketAddr,
    rank: Option<Rank>,
    peer: Option<PeerInfo>,
}

#[derive(Default)]
struct State {
    manifest: Option<(NetworkManifest, SignedManifest)>,
    sessions: HashMap<u64, Session>,
    verified: HashMap<PublicKey, u64>,
    dial_attempts: HashMap<PublicKey, Instant>,
    punch_asked: HashMap<PublicKey, Instant>,
    punch_relayed: HashMap<(PublicKey, PublicKey), Instant>,
}

struct Inner {
    network_key: PublicKey,
    net_id: NetId,
    identity: PublicKey,
    keys: SessionKeys,
    // Watched by sessions: changes are coalesced, never dropped.
    binding: watch::Sender<SignedBinding>,
    manifest_seq: watch::Sender<u64>,
    local_addrs: Mutex<Vec<SocketAddr>>,
    // Addresses that turned out to be ourselves (e.g. our NAT mapping found
    // in the DHT); never dialed again.
    self_addrs: Mutex<HashSet<SocketAddr>>,
    utp: Arc<UtpSocket>,
    manifest_path: Option<PathBuf>,
    persist: Mutex<()>,
    state: Mutex<State>,
    next_id: AtomicU64,
    events: broadcast::Sender<ControlEvent>,
}

#[derive(Clone)]
pub struct ControlNode {
    inner: Arc<Inner>,
}

enum Verdict {
    Verified,
    NotYet(String),
    Reject(&'static str),
}

impl ControlNode {
    pub fn new(
        config: ControlConfig,
        identity: &dyn Signer,
        keys: SessionKeys,
        utp: Arc<UtpSocket>,
    ) -> Result<Self, Report> {
        let net_id = NetId::from_network_key(&config.network_key);
        let binding = keys
            .bind(
                net_id,
                identity,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                DEFAULT_BINDING_LIFETIME_SECS,
            )
            .context("failed to create device binding")?;
        let mut state = State::default();
        if let Some(path) = &config.manifest_path
            && path.exists()
        {
            match load_manifest(path, &config.network_key) {
                Ok(m) => {
                    info!(seq = m.0.seq, "loaded manifest");
                    state.manifest = Some(m);
                }
                Err(e) => warn!(
                    error = %e,
                    "ignoring stored manifest; one signed by an older backscale must be re-signed with `backscale net sign`"
                ),
            }
        }
        let seq = state.manifest.as_ref().map_or(0, |(m, _)| m.seq);
        let (events, _) = broadcast::channel(256);
        Ok(ControlNode {
            inner: Arc::new(Inner {
                network_key: config.network_key,
                net_id,
                identity: identity.public_key(),
                keys,
                binding: watch::Sender::new(binding),
                manifest_seq: watch::Sender::new(seq),
                local_addrs: Mutex::new(Vec::new()),
                self_addrs: Mutex::new(HashSet::new()),
                utp,
                manifest_path: config.manifest_path,
                persist: Mutex::new(()),
                state: Mutex::new(state),
                next_id: AtomicU64::new(1),
                events,
            }),
        })
    }

    pub fn identity(&self) -> &PublicKey {
        &self.inner.identity
    }

    pub fn net_id(&self) -> NetId {
        self.inner.net_id
    }

    pub fn session_keys(&self) -> &SessionKeys {
        &self.inner.keys
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ControlEvent> {
        self.inner.events.subscribe()
    }

    pub fn manifest(&self) -> Option<NetworkManifest> {
        self.inner.state().manifest.as_ref().map(|(m, _)| m.clone())
    }

    pub fn manifest_seq(&self) -> u64 {
        self.inner.seq()
    }

    pub fn peers(&self) -> Vec<PeerInfo> {
        self.inner
            .state()
            .sessions
            .values()
            .filter_map(|s| s.peer.clone())
            .collect()
    }

    pub fn is_connected_to(&self, addr: SocketAddr) -> bool {
        self.inner.state().sessions.values().any(|s| s.addr == addr)
    }

    pub fn is_verified(&self, identity: &PublicKey) -> bool {
        self.inner.state().verified.contains_key(identity)
    }

    pub fn is_self(&self, addr: SocketAddr) -> bool {
        self.inner.self_addrs.lock().unwrap().contains(&addr)
    }

    pub fn set_local_addrs(&self, addrs: Vec<SocketAddr>) {
        *self.inner.local_addrs.lock().unwrap() = addrs;
    }

    pub fn dial(&self, identity: &PublicKey, endpoints: &[SocketAddr]) {
        self.inner.dial(identity, endpoints, DIAL_BACKOFF, None);
    }

    // Re-sign the device binding for the same session keys with a fresh
    // expiry; sessions pass it on to their peers.
    pub fn refresh_binding(&self, identity: &dyn Signer) -> Result<(), Report> {
        let binding = self
            .inner
            .keys
            .bind(
                self.inner.net_id,
                identity,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                DEFAULT_BINDING_LIFETIME_SECS,
            )
            .context("failed to refresh device binding")?;
        self.inner.binding.send_replace(binding);
        debug!("device binding refreshed");
        Ok(())
    }

    pub fn publish(&self, signed: SignedManifest) -> Result<u64, Report<ManifestError>> {
        self.inner.adopt(&signed)
    }

    pub fn start(&self) {
        tokio::spawn(gossip_loop(self.inner.clone()));
        let inner = self.inner.clone();
        tokio::spawn(async move {
            loop {
                let stream = match inner.utp.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "accept loop stopped");
                        return;
                    }
                };
                if inner.state().sessions.len() >= MAX_SESSIONS {
                    debug!(addr = %stream.peer_addr(), "too many sessions, dropping");
                    continue;
                }
                spawn_session(inner.clone(), stream, false);
            }
        });
    }

    pub async fn connect(&self, addr: SocketAddr) -> Result<(), Report> {
        let stream = self
            .inner
            .utp
            .connect(addr)
            .await
            .map_err(|e| e.into_dynamic())?;
        spawn_session(self.inner.clone(), stream, true);
        Ok(())
    }
}

fn load_manifest(
    path: &PathBuf,
    key: &PublicKey,
) -> Result<(NetworkManifest, SignedManifest), Report> {
    let bytes = std::fs::read(path).context("failed to read stored manifest")?;
    let signed = SignedManifest::from_bytes(&bytes).map_err(|e| e.into_dynamic())?;
    let m = signed
        .verify(
            key,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .map_err(|e| e.into_dynamic())?;
    Ok((m, signed))
}

impl Inner {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    fn seq(&self) -> u64 {
        self.state().manifest.as_ref().map_or(0, |(m, _)| m.seq)
    }

    fn signed_manifest(&self) -> Option<SignedManifest> {
        self.state().manifest.as_ref().map(|(_, s)| s.clone())
    }

    // Writes outside the state lock (fsync can be slow). Whoever holds the
    // persist lock writes the newest manifest, so an older one never wins.
    fn persist_manifest(&self) {
        let Some(path) = &self.manifest_path else {
            return;
        };
        let _guard = self.persist.lock().unwrap();
        let Some(latest) = self.signed_manifest() else {
            return;
        };
        let write = || -> std::io::Result<()> {
            let mut f = AtomicWriteFile::open(path)?;
            f.write_all(&latest.to_bytes())?;
            f.commit()
        };
        if let Err(e) = write() {
            warn!(error = %e, "failed to persist manifest");
        }
    }

    fn adopt(&self, signed: &SignedManifest) -> Result<u64, Report<ManifestError>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = self.state();
        let current = state.manifest.as_ref().map(|(m, _)| m);
        let new = manifest::adopt(current, signed, &self.network_key, now)?;
        let diff = Arc::new(manifest::diff(current, &new));
        let seq = new.seq;
        info!(
            seq,
            added = diff.added.len(),
            removed = diff.removed.len(),
            changed = diff.changed.len(),
            "adopted manifest"
        );
        state.manifest = Some((new, signed.clone()));
        // Published under the lock so concurrent adopts can't announce out of order.
        self.manifest_seq.send_replace(seq);
        let _ = self
            .events
            .send(ControlEvent::ManifestUpdated { seq, diff });
        drop(state);
        self.persist_manifest();
        Ok(seq)
    }

    fn verify(
        &self,
        id: u64,
        hello: &Hello,
        remote_static: &[u8; 32],
        addr: SocketAddr,
    ) -> Verdict {
        if hello.identity == self.identity {
            self.self_addrs.lock().unwrap().insert(addr);
            return Verdict::Reject("connected to ourselves");
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut state = self.state();
        let Some((manifest, _)) = &state.manifest else {
            return Verdict::NotYet("no manifest yet".into());
        };
        if now >= manifest.expires_at {
            return Verdict::NotYet("manifest expired".into());
        }
        let Some(member) = manifest.member(&hello.identity) else {
            return Verdict::NotYet(format!("{} is not a member", hello.identity.fingerprint()));
        };
        let name = member.name.clone();
        let binding = match hello.binding.verify(&hello.identity, self.net_id, now) {
            Ok(b) => b,
            Err(e) => {
                warn!(peer = %name, error = %e, "invalid device binding");
                return Verdict::Reject("invalid device binding");
            }
        };
        if &binding.noise_public != remote_static {
            warn!(peer = %name, "noise key does not match device binding");
            return Verdict::Reject("noise key does not match device binding");
        }
        if self.wg_key_taken(&state, &hello.identity, &binding.wg_public) {
            warn!(peer = %name, "device binding claims another member's WireGuard key");
            return Verdict::Reject("WireGuard key belongs to another member");
        }

        if let Some(&other) = state.verified.get(&hello.identity)
            && other != id
        {
            // Duplicate sessions (simultaneous or parallel dials): keep the
            // lowest-ranked one, which both ends agree on.
            let rank = |sid: u64| state.sessions.get(&sid).and_then(|s| s.rank.clone());
            if rank(id) < rank(other) {
                if let Some(s) = state.sessions.get(&other) {
                    s.close.send_replace(Some("duplicate session"));
                }
            } else {
                return Verdict::Reject("duplicate session");
            }
        }

        let info = PeerInfo {
            identity: hello.identity.clone(),
            name,
            addr,
            binding,
            observed_us: hello.observed,
            local_addrs: hello
                .local_addrs
                .iter()
                .take(MAX_ENDPOINTS)
                .copied()
                .collect(),
        };
        state.verified.insert(hello.identity.clone(), id);
        if let Some(s) = state.sessions.get_mut(&id) {
            s.peer = Some(info.clone());
        }
        drop(state);
        info!(peer = %info.name, %addr, "peer verified");
        let _ = self.events.send(ControlEvent::PeerUp(Box::new(info)));
        Verdict::Verified
    }

    fn dial(
        self: &Arc<Self>,
        identity: &PublicKey,
        endpoints: &[SocketAddr],
        backoff: Duration,
        via: Option<u64>,
    ) {
        let now = Instant::now();
        let own_addrs = self.local_addrs.lock().unwrap().clone();
        let targets: Vec<SocketAddr> = {
            let mut st = self.state();
            let member = st
                .manifest
                .as_ref()
                .is_some_and(|(m, _)| m.member(identity).is_some());
            if identity == &self.identity || !member || st.verified.contains_key(identity) {
                return;
            }
            // With a relay, don't dial now: ask it to make both sides dial at
            // the same moment. If one side's packets reach the other's NAT
            // first, Linux conntrack remaps the late side's port and the punch fails.
            if let Some(v) = via {
                if st
                    .punch_asked
                    .get(identity)
                    .is_some_and(|t| now.duration_since(*t) < backoff)
                {
                    return;
                }
                st.punch_asked.insert(identity.clone(), now);
                if let Some(s) = st.sessions.get(&v) {
                    let _ = s.out.try_send(Msg::Punch(identity.clone()));
                }
                return;
            }
            if st
                .dial_attempts
                .get(identity)
                .is_some_and(|t| now.duration_since(*t) < backoff)
            {
                return;
            }
            st.dial_attempts.insert(identity.clone(), now);
            let mut targets = Vec::new();
            for ep in endpoints {
                let busy = st.sessions.values().any(|s| s.addr == *ep);
                let ours = own_addrs.contains(ep) || self.self_addrs.lock().unwrap().contains(ep);
                if !busy && !ours && !targets.contains(ep) {
                    targets.push(*ep);
                }
            }
            targets.truncate(MAX_ENDPOINTS);
            targets
        };
        debug!(peer = %identity.fingerprint(), ?targets, "dialing");
        for ep in targets {
            let inner = self.clone();
            tokio::spawn(async move {
                match inner.utp.connect(ep).await {
                    Ok(stream) => spawn_session(inner, stream, true),
                    Err(e) => debug!(%ep, error = %e, "dial failed"),
                }
            });
        }
    }

    fn relay_punch(&self, from_session: u64, target: &PublicKey) {
        let now = Instant::now();
        let mut st = self.state();
        let Some(src) = st.sessions.get(&from_session).and_then(|s| s.peer.clone()) else {
            return;
        };
        let Some(&tid) = st.verified.get(target) else {
            return;
        };
        if tid == from_session {
            return;
        }
        let Some(dst) = st.sessions.get(&tid).and_then(|s| s.peer.clone()) else {
            return;
        };
        let key = (src.identity.clone(), target.clone());
        if st
            .punch_relayed
            .get(&key)
            .is_some_and(|t| now.duration_since(*t) < PUNCH_RELAY_LIMIT)
        {
            return;
        }
        st.punch_relayed.insert(key, now);
        debug!(from = %src.name, to = %dst.name, "relaying punch to both sides");
        for (sid, other) in [(tid, &src), (from_session, &dst)] {
            if let Some(s) = st.sessions.get(&sid) {
                let _ = s.out.try_send(Msg::PunchRequest {
                    from: other.identity.clone(),
                    endpoints: other.endpoints(),
                });
            }
        }
    }

    fn gossip(&self) {
        let now = Instant::now();
        let mut st = self.state();
        let stale = Duration::from_secs(600);
        st.dial_attempts
            .retain(|_, t| now.duration_since(*t) < stale);
        st.punch_asked.retain(|_, t| now.duration_since(*t) < stale);
        st.punch_relayed
            .retain(|_, t| now.duration_since(*t) < stale);
        let ads: Vec<(u64, PeerAd)> = st
            .sessions
            .iter()
            .filter_map(|(id, s)| {
                let p = s.peer.as_ref()?;
                Some((
                    *id,
                    PeerAd {
                        identity: p.identity.clone(),
                        endpoints: p.endpoints(),
                    },
                ))
            })
            .collect();
        for (id, s) in &st.sessions {
            if s.peer.is_none() {
                continue;
            }
            let list: Vec<PeerAd> = ads
                .iter()
                .filter(|(aid, _)| aid != id)
                .map(|(_, ad)| ad.clone())
                .take(MAX_ADS)
                .collect();
            if !list.is_empty() {
                let _ = s.out.try_send(Msg::Peers(list));
            }
        }
    }

    // A member could otherwise claim someone else's WireGuard key and take
    // over their tunnel in the data plane.
    fn wg_key_taken(&self, state: &State, identity: &PublicKey, wg_public: &[u8; 32]) -> bool {
        *wg_public == self.keys.wg_public()
            || state
                .sessions
                .values()
                .filter_map(|s| s.peer.as_ref())
                .any(|p| &p.identity != identity && &p.binding.wg_public == wg_public)
    }

    // False if the update claims another member's WireGuard key.
    fn update_binding(&self, id: u64, binding: DeviceBinding) -> bool {
        let mut state = self.state();
        if self.wg_key_taken(&state, &binding.identity, &binding.wg_public) {
            return false;
        }
        let Some(peer) = state.sessions.get_mut(&id).and_then(|s| s.peer.as_mut()) else {
            return true;
        };
        peer.binding = binding;
        let info = peer.clone();
        drop(state);
        let _ = self.events.send(ControlEvent::PeerUp(Box::new(info)));
        true
    }

    fn peer_binding_expired(&self, id: u64) -> bool {
        self.state()
            .sessions
            .get(&id)
            .and_then(|s| s.peer.as_ref())
            .is_some_and(|p| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    >= p.binding.expires_at
            })
    }

    fn still_member(&self, identity: &PublicKey) -> bool {
        self.state().manifest.as_ref().is_some_and(|(m, _)| {
            m.member(identity).is_some()
                && SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    < m.expires_at
        })
    }

    fn remove_session(&self, id: u64) {
        let mut state = self.state();
        let Some(s) = state.sessions.remove(&id) else {
            return;
        };
        if let Some(peer) = s.peer
            && state.verified.get(&peer.identity) == Some(&id)
        {
            state.verified.remove(&peer.identity);
            drop(state);
            info!(peer = %peer.name, "peer down");
            let _ = self.events.send(ControlEvent::PeerDown(peer.identity));
        }
    }
}

async fn gossip_loop(inner: Arc<Inner>) {
    let mut events = inner.events.subscribe();
    let mut tick = tokio::time::interval(GOSSIP_EVERY);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            ev = events.recv() => match ev {
                Ok(ControlEvent::PeerUp(_)) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Closed) => return,
            },
        }
        inner.gossip();
    }
}

fn spawn_session(inner: Arc<Inner>, stream: UtpStream, we_initiated: bool) {
    let id = inner.next_id.fetch_add(1, Ordering::Relaxed);
    let addr = stream.peer_addr();
    let (out, outbox) = mpsc::channel(OUTBOX);
    let (close, close_rx) = watch::channel(None);
    inner.state().sessions.insert(
        id,
        Session {
            out: out.clone(),
            close,
            addr,
            rank: None,
            peer: None,
        },
    );
    let span = info_span!("session", %addr, id);
    tokio::spawn(
        async move {
            let io = SessionIo {
                out,
                outbox,
                close_rx,
            };
            if let Err(e) = run_session(&inner, id, stream, we_initiated, io).await {
                debug!(error = %e, "session ended with error");
            }
            inner.remove_session(id);
        }
        .instrument(span),
    );
}

struct SessionIo {
    out: mpsc::Sender<Msg>,
    outbox: mpsc::Receiver<Msg>,
    close_rx: watch::Receiver<Option<&'static str>>,
}

// Sends queued messages; never blocks the session loop. Ends when the queue
// closes (after the session's last message) or the peer stops reading.
async fn write_loop<W: tokio::io::AsyncWrite + Unpin>(
    mut writer: noise::SecureWriter<W>,
    mut outbox: mpsc::Receiver<Msg>,
) {
    while let Some(msg) = outbox.recv().await {
        match tokio::time::timeout(WRITE_TIMEOUT, writer.send(&msg)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                debug!(error = %e, "control write failed");
                return;
            }
            Err(_) => {
                debug!("peer stopped reading, dropping session");
                return;
            }
        }
    }
    writer.close().await;
}

async fn run_session(
    inner: &Arc<Inner>,
    id: u64,
    stream: UtpStream,
    we_initiated: bool,
    io: SessionIo,
) -> Result<(), Report> {
    let SessionIo {
        out,
        outbox,
        mut close_rx,
    } = io;
    let addr = stream.peer_addr();
    let side = if we_initiated {
        Side::Initiator
    } else {
        Side::Responder
    };
    let mut prologue = PROLOGUE.to_vec();
    prologue.extend_from_slice(&inner.net_id.0);
    let noise_secret = inner.keys.noise.to_bytes();
    let established = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        noise::handshake(stream, side, &noise_secret, &prologue),
    )
    .await
    .map_err(|_| report!("handshake timed out"))??;
    let noise::Established {
        mut reader,
        mut writer,
        remote_static,
        hash,
    } = established;

    let mut binding_rx = inner.binding.subscribe();
    let mut seq_rx = inner.manifest_seq.subscribe();
    let binding = binding_rx.borrow_and_update().clone();
    seq_rx.mark_unchanged();
    let local_addrs = inner.local_addrs.lock().unwrap().clone();
    writer
        .send(&Msg::Hello(Hello {
            identity: inner.identity.clone(),
            binding,
            manifest_seq: inner.seq(),
            observed: addr,
            local_addrs,
        }))
        .await?;
    let hello = match tokio::time::timeout(HANDSHAKE_TIMEOUT, reader.recv::<Msg>()).await {
        Ok(Ok(Some(Msg::Hello(h)))) => h,
        Ok(Ok(Some(_))) => bail!("expected Hello"),
        Ok(Ok(None)) => bail!("peer closed before Hello"),
        Ok(Err(e)) => return Err(e),
        Err(_) => bail!("timed out waiting for Hello"),
    };
    debug!(peer = %hello.identity.fingerprint(), seq = hello.manifest_seq, "hello");
    let initiator = if we_initiated {
        inner.identity.clone()
    } else {
        hello.identity.clone()
    };
    if let Some(s) = inner.state().sessions.get_mut(&id) {
        s.rank = Some((initiator, hash));
    }

    let (msg_tx, mut msgs) = mpsc::channel::<Msg>(16);
    let _reader = AbortOnDrop(tokio::spawn(async move {
        loop {
            match reader.recv::<Msg>().await {
                Ok(Some(m)) => {
                    if msg_tx.send(m).await.is_err() {
                        return;
                    }
                }
                Ok(None) => return,
                Err(e) => {
                    debug!(error = %e, "control read failed");
                    return;
                }
            }
        }
    }));
    let mut writer_task = tokio::spawn(write_loop(writer, outbox));

    // Messages the session itself needs delivered; a full queue means the
    // peer isn't keeping up, so the session is dropped rather than waited on.
    let send = |m: Msg| out.try_send(m).is_ok();

    if hello.manifest_seq > inner.seq() && !send(Msg::GetManifest) {
        return Ok(());
    }

    let mut verified = false;
    let check = |verified: &mut bool| -> Option<&'static str> {
        if *verified {
            return None;
        }
        match inner.verify(id, &hello, &remote_static, addr) {
            Verdict::Verified => {
                *verified = true;
                None
            }
            Verdict::NotYet(why) => {
                debug!(%why, "peer not verified yet");
                None
            }
            Verdict::Reject(why) => Some(why),
        }
    };

    let grace = tokio::time::sleep(UNVERIFIED_GRACE);
    tokio::pin!(grace);
    let mut expiry_check = tokio::time::interval(BINDING_CHECK);
    let bye = match check(&mut verified) {
        Some(why) => Some(why),
        None => loop {
            tokio::select! {
                m = msgs.recv() => match m {
                    None => break None,
                    Some(Msg::GetManifest) => {
                        if let Some(signed) = inner.signed_manifest()
                            && !send(Msg::Manifest(signed))
                        {
                            break Some("peer too slow");
                        }
                    }
                    Some(Msg::ManifestSeq(seq)) => {
                        if seq > inner.seq() && !send(Msg::GetManifest) {
                            break Some("peer too slow");
                        }
                    }
                    Some(Msg::Manifest(signed)) => {
                        match inner.adopt(&signed) {
                            Ok(_) => {}
                            Err(e) if matches!(e.current_context(), ManifestError::Stale { .. }) => {}
                            Err(e) => warn!(error = %e, "rejected manifest from peer"),
                        }
                        if let Some(why) = check(&mut verified) {
                            break Some(why);
                        }
                    }
                    Some(Msg::Binding(signed)) => {
                        match signed.verify(&hello.identity, inner.net_id, SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()) {
                            Ok(b) if b.noise_public == remote_static => {
                                if !inner.update_binding(id, b) {
                                    break Some("WireGuard key belongs to another member");
                                }
                            }
                            Ok(_) => break Some("binding update changed the noise key"),
                            Err(e) => {
                                warn!(error = %e, "invalid binding update");
                                break Some("invalid binding update");
                            }
                        }
                    }
                    Some(Msg::Peers(ads)) if verified => {
                        for ad in ads.into_iter().take(MAX_ADS) {
                            let _ = inner.events.send(ControlEvent::Advertised(ad.clone()));
                            inner.dial(&ad.identity, &ad.endpoints, DIAL_BACKOFF, Some(id));
                        }
                    }
                    Some(Msg::Punch(target)) if verified => inner.relay_punch(id, &target),
                    Some(Msg::PunchRequest { from, endpoints }) if verified => {
                        debug!(from = %from.fingerprint(), ?endpoints, "punch request");
                        inner.dial(&from, &endpoints, PUNCH_DIAL_BACKOFF, None);
                    }
                    Some(Msg::Peers(_) | Msg::Punch(_) | Msg::PunchRequest { .. }) => {}
                    Some(Msg::Hello(_)) => break Some("unexpected Hello"),
                    Some(Msg::Bye(reason)) => {
                        debug!(%reason, "peer said bye");
                        break None;
                    }
                },
                Ok(()) = seq_rx.changed() => {
                    if verified && !inner.still_member(&hello.identity) {
                        info!("peer removed from network");
                        break Some("removed from network");
                    }
                    if let Some(why) = check(&mut verified) {
                        break Some(why);
                    }
                    let seq = *seq_rx.borrow_and_update();
                    if !send(Msg::ManifestSeq(seq)) {
                        break Some("peer too slow");
                    }
                }
                Ok(()) = binding_rx.changed() => {
                    let b = binding_rx.borrow_and_update().clone();
                    if !send(Msg::Binding(b)) {
                        break Some("peer too slow");
                    }
                }
                Ok(()) = close_rx.changed() => {
                    if let Some(why) = *close_rx.borrow() {
                        break Some(why);
                    }
                }
                _ = &mut writer_task => break None,
                _ = expiry_check.tick(), if verified => {
                    if inner.peer_binding_expired(id) {
                        break Some("device binding expired");
                    }
                }
                _ = &mut grace, if !verified => break Some("not a member of this network"),
            }
        },
    };
    if let Some(why) = bye {
        debug!(%why, "closing session");
        let _ = out.try_send(Msg::Bye(why.into()));
    }
    Ok(())
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
