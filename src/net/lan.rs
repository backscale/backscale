// LAN peer discovery: members announce the network's rotating DHT topic and
// their listen port to a multicast group. Announcements are only hints; the
// Noise handshake and Hello decide membership.
//
// IPv4 announcements also carry the sending interface's address: bridges with
// netfilter (libvirt, Docker) source-NAT multicast that isn't 224.0.0.0/24.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use crate::manifest::NetId;
use crate::net::{TOPIC_PERIOD_SECS, manager_topic, topic};

pub const GROUP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 41, 64);
pub const GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xbac5);
pub const LAN_PORT: u16 = 41640;
const ANNOUNCE_EVERY: Duration = Duration::from_secs(30);
const MAGIC: &[u8; 6] = b"BKLAN1";
const PACKET_LEN: usize = MAGIC.len() + 20 + 2 + 4;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Topic {
    Member,
    Manager,
}

impl Topic {
    fn of(self, net_id: &NetId, unix: u64) -> [u8; 20] {
        match self {
            Topic::Member => topic(net_id, unix).0,
            Topic::Manager => manager_topic(net_id, unix).0,
        }
    }
}

pub fn encode(
    kind: Topic,
    net_id: &NetId,
    unix: u64,
    port: u16,
    iface: Option<Ipv4Addr>,
) -> [u8; PACKET_LEN] {
    let mut p = [0u8; PACKET_LEN];
    p[..6].copy_from_slice(MAGIC);
    p[6..26].copy_from_slice(&kind.of(net_id, unix));
    p[26..28].copy_from_slice(&port.to_be_bytes());
    p[28..].copy_from_slice(&iface.unwrap_or(Ipv4Addr::UNSPECIFIED).octets());
    p
}

// The announced port and interface address if the packet is for our network,
// allowing the previous topic period for rollover and clock skew.
pub fn decode(kind: Topic, net_id: &NetId, unix: u64, p: &[u8]) -> Option<(u16, Option<Ipv4Addr>)> {
    if p.len() != PACKET_LEN || &p[..6] != MAGIC {
        return None;
    }
    let current = kind.of(net_id, unix);
    let previous = kind.of(net_id, unix.saturating_sub(TOPIC_PERIOD_SECS));
    if p[6..26] != current && p[6..26] != previous {
        return None;
    }
    let port = u16::from_be_bytes([p[26], p[27]]);
    let iface = Ipv4Addr::new(p[28], p[29], p[30], p[31]);
    (port != 0).then_some((port, (!iface.is_unspecified()).then_some(iface)))
}

// Where to dial an announcer: its claimed interface address if that is on one
// of our own subnets (so a forged packet can't point us off the LAN), else the
// packet's source.
fn candidate(src: SocketAddr, port: u16, claimed: Option<Ipv4Addr>) -> SocketAddr {
    match src {
        SocketAddr::V4(a) => {
            let ip = claimed.filter(|c| on_link(*c)).unwrap_or(*a.ip());
            SocketAddr::new(ip.into(), port)
        }
        SocketAddr::V6(a) => SocketAddrV6::new(*a.ip(), port, 0, a.scope_id()).into(),
    }
}

fn on_link(ip: Ipv4Addr) -> bool {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .iter()
        .any(|i| match &i.addr {
            if_addrs::IfAddr::V4(v4) if !i.is_loopback() => {
                let mask = u32::from(v4.netmask);
                u32::from(v4.ip) & mask == u32::from(ip) & mask && v4.ip != ip
            }
            _ => false,
        })
}

fn bind(domain: Domain) -> std::io::Result<UdpSocket> {
    let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.set_reuse_port(true)?;
    let addr: SocketAddr = if domain == Domain::IPV6 {
        s.set_only_v6(true)?;
        s.set_multicast_loop_v6(false)?;
        s.set_multicast_hops_v6(1)?;
        SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, LAN_PORT, 0, 0).into()
    } else {
        s.set_multicast_loop_v4(false)?;
        s.set_multicast_ttl_v4(1)?;
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, LAN_PORT).into()
    };
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    UdpSocket::from_std(s.into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Iface {
    V4(Ipv4Addr),
    V6(u32),
}

fn interfaces() -> HashSet<Iface> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback() && i.oper_status != if_addrs::IfOperStatus::Down)
        .filter_map(|i| match i.ip() {
            IpAddr::V4(v4) => Some(Iface::V4(v4)),
            IpAddr::V6(_) => i.index.map(Iface::V6),
        })
        .collect()
}

struct Lan {
    v4: Option<UdpSocket>,
    v6: Option<UdpSocket>,
    joined: HashSet<Iface>,
}

impl Lan {
    fn sock(&self, iface: &Iface) -> Option<&UdpSocket> {
        match iface {
            Iface::V4(_) => self.v4.as_ref(),
            Iface::V6(_) => self.v6.as_ref(),
        }
    }

    // Joins newly appeared interfaces; returns all current ones.
    fn refresh(&mut self) -> HashSet<Iface> {
        let now = interfaces();
        for iface in now.difference(&self.joined.clone()) {
            let Some(s) = self.sock(iface) else { continue };
            let sock = socket2::SockRef::from(s);
            let res = match iface {
                Iface::V4(a) => sock.join_multicast_v4(&GROUP_V4, a),
                Iface::V6(i) => sock.join_multicast_v6(&GROUP_V6, *i),
            };
            match res {
                Ok(()) => debug!(iface = ?iface, "joined LAN discovery group"),
                Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {}
                Err(e) => {
                    debug!(iface = ?iface, error = %e, "failed to join LAN discovery group");
                    continue;
                }
            }
            self.joined.insert(*iface);
        }
        self.joined.retain(|i| now.contains(i));
        now
    }

    async fn announce(&mut self, kinds: &[Topic], net_id: &NetId, port: u16) {
        let unix = now();
        let ifaces = self.refresh();
        for kind in kinds {
            self.announce_one(&ifaces, *kind, net_id, port, unix).await;
        }
    }

    async fn announce_one(
        &self,
        ifaces: &HashSet<Iface>,
        kind: Topic,
        net_id: &NetId,
        port: u16,
        unix: u64,
    ) {
        for &iface in ifaces {
            let Some(s) = self.sock(&iface) else { continue };
            let sock = socket2::SockRef::from(s);
            let (set, dst, packet): (_, SocketAddr, _) = match iface {
                Iface::V4(a) => (
                    sock.set_multicast_if_v4(&a),
                    SocketAddrV4::new(GROUP_V4, LAN_PORT).into(),
                    encode(kind, net_id, unix, port, Some(a)),
                ),
                Iface::V6(i) => (
                    sock.set_multicast_if_v6(i),
                    SocketAddrV6::new(GROUP_V6, LAN_PORT, 0, i).into(),
                    encode(kind, net_id, unix, port, None),
                ),
            };
            if let Err(e) = set {
                trace!(error = %e, "failed to select multicast interface");
                continue;
            }
            if let Err(e) = s.send_to(&packet, dst).await {
                trace!(error = %e, %dst, "LAN announce failed");
            }
        }
    }
}

async fn recv(s: &Option<UdpSocket>, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
    match s {
        Some(s) => s.recv_from(buf).await,
        None => std::future::pending().await,
    }
}

pub struct LanRole {
    pub listen: Topic,
    pub announce_member: bool,
    // The manager topic is announced while this says so.
    pub manager_live: Option<Box<dyn Fn() -> bool + Send>>,
}

impl LanRole {
    pub fn member(manager_live: Option<Box<dyn Fn() -> bool + Send>>) -> Self {
        LanRole {
            listen: Topic::Member,
            announce_member: true,
            manager_live,
        }
    }

    pub fn find_manager() -> Self {
        LanRole {
            listen: Topic::Manager,
            announce_member: false,
            manager_live: None,
        }
    }

    fn announcing(&self) -> Vec<Topic> {
        let mut v = vec![];
        if self.announce_member {
            v.push(Topic::Member);
        }
        if self.manager_live.as_ref().is_some_and(|f| f()) {
            v.push(Topic::Manager);
        }
        v
    }
}

pub async fn run(net_id: NetId, port: u16, role: LanRole, found: mpsc::Sender<SocketAddr>) {
    let v4 = bind(Domain::IPV4)
        .inspect_err(|e| warn!(error = %e, "LAN discovery unavailable over IPv4"))
        .ok();
    let v6 = bind(Domain::IPV6)
        .inspect_err(|e| debug!(error = %e, "LAN discovery unavailable over IPv6"))
        .ok();
    if v4.is_none() && v6.is_none() {
        return;
    }
    let mut lan = Lan {
        v4,
        v6,
        joined: HashSet::new(),
    };
    let mut tick = tokio::time::interval(ANNOUNCE_EVERY);
    let mut buf = [0u8; 64];
    let mut buf6 = [0u8; 64];
    loop {
        let (r, data) = tokio::select! {
            _ = tick.tick() => {
                lan.announce(&role.announcing(), &net_id, port).await;
                continue;
            }
            r = recv(&lan.v4, &mut buf) => (r, &buf),
            r = recv(&lan.v6, &mut buf6) => (r, &buf6),
        };
        let (n, src) = match r {
            Ok(r) => r,
            Err(e) => {
                trace!(error = %e, "LAN discovery receive failed");
                continue;
            }
        };
        let Some((peer_port, claimed)) = decode(role.listen, &net_id, now(), &data[..n]) else {
            continue;
        };
        let candidate = candidate(src, peer_port, claimed);
        trace!(%src, %candidate, "LAN discovery announcement");
        let _ = found.try_send(candidate);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(b: u8) -> NetId {
        NetId([b; 32])
    }

    #[test]
    fn roundtrip_and_rejects() {
        let t = 1_800_000_000;
        let a = Ipv4Addr::new(10, 0, 0, 5);
        let p = encode(Topic::Member, &net(1), t, 41641, Some(a));
        assert_eq!(
            decode(Topic::Member, &net(1), t, &p),
            Some((41641, Some(a)))
        );
        let p6 = encode(Topic::Member, &net(1), t, 41641, None);
        assert_eq!(decode(Topic::Member, &net(1), t, &p6), Some((41641, None)));
        assert_eq!(decode(Topic::Member, &net(2), t, &p), None, "other network");
        assert_eq!(decode(Topic::Member, &net(1), t, &p[..31]), None, "short");
        let mut bad = p;
        bad[0] ^= 1;
        assert_eq!(decode(Topic::Member, &net(1), t, &bad), None, "magic");
        assert_eq!(
            decode(
                Topic::Member,
                &net(1),
                t,
                &encode(Topic::Member, &net(1), t, 0, None)
            ),
            None,
            "port 0"
        );
    }

    #[test]
    fn manager_beacons_are_separate() {
        let t = 1_800_000_000;
        let p = encode(Topic::Manager, &net(1), t, 7, None);
        assert_eq!(decode(Topic::Manager, &net(1), t, &p), Some((7, None)));
        assert_eq!(decode(Topic::Member, &net(1), t, &p), None);
        let m = encode(Topic::Member, &net(1), t, 7, None);
        assert_eq!(decode(Topic::Manager, &net(1), t, &m), None);
    }

    #[test]
    fn candidate_falls_back_to_source() {
        let src: SocketAddr = "192.0.2.1:9".parse().unwrap();
        // TEST-NET addresses are on none of our subnets.
        let off_link = Ipv4Addr::new(198, 51, 100, 7);
        assert_eq!(
            candidate(src, 41641, Some(off_link)),
            "192.0.2.1:41641".parse().unwrap()
        );
        assert_eq!(
            candidate(src, 41641, None),
            "192.0.2.1:41641".parse().unwrap()
        );
        let src6: SocketAddr = "[fe80::1%3]:9".parse().unwrap();
        assert_eq!(
            candidate(src6, 41641, None),
            "[fe80::1%3]:41641".parse().unwrap()
        );
    }

    #[test]
    fn topic_window() {
        let t = 1_800_000_000 - 1_800_000_000 % TOPIC_PERIOD_SECS + 10;
        let p = encode(Topic::Member, &net(1), t, 7, None);
        assert_eq!(
            decode(Topic::Member, &net(1), t + TOPIC_PERIOD_SECS, &p),
            Some((7, None)),
            "previous period"
        );
        assert_eq!(
            decode(Topic::Member, &net(1), t + 2 * TOPIC_PERIOD_SECS, &p),
            None,
            "too old"
        );
        assert_eq!(
            decode(Topic::Member, &net(1), t - TOPIC_PERIOD_SECS, &p),
            None,
            "future period"
        );
    }
}
