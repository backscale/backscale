use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use rootcause::prelude::*;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

// Dual-stack sockets report IPv4 peers as ::ffff:a.b.c.d; everything above
// the socket sees plain IPv4 addresses instead.
pub fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => addr,
        },
        v4 => v4,
    }
}

fn mapped(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
        v6 => v6,
    }
}

// `[::]` binds dual-stack, falling back to IPv4 when the host has no IPv6.
fn bind_socket(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    if let SocketAddr::V6(v6) = addr
        && v6.ip().is_unspecified()
    {
        let dual = (|| {
            let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            s.set_only_v6(false)?;
            s.bind(&addr.into())?;
            Ok::<_, std::io::Error>(s)
        })();
        match dual {
            Ok(s) => {
                s.set_nonblocking(true)?;
                return Ok(s.into());
            }
            // These say nothing about IPv6 support; report them as they are.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                return Err(e);
            }
            Err(e) => {
                warn!(error = %e, "IPv6 unavailable, using IPv4 only");
                return bind_socket(SocketAddr::from(([0, 0, 0, 0], addr.port())));
            }
        }
    }
    let s = std::net::UdpSocket::bind(addr)?;
    s.set_nonblocking(true)?;
    Ok(s)
}

pub const DUAL_STACK_ANY: Ipv6Addr = Ipv6Addr::UNSPECIFIED;

const QUEUE: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Proto {
    Dht,
    Utp,
    Wg,
}

impl Proto {
    // KRPC is a bencoded dict, so it starts with 'd'. WireGuard is a type byte
    // 1-4 followed by three zero bytes; uTP is (type << 4) | version 1. The two
    // only overlap on an ST_DATA with no extension and connection id 0, which
    // our uTP never uses.
    pub fn classify(packet: &[u8]) -> Option<Proto> {
        match packet {
            [b'd', ..] => Some(Proto::Dht),
            [1..=4, 0, 0, 0, ..] => Some(Proto::Wg),
            [b, ..] if b & 0x0F == 1 && b >> 4 <= 4 => Some(Proto::Utp),
            _ => None,
        }
    }
}

// The datagram shape every protocol on the mux uses; the uTP and DHT crates'
// transports carry exactly this, so one mux can feed both.
pub type Datagram = (SocketAddr, Vec<u8>);

#[derive(Clone)]
pub struct PacketTx {
    tx: mpsc::Sender<Datagram>,
}

impl PacketTx {
    pub fn new(tx: mpsc::Sender<Datagram>) -> Self {
        PacketTx { tx }
    }

    pub fn send(&self, addr: SocketAddr, data: Vec<u8>) {
        if self.tx.try_send((addr, data)).is_err() {
            trace!(%addr, "outgoing queue full, dropping packet");
        }
    }
}

pub struct Endpoint {
    pub rx: mpsc::Receiver<Datagram>,
    pub tx: PacketTx,
}

pub struct UdpMux {
    pub local_addr: SocketAddr,
    pub dht: Endpoint,
    pub utp: backscale_utp::Transport,
    pub wg: Endpoint,
    pub tasks: MuxTasks,
}

pub struct MuxTasks(Vec<JoinHandle<()>>);

impl Drop for MuxTasks {
    fn drop(&mut self) {
        for t in &self.0 {
            t.abort();
        }
    }
}

impl UdpMux {
    pub async fn bind(addr: SocketAddr) -> Result<Self, Report> {
        let std_socket = bind_socket(addr)
            .context("failed to bind UDP socket")
            .attach(format!("address: {addr}"))?;
        let socket = std::sync::Arc::new(UdpSocket::from_std(std_socket)?);
        let local_addr = socket.local_addr()?;
        let is_v6 = local_addr.is_ipv6();
        let (out_tx, mut out_rx) = mpsc::channel::<Datagram>(QUEUE);
        let (dht_tx, dht_rx) = mpsc::channel(QUEUE);
        let (utp_tx, utp_rx) = mpsc::channel(QUEUE);
        let (wg_tx, wg_rx) = mpsc::channel(QUEUE);

        let recv_sock = socket.clone();
        let recv = tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let (n, addr) = match recv_sock.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(e) => {
                        // ICMP-induced errors (e.g. ECONNREFUSED) are per-packet.
                        debug!(error = %e, "udp recv error");
                        continue;
                    }
                };
                let addr = canonical(addr);
                let Some(proto) = Proto::classify(&buf[..n]) else {
                    trace!(%addr, "dropping unclassifiable packet");
                    continue;
                };
                let dg = (addr, buf[..n].to_vec());
                let tx = match proto {
                    Proto::Dht => &dht_tx,
                    Proto::Utp => &utp_tx,
                    Proto::Wg => &wg_tx,
                };
                if tx.try_send(dg).is_err() {
                    trace!(?proto, "inbound queue full, dropping packet");
                }
            }
        });

        let send = tokio::spawn(async move {
            while let Some((addr, data)) = out_rx.recv().await {
                let dst = if is_v6 { mapped(addr) } else { addr };
                if addr.is_ipv6() && !is_v6 {
                    continue;
                }
                if let Err(e) = socket.send_to(&data, dst).await {
                    debug!(%addr, error = %e, "udp send error");
                }
            }
        });

        Ok(UdpMux {
            local_addr,
            dht: Endpoint {
                rx: dht_rx,
                tx: PacketTx::new(out_tx.clone()),
            },
            utp: backscale_utp::Transport {
                rx: utp_rx,
                tx: out_tx.clone(),
            },
            wg: Endpoint {
                rx: wg_rx,
                tx: PacketTx::new(out_tx),
            },
            tasks: MuxTasks(vec![recv, send]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify() {
        assert_eq!(Proto::classify(b"d1:ad"), Some(Proto::Dht));
        for t in 1..=4u8 {
            assert_eq!(Proto::classify(&[t, 0, 0, 0, 9]), Some(Proto::Wg));
        }
        // ST_DATA, ST_FIN, ST_STATE, ST_RESET, ST_SYN with a nonzero conn id.
        for b in [0x01u8, 0x11, 0x21, 0x31, 0x41] {
            assert_eq!(Proto::classify(&[b, 0, 0x12, 0x34]), Some(Proto::Utp));
        }
        assert_eq!(Proto::classify(&[0x01, 1, 0, 0]), Some(Proto::Utp));
        assert_eq!(Proto::classify(&[0x51, 0, 1, 0]), None);
        assert_eq!(Proto::classify(&[0x02, 0, 1, 0]), None);
        assert_eq!(Proto::classify(&[]), None);
    }

    #[test]
    fn canonical_addrs() {
        let m: SocketAddr = "[::ffff:10.1.2.3]:5".parse().unwrap();
        assert_eq!(canonical(m), "10.1.2.3:5".parse::<SocketAddr>().unwrap());
        let v6: SocketAddr = "[2001:db8::1]:5".parse().unwrap();
        assert_eq!(canonical(v6), v6);
        assert_eq!(mapped("10.1.2.3:5".parse().unwrap()), m);
    }

    #[tokio::test]
    async fn dual_stack_mux() {
        let any6 = SocketAddr::new(DUAL_STACK_ANY.into(), 0);
        let mut a = UdpMux::bind(any6).await.unwrap();
        let port = a.local_addr.port();
        let mut b4 = UdpMux::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        b4.dht.tx.send(
            SocketAddr::from(([127, 0, 0, 1], port)),
            b"d1:xi4ee".to_vec(),
        );
        let (from, _) = a.dht.rx.recv().await.unwrap();
        assert_eq!(from, b4.local_addr, "IPv4 peer must appear as plain IPv4");
        a.dht.tx.send(from, b"d1:xi5ee".to_vec());
        assert_eq!(b4.dht.rx.recv().await.unwrap().1, b"d1:xi5ee");

        let Ok(mut b6) = UdpMux::bind("[::1]:0".parse().unwrap()).await else {
            eprintln!("host has no IPv6 loopback, skipping the IPv6 half");
            return;
        };
        b6.utp
            .tx
            .try_send((
                SocketAddr::new("::1".parse().unwrap(), port),
                vec![0x21, 0, 0, 7],
            ))
            .unwrap();
        let (from, _) = a.utp.rx.recv().await.unwrap();
        assert_eq!(from, b6.local_addr);
        a.utp.tx.try_send((from, vec![0x21, 0, 0, 8])).unwrap();
        assert_eq!(b6.utp.rx.recv().await.unwrap().1, vec![0x21, 0, 0, 8]);
    }

    #[tokio::test]
    async fn mux_roundtrip() {
        let mut a = UdpMux::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let mut b = UdpMux::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let utp = vec![0x01, 0, 0x12, 0x34];
        let wg = vec![0x01, 0, 0, 0, 9];
        a.utp.tx.try_send((b.local_addr, utp.clone())).unwrap();
        a.dht.tx.send(b.local_addr, b"de".to_vec());
        a.wg.tx.send(b.local_addr, wg.clone());
        assert_eq!(b.utp.rx.recv().await.unwrap(), (a.local_addr, utp));
        assert_eq!(b.dht.rx.recv().await.unwrap().1, b"de");
        assert_eq!(b.wg.rx.recv().await.unwrap().1, wg);
        b.dht.tx.send(a.local_addr, b"d1:xi1ee".to_vec());
        assert_eq!(a.dht.rx.recv().await.unwrap().1, b"d1:xi1ee");
    }
}
