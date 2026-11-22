use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use backscale_utp::packet::{Packet, Type};
use backscale_utp::{Transport, UtpConfig, UtpError, UtpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

const A: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
    1,
);
const B: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2)),
    2,
);

type Keep = Arc<dyn Fn(usize) -> bool + Send + Sync>;

// Forwards one direction of an in-memory link, dropping datagrams `keep` rejects.
fn forward(
    mut out: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    into: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    from: SocketAddr,
    keep: Keep,
) {
    tokio::spawn(async move {
        let n = AtomicUsize::new(0);
        while let Some((_, data)) = out.recv().await {
            if keep(n.fetch_add(1, Ordering::Relaxed)) {
                let _ = into.send((from, data)).await;
            }
        }
    });
}

// Two transports, A and B, joined by a link that may drop datagrams. Also
// returns a sender that injects datagrams into B as if from A.
fn link(keep: Keep) -> (Transport, Transport, mpsc::Sender<(SocketAddr, Vec<u8>)>) {
    let (a_in, a_rx) = mpsc::channel(4096);
    let (b_in, b_rx) = mpsc::channel(4096);
    let (a_tx, a_out) = mpsc::channel(4096);
    let (b_tx, b_out) = mpsc::channel(4096);
    forward(a_out, b_in.clone(), A, keep.clone());
    forward(b_out, a_in, B, keep);
    (
        Transport { rx: a_rx, tx: a_tx },
        Transport { rx: b_rx, tx: b_tx },
        b_in,
    )
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

async fn transfer(keep: Keep, len: usize) {
    let (ta, tb, _) = link(keep);
    let a = UtpSocket::new(ta, UtpConfig::default());
    let b = UtpSocket::new(tb, UtpConfig::default());
    let server = tokio::spawn(async move {
        let mut s = b.accept().await.unwrap();
        assert_eq!(s.peer_addr(), A);
        let mut got = Vec::new();
        s.read_to_end(&mut got).await.unwrap();
        (got, s.error(), b)
    });
    let data = pattern(len);
    let mut c = a.connect(B).await.unwrap();
    c.write_all(&data).await.unwrap();
    c.shutdown().await.unwrap();
    let (got, err, _b) = server.await.unwrap();
    assert_eq!(err, None);
    assert!(
        got == data,
        "received {} of {len} bytes, or corrupted",
        got.len()
    );
}

#[tokio::test(start_paused = true)]
async fn transfers_a_megabyte_to_eof() {
    transfer(Arc::new(|_| true), 1 << 20).await;
}

#[tokio::test(start_paused = true)]
async fn retransmits_over_a_lossy_link() {
    transfer(Arc::new(|n| n % 7 != 3), 300_000).await;
}

#[tokio::test(start_paused = true)]
async fn max_conns_refuses_extra_connections() {
    let (ta, tb, _) = link(Arc::new(|_| true));
    let a = UtpSocket::new(ta, UtpConfig::default());
    let b = UtpSocket::new(
        tb,
        UtpConfig {
            max_conns: 1,
            ..UtpConfig::default()
        },
    );
    let accept = tokio::spawn(async move {
        let s = b.accept().await.unwrap();
        (s, b)
    });
    let _first = a.connect(B).await.unwrap();
    let _held = accept.await.unwrap();
    assert_eq!(a.connect(B).await.err(), Some(UtpError::ConnectTimeout));
}

#[tokio::test(start_paused = true)]
async fn ignores_syn_with_reserved_connection_id() {
    let (_ta, tb, inject) = link(Arc::new(|_| true));
    let b = UtpSocket::new(tb, UtpConfig::default());
    // The acceptor would receive on conn_id + 1 == 0, which collides with
    // WireGuard on a shared socket.
    inject
        .send((A, Packet::new(Type::Syn, u16::MAX, 1, 0).encode()))
        .await
        .unwrap();
    let accepted = tokio::time::timeout(Duration::from_secs(10), b.accept()).await;
    assert!(
        accepted.is_err(),
        "a SYN for connection id 0 must not be accepted"
    );
}

#[tokio::test]
async fn udp_transport_roundtrip() {
    let bind = || async { Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()) };
    let (sa, sb) = (bind().await, bind().await);
    let b_addr = sb.local_addr().unwrap();
    let (ta, _pa) = Transport::udp(sa);
    let (tb, _pb) = Transport::udp(sb);
    let a = UtpSocket::new(ta, UtpConfig::default());
    let b = UtpSocket::new(tb, UtpConfig::default());
    let server = tokio::spawn(async move {
        let mut s = b.accept().await.unwrap();
        let mut got = Vec::new();
        s.read_to_end(&mut got).await.unwrap();
        got
    });
    let mut c = a.connect(b_addr).await.unwrap();
    c.write_all(b"over real UDP").await.unwrap();
    c.shutdown().await.unwrap();
    assert_eq!(server.await.unwrap(), b"over real UDP");
}
