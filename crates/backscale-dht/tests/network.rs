use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use backscale_dht::wire::Message;
use backscale_dht::{Datagram, Dht, DhtConfig, DhtError, NodeId, Transport};
use tokio::sync::mpsc;

type Sent = Arc<Mutex<Vec<Datagram>>>;
type Inboxes = Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Datagram>>>>;

fn addr(i: u8) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::new(10, 0, 0, i).into(), 6881)
}

// An in-memory network: datagrams go to whichever node owns the destination
// address, or nowhere. Every datagram sent is also recorded with its sender.
struct Net {
    inboxes: Inboxes,
    sent: Sent,
}

impl Net {
    fn new() -> Self {
        Net {
            inboxes: Arc::default(),
            sent: Arc::default(),
        }
    }

    fn transport(&self, at: SocketAddr) -> Transport {
        let (in_tx, rx) = mpsc::channel(4096);
        let (tx, mut out) = mpsc::channel::<(SocketAddr, Vec<u8>)>(4096);
        self.inboxes.lock().unwrap().insert(at, in_tx);
        let inboxes = self.inboxes.clone();
        let sent = self.sent.clone();
        tokio::spawn(async move {
            while let Some((to, data)) = out.recv().await {
                sent.lock().unwrap().push((at, data.clone()));
                let dst = inboxes.lock().unwrap().get(&to).cloned();
                if let Some(dst) = dst {
                    let _ = dst.send((at, data)).await;
                }
            }
        });
        Transport { rx, tx }
    }

    fn node(&self, i: u8, seeds: &[SocketAddr], version: Option<&[u8]>) -> Dht {
        let config = DhtConfig {
            routers: vec![],
            nodes: seeds.to_vec(),
            client_version: version.map(|v| v.to_vec()),
            ..DhtConfig::default()
        };
        Dht::new(config, self.transport(addr(i)))
    }
}

// Node 1 is the seed; nodes 2..=n bootstrap through it.
async fn network(n: u8) -> (Net, Vec<Dht>) {
    let net = Net::new();
    let mut nodes = vec![net.node(1, &[], None)];
    for i in 2..=n {
        nodes.push(net.node(i, &[addr(1)], None));
    }
    for d in &nodes[1..] {
        d.bootstrap().await.unwrap();
    }
    // A second round lets early nodes learn about later ones.
    for d in &nodes[1..] {
        d.bootstrap().await.unwrap();
    }
    (net, nodes)
}

#[tokio::test(start_paused = true)]
async fn bootstrap_fills_routing_tables() {
    let (_net, nodes) = network(8).await;
    for (i, d) in nodes.iter().enumerate() {
        assert!(
            d.table_size() >= 3,
            "node {} knows only {}",
            i + 1,
            d.table_size()
        );
    }
}

#[tokio::test(start_paused = true)]
async fn find_node_locates_a_node() {
    let (_net, nodes) = network(8).await;
    let target = nodes[6].id();
    let found = nodes[2].find_node(target).await;
    assert!(
        found.iter().any(|n| n.id == target && n.addr == addr(7)),
        "lookup did not find node 7: {found:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn announce_then_get_peers() {
    let (_net, nodes) = network(8).await;
    let info_hash: NodeId = "0123456789abcdef0123456789abcdef01234567".parse().unwrap();
    let announced = nodes[1].announce(info_hash, 7000, false).await;
    assert!(announced.stored > 0, "announce stored nowhere");
    let peers = nodes[5].get_peers(info_hash).await;
    let expected = SocketAddr::new(addr(2).ip(), 7000);
    assert!(peers.contains(&expected), "{peers:?} lacks {expected}");
}

#[tokio::test(start_paused = true)]
async fn bootstrap_against_a_silent_node_fails() {
    let net = Net::new();
    let d = net.node(1, &[addr(99)], None);
    assert_eq!(d.bootstrap().await, Err(DhtError::BootstrapFailed));
}

#[tokio::test(start_paused = true)]
async fn client_version_only_when_configured() {
    let net = Net::new();
    let seed = net.node(1, &[], None);
    let tagged = net.node(2, &[addr(1)], Some(b"XY\x00\x01"));
    tagged.bootstrap().await.unwrap();
    let sent = net.sent.lock().unwrap().clone();
    let versions = |from: SocketAddr| -> Vec<Option<Vec<u8>>> {
        sent.iter()
            .filter(|(src, _)| *src == from)
            .map(|(_, data)| Message::decode(data).unwrap().v.map(|v| v.into_vec()))
            .collect()
    };
    let tagged_v = versions(addr(2));
    let seed_v = versions(addr(1));
    assert!(!tagged_v.is_empty() && !seed_v.is_empty());
    assert!(
        tagged_v
            .iter()
            .all(|v| v.as_deref() == Some(b"XY\x00\x01".as_slice()))
    );
    assert!(seed_v.iter().all(|v| v.is_none()));
    drop(seed);
}

#[tokio::test]
async fn udp_transport_bootstrap() {
    let bind = || async { Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap()) };
    let (sa, sb) = (bind().await, bind().await);
    let a_addr = sa.local_addr().unwrap();
    let (ta, _pa) = Transport::udp(sa);
    let (tb, _pb) = Transport::udp(sb);
    let config = |nodes: Vec<SocketAddr>| DhtConfig {
        routers: vec![],
        nodes,
        ..DhtConfig::default()
    };
    let a = Dht::new(config(vec![]), ta);
    let b = Dht::new(config(vec![a_addr]), tb);
    assert_eq!(b.bootstrap().await, Ok(1));
    assert!(b.nodes().iter().any(|n| n.id == a.id() && n.addr == a_addr));
}
