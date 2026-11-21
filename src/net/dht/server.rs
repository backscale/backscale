use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use serde_bytes::ByteBuf;

use super::Family;
use super::krpc;
use super::node_id::NodeId;
use super::routing::{K, RoutingTable};
use super::wire::{self, Args, CompactAddr, CompactNodes, CompactNodes6, Resp};

const TOKEN_ROTATE: Duration = Duration::from_secs(5 * 60);
const PEER_TTL: Duration = Duration::from_secs(30 * 60);
const MAX_PEERS_PER_HASH: usize = 100;
const MAX_HASHES: usize = 2000;
const MAX_VALUES_RETURNED: usize = 50;

type QueryError = (i64, &'static str);

pub struct Server {
    secrets: [[u8; 32]; 2],
    rotated: Instant,
    peers: HashMap<NodeId, HashMap<SocketAddr, Instant>>,
}

impl Server {
    pub fn new(now: Instant) -> Self {
        Server {
            secrets: [rand::random(), rand::random()],
            rotated: now,
            peers: HashMap::new(),
        }
    }

    fn token(secret: &[u8; 32], ip: IpAddr) -> Vec<u8> {
        let bytes = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        blake3::keyed_hash(secret, &bytes).as_bytes()[..8].to_vec()
    }

    fn token_for(&self, ip: IpAddr) -> ByteBuf {
        ByteBuf::from(Self::token(&self.secrets[0], ip))
    }

    // Tokens stay valid for one extra rotation period.
    fn token_valid(&self, ip: IpAddr, token: &[u8]) -> bool {
        self.secrets.iter().any(|s| Self::token(s, ip) == token)
    }

    pub fn maintain(&mut self, now: Instant) {
        if now.duration_since(self.rotated) >= TOKEN_ROTATE {
            self.secrets[1] = self.secrets[0];
            self.secrets[0] = rand::random();
            self.rotated = now;
        }
        self.peers.retain(|_, peers| {
            peers.retain(|_, t| now.duration_since(*t) < PEER_TTL);
            !peers.is_empty()
        });
    }

    // `tables` is indexed by `Family`.
    pub fn handle(
        &mut self,
        from: SocketAddr,
        q: &[u8],
        a: &Args,
        tables: [&RoutingTable; 2],
        now: Instant,
    ) -> Result<Resp, QueryError> {
        let own = tables[0].own_id();
        let mut r = Resp {
            id: own,
            ..Default::default()
        };
        // BEP 32: answer in the querier's own family unless it asks otherwise.
        let want: Vec<Family> = match &a.want {
            Some(w) => Family::ALL
                .into_iter()
                .filter(|f| w.iter().any(|x| x.as_slice() == f.want_tag()))
                .collect(),
            None => vec![Family::of(&from)],
        };
        let wants = |f: Family| want.contains(&f);
        let fill_nodes = |r: &mut Resp, target: &NodeId| {
            if wants(Family::V4) {
                r.nodes = Some(CompactNodes(tables[Family::V4 as usize].closest(target, K)));
            }
            if wants(Family::V6) {
                r.nodes6 = Some(CompactNodes6(
                    tables[Family::V6 as usize].closest(target, K),
                ));
            }
        };
        match q {
            krpc::PING => {}
            krpc::FIND_NODE => {
                let target = a.target.ok_or((wire::ERR_PROTOCOL, "missing target"))?;
                fill_nodes(&mut r, &target);
            }
            krpc::GET_PEERS => {
                let ih = a
                    .info_hash
                    .ok_or((wire::ERR_PROTOCOL, "missing info_hash"))?;
                r.token = Some(self.token_for(from.ip()));
                fill_nodes(&mut r, &ih);
                if let Some(peers) = self.peers.get(&ih) {
                    let values: Vec<CompactAddr> = peers
                        .keys()
                        .filter(|a| wants(Family::of(a)))
                        .take(MAX_VALUES_RETURNED)
                        .map(|a| CompactAddr(*a))
                        .collect();
                    if !values.is_empty() {
                        r.values = Some(values);
                    }
                }
            }
            krpc::ANNOUNCE_PEER => {
                let ih = a
                    .info_hash
                    .ok_or((wire::ERR_PROTOCOL, "missing info_hash"))?;
                let token = a
                    .token
                    .as_ref()
                    .ok_or((wire::ERR_PROTOCOL, "missing token"))?;
                if !self.token_valid(from.ip(), token) {
                    return Err((wire::ERR_PROTOCOL, "bad token"));
                }
                let port = if a.implied_port == Some(1) {
                    from.port()
                } else {
                    a.port
                        .and_then(|p| u16::try_from(p).ok())
                        .filter(|&p| p != 0)
                        .ok_or((wire::ERR_PROTOCOL, "bad port"))?
                };
                if !self.peers.contains_key(&ih) && self.peers.len() >= MAX_HASHES {
                    return Err((wire::ERR_SERVER, "peer store full"));
                }
                let peers = self.peers.entry(ih).or_default();
                let addr = SocketAddr::new(from.ip(), port);
                if peers.len() >= MAX_PEERS_PER_HASH
                    && !peers.contains_key(&addr)
                    && let Some(oldest) = peers.iter().min_by_key(|(_, t)| **t).map(|(a, _)| *a)
                {
                    peers.remove(&oldest);
                }
                peers.insert(addr, now);
            }
            _ => return Err((wire::ERR_METHOD, "method unknown")),
        }
        Ok(r)
    }
}
