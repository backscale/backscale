use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::task::JoinSet;
use tracing::trace;

use super::krpc;
use super::node_id::NodeId;
use super::routing::K;
use super::wire::{Args, NodeInfo, Resp};
use super::{Family, Inner};

const ALPHA: usize = 3;
const MAX_QUERIES: usize = 256;

#[derive(Debug, Clone)]
pub enum Kind {
    FindNode,
    GetPeers,
}

#[derive(Debug, Clone)]
pub struct Responder {
    pub node: NodeInfo,
    pub token: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
pub struct LookupResult {
    // Closest responding nodes, nearest first.
    pub closest: Vec<Responder>,
    pub peers: Vec<SocketAddr>,
}

// BEP 32: the IPv4 and IPv6 DHTs are separate overlays, so each lookup walks one.
pub async fn lookup(
    inner: &Arc<Inner>,
    target: NodeId,
    kind: Kind,
    family: Family,
) -> LookupResult {
    let own = inner.own_id();
    let mut candidates: BTreeMap<NodeId, NodeInfo> = inner
        .table(family)
        .closest(&target, K * 2)
        .into_iter()
        .map(|n| (target.distance(&n.id), n))
        .collect();
    let mut queried: HashSet<SocketAddr> = HashSet::new();
    let mut responded: BTreeMap<NodeId, Responder> = BTreeMap::new();
    let mut peers: HashSet<SocketAddr> = HashSet::new();
    let mut inflight = JoinSet::new();

    loop {
        while inflight.len() < ALPHA && queried.len() < MAX_QUERIES {
            let kth = (responded.len() >= K).then(|| *responded.keys().nth(K - 1).unwrap());
            let next = candidates
                .iter()
                .find(|(_, n)| !queried.contains(&n.addr))
                .filter(|(d, _)| kth.is_none_or(|kth| **d < kth))
                .map(|(_, n)| *n);
            let Some(node) = next else { break };
            queried.insert(node.addr);
            let inner = inner.clone();
            let kind = kind.clone();
            inflight.spawn(async move {
                let res = query(&inner, node, target, &kind, family).await;
                (node, res)
            });
        }
        let Some(joined) = inflight.join_next().await else {
            break;
        };
        let Ok((node, res)) = joined else { continue };
        let Some(resp) = res else { continue };
        let node = NodeInfo {
            id: resp.id,
            addr: node.addr,
        };
        let nodes = match family {
            Family::V4 => resp.nodes.as_ref().map(|n| &n.0),
            Family::V6 => resp.nodes6.as_ref().map(|n| &n.0),
        };
        for n in nodes.into_iter().flatten() {
            if n.id != own
                && n.addr.port() != 0
                && !n.addr.ip().is_unspecified()
                && Family::of(&n.addr) == family
            {
                candidates.entry(target.distance(&n.id)).or_insert(*n);
            }
        }
        if let Some(values) = &resp.values {
            peers.extend(values.iter().map(|c| c.0));
        }
        responded.insert(
            target.distance(&node.id),
            Responder {
                node,
                token: resp.token.map(|t| t.into_vec()),
            },
        );
    }

    trace!(%target, queried = queried.len(), responded = responded.len(), "lookup done");
    LookupResult {
        closest: responded.into_values().take(K).collect(),
        peers: peers.into_iter().collect(),
    }
}

async fn query(
    inner: &Arc<Inner>,
    node: NodeInfo,
    target: NodeId,
    kind: &Kind,
    family: Family,
) -> Option<Resp> {
    let (q, mut args) = match kind {
        Kind::FindNode => (
            krpc::FIND_NODE,
            Args {
                target: Some(target),
                ..Default::default()
            },
        ),
        Kind::GetPeers => (
            krpc::GET_PEERS,
            Args {
                info_hash: Some(target),
                ..Default::default()
            },
        ),
    };
    args.want = Some(vec![serde_bytes::ByteBuf::from(family.want_tag().to_vec())]);
    inner.query(node.addr, Some(node.id), q, args).await.ok()
}
