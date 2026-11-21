use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use rootcause::prelude::*;
use serde_bytes::ByteBuf;
use tokio::sync::oneshot;

use super::node_id::NodeId;
use super::wire::{Args, CompactAddr, Message, Resp};
use crate::net::socket::PacketTx;

pub const CLIENT_VERSION: &[u8] = b"BK\x00\x01";
const MAX_PENDING: usize = 4096;

pub const PING: &[u8] = b"ping";
pub const FIND_NODE: &[u8] = b"find_node";
pub const GET_PEERS: &[u8] = b"get_peers";
pub const ANNOUNCE_PEER: &[u8] = b"announce_peer";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    Timeout,
    Remote(i64, String),
    Malformed,
    Busy,
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RpcError::Timeout => write!(f, "query timed out"),
            RpcError::Busy => write!(f, "too many queries in flight"),
            RpcError::Remote(code, msg) => write!(f, "remote error {code}: {msg}"),
            RpcError::Malformed => write!(f, "malformed response"),
        }
    }
}

impl std::error::Error for RpcError {}

pub struct Reply {
    pub resp: Resp,
    // Our address as seen by the responder (BEP 42 `ip` field).
    pub seen_as: Option<SocketAddr>,
}

struct Pending {
    addr: SocketAddr,
    reply: oneshot::Sender<Message>,
}

pub struct Rpc {
    tx: PacketTx,
    pending: Mutex<HashMap<[u8; 2], Pending>>,
    next_tid: AtomicU16,
    timeout: Duration,
}

struct PendingGuard<'a> {
    rpc: &'a Rpc,
    tid: [u8; 2],
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.rpc.pending.lock().unwrap().remove(&self.tid);
    }
}

impl Rpc {
    pub fn new(tx: PacketTx, timeout: Duration) -> Self {
        Rpc {
            tx,
            pending: Mutex::new(HashMap::new()),
            next_tid: AtomicU16::new(rand::random()),
            timeout,
        }
    }

    // Bounded well below the 2^16 transaction ids, so finding a free one
    // always terminates quickly.
    fn register(&self, addr: SocketAddr) -> Option<([u8; 2], oneshot::Receiver<Message>)> {
        let (tx, rx) = oneshot::channel();
        let mut pending = self.pending.lock().unwrap();
        if pending.len() >= MAX_PENDING {
            return None;
        }
        loop {
            let tid = self.next_tid.fetch_add(1, Ordering::Relaxed).to_be_bytes();
            if let std::collections::hash_map::Entry::Vacant(v) = pending.entry(tid) {
                v.insert(Pending { addr, reply: tx });
                return Some((tid, rx));
            }
        }
    }

    pub async fn query(
        &self,
        addr: SocketAddr,
        own: NodeId,
        q: &[u8],
        mut args: Args,
    ) -> Result<Reply, Report<RpcError>> {
        args.id = own;
        let (tid, rx) = self.register(addr).ok_or_else(|| report!(RpcError::Busy))?;
        let _guard = PendingGuard { rpc: self, tid };
        let msg = Message {
            t: ByteBuf::from(tid.to_vec()),
            y: ByteBuf::from(b"q".to_vec()),
            q: Some(ByteBuf::from(q.to_vec())),
            a: Some(args),
            v: Some(ByteBuf::from(CLIENT_VERSION.to_vec())),
            ..Default::default()
        };
        self.tx.send(addr, msg.encode());
        let msg = match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(m)) => m,
            _ => {
                return Err(report!(RpcError::Timeout)
                    .attach(format!("{} to {addr}", String::from_utf8_lossy(q))));
            }
        };
        match &msg.y[..] {
            b"r" => {
                let resp = msg.r.ok_or_else(|| report!(RpcError::Malformed))?;
                Ok(Reply {
                    resp,
                    seen_as: msg.ip.map(|c| c.0),
                })
            }
            b"e" => {
                let (code, text) = msg.e.unwrap_or((0, ByteBuf::new()));
                Err(report!(RpcError::Remote(
                    code,
                    String::from_utf8_lossy(&text).into_owned()
                )))
            }
            _ => Err(report!(RpcError::Malformed)),
        }
    }

    pub fn on_reply(&self, from: SocketAddr, msg: Message) {
        let Ok(tid) = <[u8; 2]>::try_from(&msg.t[..]) else {
            return;
        };
        let mut pending = self.pending.lock().unwrap();
        if pending.get(&tid).is_some_and(|p| p.addr == from) {
            let p = pending.remove(&tid).unwrap();
            let _ = p.reply.send(msg);
        }
    }

    pub fn respond(&self, to: SocketAddr, t: ByteBuf, result: Result<Resp, (i64, &str)>) {
        let mut msg = Message {
            t,
            ip: Some(CompactAddr(to)),
            v: Some(ByteBuf::from(CLIENT_VERSION.to_vec())),
            ..Default::default()
        };
        match result {
            Ok(r) => {
                msg.y = ByteBuf::from(b"r".to_vec());
                msg.r = Some(r);
            }
            Err((code, text)) => {
                msg.y = ByteBuf::from(b"e".to_vec());
                msg.e = Some((code, ByteBuf::from(text.as_bytes().to_vec())));
            }
        }
        self.tx.send(to, msg.encode());
    }
}
