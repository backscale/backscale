pub mod conn;
pub mod ledbat;
pub mod packet;
pub mod rtt;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use rootcause::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tracing::trace;

pub use self::conn::UtpError;
use self::conn::{Role, Setup};
use self::packet::{Packet, Type};
use crate::net::socket::{Datagram, Endpoint, PacketTx};

const STREAM_BUFFER: usize = 256 * 1024;
const INBOX: usize = 1024;

#[derive(Debug, Clone)]
pub struct UtpConfig {
    pub syn_retries: u32,
    pub max_timeouts: u32,
    pub accept_backlog: usize,
    // Caps live connections, so a SYN flood can't grow memory without bound.
    pub max_conns: usize,
}

impl Default for UtpConfig {
    fn default() -> Self {
        UtpConfig {
            syn_retries: 4,
            max_timeouts: 8,
            accept_backlog: 64,
            max_conns: 1024,
        }
    }
}

struct ConnEntry {
    inbox: mpsc::Sender<Packet>,
    send_id: u16,
}

struct Shared {
    tx: PacketTx,
    config: UtpConfig,
    conns: Mutex<HashMap<(SocketAddr, u16), ConnEntry>>,
    accept_tx: mpsc::Sender<UtpStream>,
}

pub struct UtpSocket {
    shared: Arc<Shared>,
    accept_rx: tokio::sync::Mutex<mpsc::Receiver<UtpStream>>,
    task: JoinHandle<()>,
}

impl Drop for UtpSocket {
    fn drop(&mut self) {
        self.task.abort();
        self.shared.conns.lock().unwrap().clear();
    }
}

impl UtpSocket {
    pub fn new(endpoint: Endpoint, config: UtpConfig) -> Self {
        let (accept_tx, accept_rx) = mpsc::channel(config.accept_backlog);
        let shared = Arc::new(Shared {
            tx: endpoint.tx,
            config,
            conns: Mutex::new(HashMap::new()),
            accept_tx,
        });
        let task = tokio::spawn(recv_loop(shared.clone(), endpoint.rx));
        UtpSocket {
            shared,
            accept_rx: tokio::sync::Mutex::new(accept_rx),
            task,
        }
    }

    pub async fn connect(&self, addr: SocketAddr) -> Result<UtpStream, Report<UtpError>> {
        let recv_id = {
            let conns = self.shared.conns.lock().unwrap();
            if conns.len() >= self.shared.config.max_conns {
                return Err(report!(UtpError::TooManyConnections));
            }
            loop {
                let id: u16 = rand::random();
                if valid_id_pair(id) && !conns.contains_key(&(addr, id)) {
                    break id;
                }
            }
        };
        let (tx, rx) = oneshot::channel();
        let stream = spawn_conn(
            &self.shared,
            addr,
            recv_id,
            recv_id.wrapping_add(1),
            Role::Connect(tx),
        );
        match rx.await {
            Ok(Ok(())) => Ok(stream),
            Ok(Err(e)) => Err(report!(e).attach(format!("peer: {addr}"))),
            Err(_) => Err(report!(UtpError::SocketClosed)),
        }
    }

    pub async fn accept(&self) -> Result<UtpStream, Report<UtpError>> {
        self.accept_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| report!(UtpError::SocketClosed))
    }
}

fn spawn_conn(
    shared: &Arc<Shared>,
    addr: SocketAddr,
    recv_id: u16,
    send_id: u16,
    role: Role,
) -> UtpStream {
    let (inbox_tx, inbox) = mpsc::channel(INBOX);
    shared.conns.lock().unwrap().insert(
        (addr, recv_id),
        ConnEntry {
            inbox: inbox_tx,
            send_id,
        },
    );
    let (ours, theirs) = tokio::io::duplex(STREAM_BUFFER);
    let (status_tx, status_rx) = watch::channel(None);
    let weak = Arc::downgrade(shared);
    let setup = Setup {
        addr,
        recv_id,
        send_id,
        tx: shared.tx.clone(),
        config: shared.config.clone(),
        inbox,
        app: ours,
        status: status_tx,
        on_exit: Box::new(move || {
            if let Some(shared) = weak.upgrade() {
                shared.conns.lock().unwrap().remove(&(addr, recv_id));
            }
        }),
    };
    tokio::spawn(conn::run(setup, role));
    UtpStream {
        io: theirs,
        peer: addr,
        status: status_rx,
    }
}

async fn recv_loop(shared: Arc<Shared>, mut rx: mpsc::Receiver<Datagram>) {
    while let Some(dg) = rx.recv().await {
        let p = match Packet::decode(&dg.data) {
            Ok(p) => p,
            Err(e) => {
                trace!(addr = %dg.addr, error = %e, "dropping malformed uTP packet");
                continue;
            }
        };
        dispatch(&shared, dg.addr, p);
    }
}

// A connection uses `id` and `id + 1`. Neither may be 0: an ST_DATA with
// connection id 0 is indistinguishable from a WireGuard handshake initiation.
fn valid_id_pair(id: u16) -> bool {
    id != 0 && id != u16::MAX
}

fn dispatch(shared: &Arc<Shared>, addr: SocketAddr, p: Packet) {
    let target = {
        let conns = shared.conns.lock().unwrap();
        match p.ty {
            // A SYN names the initiator's receive id; we receive on id + 1.
            // Only a connection we accepted for it matches: one of our own
            // outgoing connections could hold the same id by chance.
            Type::Syn => conns
                .get(&(addr, p.conn_id.wrapping_add(1)))
                .filter(|e| e.send_id == p.conn_id),
            // Resets carry the id the peer was sending to, which is our send id.
            Type::Reset => [p.conn_id.wrapping_sub(1), p.conn_id.wrapping_add(1)]
                .iter()
                .filter_map(|id| conns.get(&(addr, *id)))
                .find(|e| e.send_id == p.conn_id),
            _ => conns.get(&(addr, p.conn_id)),
        }
        .map(|e| e.inbox.clone())
    };
    if let Some(inbox) = target {
        let _ = inbox.try_send(p);
        return;
    }
    match p.ty {
        Type::Syn => {
            if !valid_id_pair(p.conn_id) {
                trace!(%addr, conn_id = p.conn_id, "ignoring SYN with a reserved connection id");
                return;
            }
            let recv_id = p.conn_id.wrapping_add(1);
            {
                let conns = shared.conns.lock().unwrap();
                if conns.len() >= shared.config.max_conns || conns.contains_key(&(addr, recv_id)) {
                    trace!(%addr, "too many connections or id collision, ignoring SYN");
                    return;
                }
            }
            let Ok(permit) = shared.accept_tx.try_reserve() else {
                trace!(%addr, "accept backlog full, ignoring SYN");
                return;
            };
            let send_id = p.conn_id;
            permit.send(spawn_conn(shared, addr, recv_id, send_id, Role::Accept(p)));
        }
        Type::Reset => {}
        _ => {
            trace!(%addr, conn_id = p.conn_id, "packet for unknown connection, sending reset");
            let reset = Packet::new(Type::Reset, p.conn_id, 0, p.seq_nr);
            shared.tx.send(addr, reset.encode());
        }
    }
}

pub struct UtpStream {
    io: DuplexStream,
    peer: SocketAddr,
    status: watch::Receiver<Option<UtpError>>,
}

impl UtpStream {
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    // Distinguishes a clean EOF from a failed connection.
    pub fn error(&self) -> Option<UtpError> {
        self.status.borrow().clone()
    }
}

impl AsyncRead for UtpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for UtpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
