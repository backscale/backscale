use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::{Instant, sleep_until};
use tracing::{debug, trace};

use super::UtpConfig;
use super::ledbat::Ledbat;
use super::packet::{Packet, Type, sack_build, sack_contains, seq_le, seq_lt};
use super::rtt::Rtt;
use crate::PacketTx;

// Keeps a full packet under ~1200 bytes, safe for tunnels and odd MTUs.
pub const PAYLOAD: usize = 1150;
const MAX_RECV_BUF: usize = 1 << 20;
const OOO_WINDOW: u16 = 2048;
const SACK_BYTES: usize = 32;
const READ_CHUNK: usize = 64 * 1024;
const KEEPALIVE: Duration = Duration::from_secs(25);
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_LINGER: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UtpError {
    ConnectTimeout,
    Refused,
    Timeout,
    Reset,
    SocketClosed,
    TooManyConnections,
}

impl fmt::Display for UtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            UtpError::ConnectTimeout => "uTP connect timed out",
            UtpError::Refused => "uTP connection refused",
            UtpError::Timeout => "uTP connection timed out",
            UtpError::Reset => "uTP connection reset by peer",
            UtpError::SocketClosed => "uTP socket closed",
            UtpError::TooManyConnections => "too many uTP connections",
        })
    }
}

impl std::error::Error for UtpError {}

pub(super) enum Role {
    Connect(oneshot::Sender<Result<(), UtpError>>),
    Accept(Packet),
}

pub(super) struct Setup {
    pub addr: SocketAddr,
    pub recv_id: u16,
    pub send_id: u16,
    pub tx: PacketTx,
    pub config: UtpConfig,
    pub inbox: mpsc::Receiver<Packet>,
    pub app: DuplexStream,
    pub status: watch::Sender<Option<UtpError>>,
    pub on_exit: Box<dyn FnOnce() + Send>,
}

struct Sent {
    seq: u16,
    ty: Type,
    payload: Vec<u8>,
    sent_at: Instant,
    transmissions: u32,
    sacked: bool,
    lost: bool,
}

#[derive(Debug, Default)]
struct Stats {
    sent: u64,
    resent: u64,
    received: u64,
}

struct Conn {
    addr: SocketAddr,
    recv_id: u16,
    send_id: u16,
    tx: PacketTx,
    config: UtpConfig,
    epoch: Instant,

    connected: bool,
    acceptor: bool,
    // The acceptor holds back data until the initiator has provably seen
    // its SYN-ACK; otherwise the initiator could sync on a later sequence number.
    confirmed: bool,
    syn_seq: u16,
    connect_tx: Option<oneshot::Sender<Result<(), UtpError>>>,
    error: Option<UtpError>,

    seq_nr: u16,
    ack_nr: u16,
    unacked: VecDeque<Sent>,
    // Payload bytes of unacked packets that are neither SACKed nor deemed lost.
    inflight: usize,
    peer_wnd: usize,
    last_ack_seen: u16,
    dup_acks: u32,
    recovery_seq: u16,
    fin_acked: bool,
    app_eof: bool,

    ooo: HashMap<u16, (Type, Vec<u8>)>,
    ooo_bytes: usize,
    recv_buf: VecDeque<u8>,
    peer_fin: bool,
    app_write_open: bool,
    app_write_shut: bool,
    ack_pending: bool,
    last_advertised: usize,
    reply_micros: u32,

    rtt: Rtt,
    cc: Ledbat,
    last_recv: Instant,
    last_send: Instant,
    rto_deadline: Option<Instant>,
    timeouts: u32,
    linger_until: Option<Instant>,
    stats: Stats,
}

impl Conn {
    fn now_micros(&self) -> u32 {
        Instant::now().duration_since(self.epoch).as_micros() as u32
    }

    fn recv_window(&self) -> usize {
        MAX_RECV_BUF.saturating_sub(self.recv_buf.len() + self.ooo_bytes)
    }

    fn inflight(&self) -> usize {
        debug_assert_eq!(
            self.inflight,
            self.unacked
                .iter()
                .filter(|s| !s.sacked && !s.lost)
                .map(|s| s.payload.len())
                .sum::<usize>(),
            "inflight counter out of sync"
        );
        self.inflight
    }

    // Removes a packet from the in-flight count (SACKed, acked or lost).
    fn uncount(inflight: &mut usize, s: &Sent) {
        if !s.sacked && !s.lost {
            *inflight -= s.payload.len();
        }
    }

    fn send_window(&self) -> usize {
        self.cc.cwnd().min(self.peer_wnd)
    }

    // A lone packet may always go out so a zero window can't deadlock.
    fn can_send(&self, len: usize) -> bool {
        let inflight = self.inflight();
        inflight == 0 || inflight + len <= self.send_window()
    }

    fn send_packet(&mut self, mut p: Packet) {
        p.ts_micros = self.now_micros();
        p.ts_diff_micros = self.reply_micros;
        let wnd = self.recv_window();
        p.wnd = wnd as u32;
        self.last_advertised = wnd;
        if p.ty != Type::Syn {
            p.ack_nr = self.ack_nr;
            p.sack = sack_build(self.ack_nr, self.ooo.keys().copied(), SACK_BYTES);
        }
        trace!(ty = ?p.ty, seq = p.seq_nr, ack = p.ack_nr, len = p.payload.len(), "send");
        self.tx.send(self.addr, p.encode());
        self.last_send = Instant::now();
        self.ack_pending = false;
    }

    fn send_state(&mut self) {
        self.send_packet(Packet::new(Type::State, self.send_id, self.seq_nr, 0));
    }

    fn transmit(&mut self, idx: usize) {
        let now = Instant::now();
        let s = &mut self.unacked[idx];
        if !s.sacked && (s.lost || s.transmissions == 0) {
            self.inflight += s.payload.len();
        }
        s.sent_at = now;
        s.transmissions += 1;
        s.lost = false;
        let conn_id = if s.ty == Type::Syn {
            self.recv_id
        } else {
            self.send_id
        };
        let mut p = Packet::new(s.ty, conn_id, s.seq, 0);
        p.payload = s.payload.clone();
        if s.transmissions > 1 {
            self.stats.resent += 1;
        }
        self.stats.sent += 1;
        self.send_packet(p);
        if self.rto_deadline.is_none() {
            self.rto_deadline = Some(now + self.rtt.rto());
        }
    }

    fn send_new(&mut self, ty: Type, payload: Vec<u8>) {
        self.unacked.push_back(Sent {
            seq: self.seq_nr,
            ty,
            payload,
            sent_at: Instant::now(),
            transmissions: 0,
            sacked: false,
            lost: false,
        });
        self.seq_nr = self.seq_nr.wrapping_add(1);
        self.transmit(self.unacked.len() - 1);
    }

    fn resend_lost(&mut self) {
        for i in 0..self.unacked.len() {
            let s = &self.unacked[i];
            if s.lost && !s.sacked {
                if !self.can_send(s.payload.len()) {
                    break;
                }
                self.transmit(i);
            }
        }
    }

    fn fail(&mut self, err: UtpError) {
        debug!(addr = %self.addr, error = %err, "uTP connection failed");
        if let Some(tx) = self.connect_tx.take() {
            let _ = tx.send(Err(err.clone()));
        }
        self.error = Some(err);
    }

    fn on_packet(&mut self, p: Packet) {
        let now = Instant::now();
        self.last_recv = now;
        self.stats.received += 1;
        self.reply_micros = self.now_micros().wrapping_sub(p.ts_micros);
        trace!(ty = ?p.ty, seq = p.seq_nr, ack = p.ack_nr, len = p.payload.len(), "recv");
        match p.ty {
            Type::Reset => {
                self.fail(if self.connected {
                    UtpError::Reset
                } else {
                    UtpError::Refused
                });
                return;
            }
            Type::Syn => {
                if self.acceptor {
                    self.ack_pending = true;
                }
                return;
            }
            _ => {}
        }
        if self.acceptor && !self.confirmed {
            self.confirmed = true;
            self.timeouts = 0;
            self.rto_deadline = None;
        }
        if !self.connected {
            if p.ty != Type::State {
                return;
            }
            self.connected = true;
            self.confirmed = true;
            self.ack_nr = p.seq_nr.wrapping_sub(1);
            self.ack_pending = true;
            if let Some(tx) = self.connect_tx.take() {
                let _ = tx.send(Ok(()));
            }
        }
        self.peer_wnd = p.wnd as usize;
        if !self.acceptor
            && p.ty == Type::State
            && p.ack_nr == self.syn_seq
            && p.seq_nr == self.ack_nr.wrapping_add(1)
        {
            // Possibly a retransmitted SYN-ACK: confirm again.
            self.ack_pending = true;
        }
        self.on_ack(&p, now);
        if matches!(p.ty, Type::Data | Type::Fin) {
            self.on_data(p);
        }
    }

    fn on_ack(&mut self, p: &Packet, now: Instant) {
        let last_sent = self.seq_nr.wrapping_sub(1);
        if seq_lt(last_sent, p.ack_nr) {
            return;
        }
        let mut acked_bytes = 0;
        let mut progressed = false;
        while let Some(front) = self.unacked.front() {
            if !seq_le(front.seq, p.ack_nr) {
                break;
            }
            let s = self.unacked.pop_front().unwrap();
            Self::uncount(&mut self.inflight, &s);
            if !s.sacked {
                acked_bytes += s.payload.len();
                if s.transmissions == 1 {
                    self.rtt.sample(now.duration_since(s.sent_at));
                }
            }
            if s.ty == Type::Fin {
                self.fin_acked = true;
            }
            progressed = true;
        }

        let mut lost = Vec::new();
        if let Some(mask) = &p.sack {
            for s in self.unacked.iter_mut() {
                if !s.sacked && sack_contains(mask, p.ack_nr, s.seq) {
                    Self::uncount(&mut self.inflight, s);
                    s.sacked = true;
                    acked_bytes += s.payload.len();
                    if s.transmissions == 1 {
                        self.rtt.sample(now.duration_since(s.sent_at));
                    }
                }
            }
            let mut sacked_after = 0;
            for (i, s) in self.unacked.iter().enumerate().rev() {
                if s.sacked {
                    sacked_after += 1;
                } else if sacked_after >= 3 {
                    lost.push(i);
                }
            }
        }

        // Keepalives and window updates repeat the ack too; only an ack with
        // SACK data means the receiver got later packets out of order.
        let is_dup = !progressed
            && p.ty == Type::State
            && p.sack.is_some()
            && p.ack_nr == self.last_ack_seen
            && !self.unacked.is_empty();
        if is_dup {
            self.dup_acks += 1;
            if self.dup_acks >= 3 {
                lost.push(0);
            }
        } else {
            self.dup_acks = 0;
        }
        self.last_ack_seen = p.ack_nr;

        // Don't re-declare a packet lost until its last transmission had time to be acked.
        let recent = self.rtt.srtt().unwrap_or(self.rtt.rto());
        for i in lost {
            let s = &mut self.unacked[i];
            if s.lost || s.sacked || now.duration_since(s.sent_at) < recent {
                continue;
            }
            Self::uncount(&mut self.inflight, s);
            s.lost = true;
            if seq_lt(self.recovery_seq, s.seq) {
                self.cc.on_loss();
                self.recovery_seq = self.seq_nr.wrapping_sub(1);
            }
        }

        if acked_bytes > 0 {
            let delay = (p.ts_diff_micros != 0).then_some(p.ts_diff_micros);
            self.cc.on_ack(acked_bytes, delay, now);
        }
        if progressed {
            self.timeouts = 0;
            self.rto_deadline = if self.unacked.is_empty() {
                None
            } else {
                Some(now + self.rtt.rto())
            };
        }
    }

    fn on_data(&mut self, p: Packet) {
        self.ack_pending = true;
        let seq = p.seq_nr;
        if self.peer_fin || seq_le(seq, self.ack_nr) {
            return;
        }
        let ahead = seq.wrapping_sub(self.ack_nr);
        if ahead > OOO_WINDOW
            || self.recv_buf.len() + self.ooo_bytes + p.payload.len() > 2 * MAX_RECV_BUF
        {
            return;
        }
        if ahead == 1 {
            self.accept_in_order(p.ty, p.payload);
            while !self.peer_fin {
                let next = self.ack_nr.wrapping_add(1);
                let Some((ty, payload)) = self.ooo.remove(&next) else {
                    break;
                };
                self.ooo_bytes -= payload.len();
                self.accept_in_order(ty, payload);
            }
        } else if !self.ooo.contains_key(&seq) {
            self.ooo_bytes += p.payload.len();
            self.ooo.insert(seq, (p.ty, p.payload));
        }
    }

    fn accept_in_order(&mut self, ty: Type, payload: Vec<u8>) {
        self.ack_nr = self.ack_nr.wrapping_add(1);
        match ty {
            Type::Data if self.app_write_open => self.recv_buf.extend(payload),
            Type::Fin => {
                self.peer_fin = true;
                self.ooo.clear();
                self.ooo_bytes = 0;
            }
            _ => {}
        }
    }

    fn deadline(&self) -> Instant {
        let mut d = self.last_recv + IDLE_TIMEOUT;
        if self.connected {
            d = d.min(self.last_send + KEEPALIVE);
        }
        if let Some(r) = self.rto_deadline {
            d = d.min(r);
        }
        if let Some(l) = self.linger_until {
            d = d.min(l);
        }
        d
    }

    fn on_timer(&mut self) {
        let now = Instant::now();
        if self.rto_deadline.is_some_and(|r| now >= r) {
            self.on_rto(now);
        }
        if self.error.is_none() && now >= self.last_recv + IDLE_TIMEOUT {
            self.fail(UtpError::Timeout);
        }
        if self.error.is_none() && self.connected && now >= self.last_send + KEEPALIVE {
            self.send_state();
        }
    }

    fn on_rto(&mut self, now: Instant) {
        if self.acceptor && !self.confirmed {
            // The initiator already considers itself connected, so be as
            // patient as with data rather than using the SYN budget.
            self.timeouts += 1;
            if self.timeouts > self.config.max_timeouts {
                self.fail(UtpError::ConnectTimeout);
                return;
            }
            self.rtt.backoff();
            self.send_state();
            self.rto_deadline = Some(now + self.rtt.rto());
            return;
        }
        if self.unacked.is_empty() {
            self.rto_deadline = None;
            return;
        }
        self.timeouts += 1;
        let limit = if self.connected {
            self.config.max_timeouts
        } else {
            self.config.syn_retries
        };
        if self.timeouts > limit {
            self.fail(if self.connected {
                UtpError::Timeout
            } else {
                UtpError::ConnectTimeout
            });
            return;
        }
        trace!(timeouts = self.timeouts, rto = ?self.rtt.rto(), "retransmission timeout");
        self.rtt.backoff();
        if self.connected {
            self.cc.on_timeout();
        }
        for s in self.unacked.iter_mut() {
            if !s.sacked {
                Self::uncount(&mut self.inflight, s);
                s.lost = true;
            }
        }
        self.recovery_seq = self.seq_nr.wrapping_sub(1);
        self.rto_deadline = Some(now + self.rtt.rto());
    }

    fn finished(&self) -> bool {
        let sent_done = self.fin_acked;
        let recv_done = (self.peer_fin && self.recv_buf.is_empty()) || !self.app_write_open;
        sent_done && recv_done
    }
}

pub(super) async fn run(setup: Setup, role: Role) {
    let Setup {
        addr,
        recv_id,
        send_id,
        tx,
        config,
        mut inbox,
        app,
        status,
        on_exit,
    } = setup;
    let now = Instant::now();
    let (acceptor, connect_tx, syn) = match role {
        Role::Connect(c) => (false, Some(c), None),
        Role::Accept(syn) => (true, None, Some(syn)),
    };
    // BEP 29: the initiator starts at 1, the acceptor at a random number.
    let seq_nr = if acceptor { rand::random::<u16>() } else { 1 };
    let mut c = Conn {
        addr,
        recv_id,
        send_id,
        tx,
        config,
        epoch: now,
        connected: acceptor,
        acceptor,
        confirmed: !acceptor,
        syn_seq: seq_nr,
        connect_tx,
        error: None,
        seq_nr,
        ack_nr: 0,
        unacked: VecDeque::new(),
        inflight: 0,
        peer_wnd: MAX_RECV_BUF,
        last_ack_seen: 0,
        dup_acks: 0,
        recovery_seq: seq_nr.wrapping_sub(1),
        fin_acked: false,
        app_eof: false,
        ooo: HashMap::new(),
        ooo_bytes: 0,
        recv_buf: VecDeque::new(),
        peer_fin: false,
        app_write_open: true,
        app_write_shut: false,
        ack_pending: false,
        last_advertised: MAX_RECV_BUF,
        reply_micros: 0,
        rtt: Rtt::default(),
        cc: Ledbat::new(PAYLOAD, now),
        last_recv: now,
        last_send: now,
        rto_deadline: None,
        timeouts: 0,
        linger_until: None,
        stats: Stats::default(),
    };

    match syn {
        Some(syn) => {
            c.ack_nr = syn.seq_nr;
            c.peer_wnd = syn.wnd as usize;
            c.reply_micros = c.now_micros().wrapping_sub(syn.ts_micros);
            c.send_state();
            c.rto_deadline = Some(now + c.rtt.rto());
        }
        None => c.send_new(Type::Syn, Vec::new()),
    }

    let (mut app_r, mut app_w) = tokio::io::split(app);
    // Allocated once there's something to read: unconfirmed connections
    // (e.g. spoofed SYNs) never need it.
    let mut read_buf = Vec::new();

    while c.error.is_none() {
        let window_left = c.send_window().saturating_sub(c.inflight());
        let can_read = c.connected && c.confirmed && !c.app_eof && c.can_send(PAYLOAD);
        if can_read && read_buf.is_empty() {
            read_buf.resize(READ_CHUNK, 0);
        }
        let read_len = window_left.clamp(PAYLOAD, READ_CHUNK).min(read_buf.len());
        let can_write = c.app_write_open && !c.recv_buf.is_empty();
        let deadline = c.deadline();

        tokio::select! {
            pkt = inbox.recv() => match pkt {
                Some(p) => {
                    c.on_packet(p);
                    while c.error.is_none() && let Ok(p) = inbox.try_recv() {
                        c.on_packet(p);
                    }
                }
                None => c.fail(UtpError::SocketClosed),
            },
            n = app_r.read(&mut read_buf[..read_len]), if can_read => match n {
                Ok(0) | Err(_) => {
                    c.app_eof = true;
                    c.send_new(Type::Fin, Vec::new());
                }
                Ok(n) => {
                    for chunk in read_buf[..n].chunks(PAYLOAD) {
                        c.send_new(Type::Data, chunk.to_vec());
                    }
                }
            },
            n = app_w.write(c.recv_buf.as_slices().0), if can_write => match n {
                Ok(n) if n > 0 => {
                    c.recv_buf.drain(..n);
                    if c.last_advertised < MAX_RECV_BUF / 4 && c.recv_window() >= MAX_RECV_BUF / 2 {
                        c.ack_pending = true;
                    }
                }
                _ => {
                    c.app_write_open = false;
                    c.recv_buf.clear();
                }
            },
            _ = sleep_until(deadline) => c.on_timer(),
        }

        if c.error.is_some() {
            break;
        }
        c.resend_lost();
        if c.ack_pending {
            c.send_state();
        }
        if c.peer_fin && c.recv_buf.is_empty() && !c.app_write_shut {
            let _ = app_w.shutdown().await;
            c.app_write_shut = true;
        }
        if c.finished() {
            match c.linger_until {
                None => {
                    // Stay around briefly to re-ack a retransmitted FIN.
                    c.linger_until = Some(Instant::now() + (c.rtt.rto() * 2).min(MAX_LINGER));
                }
                Some(l) if Instant::now() >= l => break,
                Some(_) => {}
            }
        }
    }

    debug!(
        %addr,
        sent = c.stats.sent,
        resent = c.stats.resent,
        received = c.stats.received,
        srtt = ?c.rtt.srtt(),
        cwnd = c.cc.cwnd(),
        error = ?c.error,
        "uTP connection closed"
    );
    let _ = status.send(c.error.clone());
    on_exit();
}
