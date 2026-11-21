// uTP transfer test tool: `listen` echoes a blake3 hash of everything it
// receives, `send` pushes random bytes and verifies the echoed hash.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use rootcause::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

use backscale::net::socket::UdpMux;
use backscale::net::utp::{UtpConfig, UtpSocket, UtpStream};

#[derive(Parser)]
#[command(name = "backscale-utp", version, about = "uTP transfer test tool")]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Accept connections; echo back a blake3 hash of everything received.
    Listen {
        #[arg(long, default_value = "0.0.0.0:7000")]
        bind: SocketAddr,
        /// Exit after one connection.
        #[arg(long)]
        once: bool,
    },
    /// Send random bytes to a listener and verify the echoed hash.
    Send {
        to: SocketAddr,
        #[arg(long, default_value = "0.0.0.0:0")]
        bind: SocketAddr,
        #[arg(long, default_value_t = 10 << 20)]
        bytes: u64,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt::init();
    let result = tokio::runtime::Runtime::new()
        .context("failed to start tokio runtime")
        .map_err(|e| e.into_dynamic())
        .and_then(|rt| {
            rt.block_on(async {
                match cli.command {
                    Cmd::Listen { bind, once } => listen(bind, once).await,
                    Cmd::Send { to, bind, bytes } => send(to, bind, bytes).await,
                }
            })
        });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(report) => {
            eprintln!("{report}");
            ExitCode::FAILURE
        }
    }
}

async fn listen(bind: SocketAddr, once: bool) -> Result<(), Report> {
    let mux = UdpMux::bind(bind).await?;
    info!(addr = %mux.local_addr, "listening");
    let sock = UtpSocket::new(mux.utp, UtpConfig::default());
    loop {
        let s = sock.accept().await?;
        let task = tokio::spawn(receive(s));
        if once {
            task.await.ok();
            // Let the FIN exchange finish before the socket goes away.
            tokio::time::sleep(Duration::from_secs(1)).await;
            return Ok(());
        }
    }
}

async fn receive(mut s: UtpStream) {
    let peer = s.peer_addr();
    let start = Instant::now();
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        match s.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                hasher.update(&buf[..n]);
                total += n as u64;
            }
            Err(e) => {
                warn!(%peer, error = %e, "read failed");
                return;
            }
        }
    }
    if let Some(e) = s.error() {
        warn!(%peer, error = %e, "connection failed");
        return;
    }
    let secs = start.elapsed().as_secs_f64();
    let hash = hasher.finalize();
    println!(
        "{peer}: received {total} bytes in {secs:.2}s ({:.2} MB/s) blake3={hash}",
        total as f64 / secs / 1e6
    );
    let _ = s.write_all(hash.as_bytes()).await;
    let _ = s.shutdown().await;
    let mut rest = Vec::new();
    let _ = s.read_to_end(&mut rest).await;
}

async fn send(to: SocketAddr, bind: SocketAddr, bytes: u64) -> Result<(), Report> {
    let mux = UdpMux::bind(bind).await?;
    let sock = UtpSocket::new(mux.utp, UtpConfig::default());
    let start = Instant::now();
    let mut s = sock.connect(to).await?;
    info!(%to, "connected in {:?}", start.elapsed());
    let mut xof = blake3::Hasher::new()
        .update(&rand::random::<[u8; 32]>())
        .finalize_xof();
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut left = bytes;
    while left > 0 {
        let n = left.min(buf.len() as u64) as usize;
        xof.fill(&mut buf[..n]);
        hasher.update(&buf[..n]);
        s.write_all(&buf[..n]).await.context("write failed")?;
        left -= n as u64;
    }
    s.shutdown().await?;
    let mut echoed = Vec::new();
    s.read_to_end(&mut echoed).await?;
    if let Some(e) = s.error() {
        return Err(report!(e).context("connection failed").into_dynamic());
    }
    let secs = start.elapsed().as_secs_f64();
    let hash = hasher.finalize();
    if echoed != hash.as_bytes() {
        bail!(
            "hash mismatch: sent {hash}, peer reported {}",
            hex::encode(&echoed)
        );
    }
    println!(
        "sent {bytes} bytes in {secs:.2}s ({:.2} MB/s) blake3={hash} verified",
        bytes as f64 / secs / 1e6
    );
    Ok(())
}
