// Talks to the public mainline DHT with backscale's DHT implementation.

use std::net::SocketAddr;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use rootcause::prelude::*;

use backscale::net::dht::node_id::NodeId;
use backscale::net::dht::{Dht, DhtConfig};
use backscale::net::socket::UdpMux;

#[derive(Parser)]
#[command(name = "backscale-dht", version, about = "Mainline DHT debugging tool")]
struct Cli {
    /// Local UDP address to bind (`[::]` for dual-stack).
    #[arg(long, global = true, default_value = "0.0.0.0:0")]
    bind: SocketAddr,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Bootstrap and print routing table stats.
    Bootstrap,
    /// Find peers for an infohash.
    GetPeers { info_hash: NodeId },
    /// Announce ourselves for an infohash (implied port).
    Announce { info_hash: NodeId },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt::init();
    let result = tokio::runtime::Runtime::new()
        .context("failed to start tokio runtime")
        .map_err(|e| e.into_dynamic())
        .and_then(|rt| rt.block_on(run(cli.bind, cli.command)));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(report) => {
            eprintln!("{report}");
            ExitCode::FAILURE
        }
    }
}

async fn run(bind: SocketAddr, cmd: Cmd) -> Result<(), Report> {
    let mux = UdpMux::bind(bind).await?;
    let port = mux.local_addr.port();
    let dht = Dht::new(DhtConfig::default(), mux.dht);
    dht.bootstrap().await?;
    match cmd {
        Cmd::Bootstrap => {
            println!("node id:       {}", dht.id());
            println!("local port:    {port}");
            println!("external ipv4: {:?}", dht.external_ip());
            println!("external ipv6: {:?}", dht.external_ip6());
            println!("table size:    {}", dht.table_size());
        }
        Cmd::GetPeers { info_hash } => {
            let peers = dht.get_peers(info_hash).await;
            println!("{} peers", peers.len());
            for p in peers {
                println!("{p}");
            }
        }
        Cmd::Announce { info_hash } => {
            let a = dht.announce(info_hash, port, true).await;
            if a.stored == 0 {
                bail!("announce was not accepted by any node");
            }
            println!(
                "announced to {} nodes ({} peers seen)",
                a.stored,
                a.peers.len()
            );
        }
    }
    Ok(())
}
