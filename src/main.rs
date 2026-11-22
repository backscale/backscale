use atomic_write_file::AtomicWriteFile;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use rootcause::prelude::*;
use tracing::info;

use backscale::config::{Config, StateDir};
use backscale::daemon::{self, Request, Response, Status};
use backscale::identity::soft::SoftSigner;
use backscale::identity::{KeySpec, PublicKey, Signer};
use backscale::manifest::{ManifestDraft, NetworkManifest, Selector, SignedManifest};

mod card;

const DEFAULT_STATE_DIR: &str = "/var/lib/backscale";

#[derive(Parser)]
#[command(name = "backscale", version, about = "Serverless mesh VPN")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a state directory and identity for joining a network.
    Join {
        /// The network public key (`ed25519:<hex>`) to pin.
        #[arg(required_unless_present = "card", conflicts_with = "card")]
        network_key: Option<PublicKey>,
        /// Join using the enrollment stored on a YubiKey (PIV slot, default 82).
        #[arg(long, num_args = 0..=1, default_missing_value = "82", value_name = "SLOT")]
        card: Option<String>,
        #[arg(long, env = "BACKSCALE_STATE_DIR", default_value = DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
        /// `[::]` listens on both IPv4 and IPv6.
        #[arg(long, default_value = "[::]:41641")]
        listen: SocketAddr,
        /// Static peer to connect to (repeatable).
        #[arg(long = "peer")]
        peers: Vec<SocketAddr>,
        /// Don't use the BitTorrent DHT for discovery.
        #[arg(long)]
        no_dht: bool,
    },
    /// Provision a YubiKey so a fresh machine can join with `join --card`:
    /// key on the card, membership in the manifest, enrollment certificate.
    Enroll {
        /// PIV slot for the node's key (hex).
        #[arg(long, default_value = "82")]
        piv: String,
        /// Network key spec that signs the manifest.
        #[arg(long)]
        network_key: KeySpec,
        /// The node's name in the network.
        #[arg(long)]
        name: String,
        /// Bootstrap peer stored on the card (repeatable).
        #[arg(long = "peer")]
        peers: Vec<SocketAddr>,
        #[arg(long, default_value = "net.toml")]
        draft: PathBuf,
        /// Where to write the newly signed manifest (publish it to the network).
        #[arg(long, default_value = "manifest.bsm")]
        out: PathBuf,
        #[arg(long, default_value = "30d", value_parser = humantime::parse_duration)]
        validity: Duration,
        /// Replace an existing key in the slot instead of reusing it.
        #[arg(long)]
        regenerate: bool,
        /// Touch policy for a newly generated key: never, always or cached.
        #[arg(long, default_value = "never")]
        touch: String,
        /// Don't store the manifest on the card.
        #[arg(long)]
        no_manifest: bool,
    },
    /// Inspect a YubiKey enrollment.
    #[command(subcommand)]
    Card(CardCmd),
    /// Run the daemon.
    Up {
        #[arg(long, env = "BACKSCALE_STATE_DIR", default_value = DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
    },
    /// Show daemon status.
    Status {
        #[arg(long, env = "BACKSCALE_STATE_DIR", default_value = DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
    },
    /// Manage identity keys.
    #[command(subcommand)]
    Key(KeyCmd),
    /// Administer a network (manifest draft, signing).
    #[command(subcommand)]
    Net(NetCmd),
}

#[derive(Subcommand)]
enum CardCmd {
    /// Print the enrollment stored on the card.
    Show {
        #[arg(long, default_value = "82")]
        piv: String,
    },
}

#[derive(Subcommand)]
enum KeyCmd {
    /// Generate a key: a software ed25519 key file, or a P-256 key on a YubiKey PIV slot.
    Gen {
        /// File to write a software key to (must not exist).
        #[arg(long, conflicts_with = "piv", required_unless_present = "piv")]
        out: Option<PathBuf>,
        /// YubiKey PIV slot to generate in (hex, e.g. 82 or 9c). Uses the
        /// management key from BACKSCALE_PIV_MGM (hex), or the factory default.
        #[arg(long)]
        piv: Option<String>,
        /// Touch policy for the PIV key: never, always or cached.
        #[arg(long, default_value = "never", requires = "piv")]
        touch: String,
        /// Replace an existing key in the PIV slot.
        #[arg(long, requires = "piv")]
        force: bool,
    },
    /// Print the public key of an identity key.
    Show {
        /// Key spec: `soft:/path`, `piv:<slot>[@serial]` or `openpgp[:<ident>]`.
        #[arg(long)]
        key: KeySpec,
    },
}

#[derive(Subcommand)]
enum NetCmd {
    /// Create a new manifest draft for a network.
    Init {
        /// Network key spec (the key that signs manifests).
        #[arg(long)]
        network_key: KeySpec,
        /// Network name.
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "net.toml")]
        draft: PathBuf,
    },
    /// Add a member to the manifest draft.
    AddMember {
        /// The member's identity public key (`ed25519:<hex>`).
        identity: PublicKey,
        #[arg(long)]
        name: String,
        /// Fixed IPv4 address (default: next free).
        #[arg(long)]
        ipv4: Option<Ipv4Addr>,
        /// Fixed IPv6 address (default: next free).
        #[arg(long)]
        ipv6: Option<Ipv6Addr>,
        #[arg(long = "tag")]
        tags: Vec<String>,
        #[arg(long, default_value = "net.toml")]
        draft: PathBuf,
    },
    /// Remove a member (by name or identity key) from the manifest draft.
    RemoveMember {
        who: String,
        #[arg(long, default_value = "net.toml")]
        draft: PathBuf,
    },
    /// Add or remove a member's tags in the manifest draft.
    Tag {
        who: String,
        #[arg(long = "add")]
        add: Vec<String>,
        #[arg(long = "remove")]
        remove: Vec<String>,
        #[arg(long, default_value = "net.toml")]
        draft: PathBuf,
    },
    /// Edit the draft's ACL (who may reach whom over the overlay).
    Acl {
        #[command(subcommand)]
        cmd: AclCmd,
    },
    /// Sign the draft into a new manifest version.
    Sign {
        #[arg(long)]
        network_key: KeySpec,
        #[arg(long, default_value = "net.toml")]
        draft: PathBuf,
        /// How long the manifest stays valid.
        #[arg(long, default_value = "30d", value_parser = humantime::parse_duration)]
        validity: Duration,
        #[arg(long, default_value = "manifest.bsm")]
        out: PathBuf,
    },
    /// Hand a signed manifest to the local daemon, which spreads it to peers.
    Publish {
        file: PathBuf,
        #[arg(long, env = "BACKSCALE_STATE_DIR", default_value = DEFAULT_STATE_DIR)]
        state_dir: PathBuf,
    },
    /// Show (and verify) a signed manifest.
    Show {
        file: PathBuf,
        /// Pinned network public key to verify against.
        #[arg(long)]
        pin: Option<PublicKey>,
    },
}

#[derive(Subcommand)]
enum AclCmd {
    /// Allow members matching `--from` and members matching `--to` to reach
    /// each other. Selectors: `*`, a member name or `tag:<tag>`.
    Add {
        #[arg(long, required = true, num_args = 1..)]
        from: Vec<String>,
        #[arg(long, required = true, num_args = 1..)]
        to: Vec<String>,
        #[arg(long, default_value = "net.toml")]
        draft: PathBuf,
    },
    /// List the draft's ACL rules.
    List {
        #[arg(long, default_value = "net.toml")]
        draft: PathBuf,
    },
    /// Remove rule N (as numbered by `list`).
    Remove {
        n: usize,
        #[arg(long, default_value = "net.toml")]
        draft: PathBuf,
    },
    /// Drop the ACL: every member may reach every member again.
    Clear {
        #[arg(long, default_value = "net.toml")]
        draft: PathBuf,
    },
}

fn selectors(raw: &[String]) -> Result<Vec<Selector>, Report> {
    raw.iter().map(|s| s.parse()).collect()
}

fn acl_cmd(cmd: AclCmd) -> Result<(), Report> {
    match cmd {
        AclCmd::Add { from, to, draft } => {
            let mut d = ManifestDraft::load(&draft)?;
            d.add_acl(selectors(&from)?, selectors(&to)?)
                .context("failed to add ACL rule")?;
            d.save(&draft)?;
            println!("added rule {}", d.acl.as_ref().map_or(0, |a| a.len()));
        }
        AclCmd::List { draft } => {
            let d = ManifestDraft::load(&draft)?;
            match &d.acl {
                None => println!("no ACL: every member may reach every member"),
                Some(rules) if rules.is_empty() => {
                    println!("empty ACL: no member may reach any other")
                }
                Some(rules) => {
                    for (i, r) in rules.iter().enumerate() {
                        let join = |v: &[Selector]| {
                            v.iter()
                                .map(|s| s.to_string())
                                .collect::<Vec<_>>()
                                .join(",")
                        };
                        println!("{}. {} <-> {}", i + 1, join(&r.from), join(&r.to));
                    }
                }
            }
        }
        AclCmd::Remove { n, draft } => {
            let mut d = ManifestDraft::load(&draft)?;
            d.remove_acl(n)?;
            d.save(&draft)?;
            if d.acl.as_ref().is_some_and(|a| a.is_empty()) {
                println!(
                    "removed rule {n}; the ACL is now empty, so no member may reach any other"
                );
                println!("(use `net acl clear` to allow everything again)");
            } else {
                println!("removed rule {n}");
            }
        }
        AclCmd::Clear { draft } => {
            let mut d = ManifestDraft::load(&draft)?;
            d.clear_acl();
            d.save(&draft)?;
            println!("ACL cleared: every member may reach every member");
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt::init();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(report) => {
            eprintln!("{report}");
            ExitCode::FAILURE
        }
    }
}

fn runtime() -> Result<tokio::runtime::Runtime, Report> {
    Ok(tokio::runtime::Runtime::new().context("failed to start tokio runtime")?)
}

fn run(cli: Cli) -> Result<(), Report> {
    match cli.command {
        Command::Join {
            network_key,
            card,
            state_dir,
            listen,
            peers,
            no_dht,
        } => match (card, network_key) {
            (Some(slot), _) => card::join(&slot, StateDir(state_dir), listen, peers, !no_dht),
            (None, Some(key)) => join(key, StateDir(state_dir), listen, peers, !no_dht),
            (None, None) => bail!("pass a network key or --card"),
        },
        Command::Enroll {
            piv,
            network_key,
            name,
            peers,
            draft,
            out,
            validity,
            regenerate,
            touch,
            no_manifest,
        } => card::enroll(card::EnrollArgs {
            slot: piv,
            network_key,
            name,
            peers,
            draft,
            out,
            validity,
            regenerate,
            touch,
            with_manifest: !no_manifest,
        }),
        Command::Card(CardCmd::Show { piv }) => card::show(&piv),
        Command::Up { state_dir } => runtime()?.block_on(daemon::run(StateDir(state_dir))),
        Command::Status { state_dir } => {
            let resp =
                runtime()?.block_on(daemon::request(&StateDir(state_dir), Request::Status))?;
            match resp {
                Response::Status(s) => print_status(&s),
                Response::Error(e) => bail!("{e}"),
                other => bail!("unexpected response: {other:?}"),
            }
            Ok(())
        }
        Command::Key(cmd) => key_cmd(cmd),
        Command::Net(cmd) => net_cmd(cmd),
    }
}

#[cfg(feature = "piv")]
fn piv_generate(
    slot: u8,
    serial: Option<u32>,
    touch: &str,
    force: bool,
) -> Result<PublicKey, Report> {
    use backscale::identity::piv;
    let mgm = piv::mgm_from_env()?;
    piv::PivSigner::generate(
        slot,
        serial,
        piv::parse_touch(touch)?,
        mgm.as_deref(),
        force,
    )
}

#[cfg(not(feature = "piv"))]
fn piv_generate(_: u8, _: Option<u32>, _: &str, _: bool) -> Result<PublicKey, Report> {
    bail!("this build has no YubiKey PIV support (build with --features piv)")
}

fn key_cmd(cmd: KeyCmd) -> Result<(), Report> {
    match cmd {
        KeyCmd::Gen { out: Some(out), .. } => {
            let key = SoftSigner::generate();
            key.save(&out)?;
            println!("{}", key.public_key());
        }
        KeyCmd::Gen {
            piv: Some(slot),
            touch,
            force,
            ..
        } => {
            let KeySpec::Piv { slot, serial } = format!("piv:{slot}").parse()? else {
                unreachable!()
            };
            println!("{}", piv_generate(slot, serial, &touch, force)?);
            println!("use it as: piv:{slot:02x}");
        }
        KeyCmd::Gen { .. } => bail!("pass --out or --piv"),
        KeyCmd::Show { key } => {
            println!("{}", key.open()?.public_key());
        }
    }
    Ok(())
}

fn net_cmd(cmd: NetCmd) -> Result<(), Report> {
    match cmd {
        NetCmd::Init {
            network_key,
            name,
            draft,
        } => {
            if draft.exists() {
                bail!("draft {} already exists", draft.display());
            }
            let key = network_key.open()?;
            let d = ManifestDraft::new(key.public_key(), name)?;
            d.save(&draft)?;
            println!("network key: {}", d.network_key);
            println!("net id:      {}", d.net_id());
            println!("ipv4:        {}", d.settings.ipv4_prefix);
            println!("ipv6:        {}", d.settings.ipv6_prefix);
            println!("draft:       {}", draft.display());
        }
        NetCmd::AddMember {
            identity,
            name,
            ipv4,
            ipv6,
            tags,
            draft,
        } => {
            let mut d = ManifestDraft::load(&draft)?;
            let m = d
                .add_member(identity, name, ipv4, ipv6, tags)
                .context("failed to add member")?;
            println!("added {} ({}, {})", m.name, m.ipv4, m.ipv6);
            d.save(&draft)?;
        }
        NetCmd::RemoveMember { who, draft } => {
            let mut d = ManifestDraft::load(&draft)?;
            let m = d.remove_member(&who)?;
            d.save(&draft)?;
            println!("removed {} ({})", m.name, m.identity);
        }
        NetCmd::Tag {
            who,
            add,
            remove,
            draft,
        } => {
            let mut d = ManifestDraft::load(&draft)?;
            let m = d.set_tags(&who, &add, &remove)?;
            println!("{}: [{}]", m.name, m.tags.join(","));
            d.save(&draft)?;
        }
        NetCmd::Acl { cmd } => acl_cmd(cmd)?,
        NetCmd::Sign {
            network_key,
            draft,
            validity,
            out,
        } => {
            let mut d = ManifestDraft::load(&draft)?;
            let key = network_key.open()?;
            let manifest = d.next_manifest(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                validity.as_secs(),
            );
            let signed = manifest.sign(key.as_ref())?;
            let mut f = AtomicWriteFile::open(&out).context("failed to write signed manifest")?;
            f.write_all(&signed.to_bytes())?;
            f.commit()?;
            // Only record the new seq once the manifest is safely written.
            d.save(&draft)?;
            info!(seq = manifest.seq, path = %out.display(), "signed manifest");
            print_manifest(&manifest);
        }
        NetCmd::Publish { file, state_dir } => {
            let bytes = std::fs::read(&file)
                .context("failed to read manifest")
                .attach(format!("path: {}", file.display()))?;
            let signed = SignedManifest::from_bytes(&bytes)?;
            let resp = runtime()?.block_on(daemon::request(
                &StateDir(state_dir),
                Request::Publish(signed),
            ))?;
            match resp {
                Response::Published(seq) => println!("published manifest seq {seq}"),
                Response::Error(e) => bail!("daemon rejected manifest: {e}"),
                other => bail!("unexpected response: {other:?}"),
            }
        }
        NetCmd::Show { file, pin } => {
            let bytes = std::fs::read(&file)
                .context("failed to read manifest")
                .attach(format!("path: {}", file.display()))?;
            let signed = SignedManifest::from_bytes(&bytes)?;
            let (key, pinned) = match pin {
                Some(k) => (k, true),
                None => (signed.decode_unverified()?.network_key, false),
            };
            let m = signed.verify(
                &key,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )?;
            if pinned {
                println!("signature: valid (pinned network key)");
            } else {
                println!("signature: valid, but NOT checked against a pinned key (use --pin)");
            }
            print_manifest(&m);
        }
    }
    Ok(())
}

fn join(
    network_key: PublicKey,
    dir: StateDir,
    listen: SocketAddr,
    peers: Vec<SocketAddr>,
    dht: bool,
) -> Result<(), Report> {
    if dir.config().exists() {
        bail!("{} already exists", dir.config().display());
    }
    std::fs::create_dir_all(&dir.0)
        .context("failed to create state directory")
        .attach(format!("path: {}", dir.0.display()))?;
    let key_path = dir.identity_key();
    let key = if key_path.exists() {
        SoftSigner::load(&key_path)?
    } else {
        let k = SoftSigner::generate();
        k.save(&key_path)?;
        k
    };
    let config = Config {
        network_key,
        identity: format!("soft:{}", key_path.display()),
        listen,
        peers,
        dht,
        lan_discovery: true,
        tun: true,
        tun_name: "backscale0".into(),
    };
    config.save(&dir.config())?;
    println!("identity: {}", key.public_key());
    println!("ask the network admin to run:");
    println!(
        "  backscale net add-member {} --name <name>",
        key.public_key()
    );
    Ok(())
}

fn print_status(s: &Status) {
    println!(
        "identity: {} ({})",
        s.identity,
        s.name.as_deref().unwrap_or("not a member")
    );
    println!("net id:   {}", s.net_id);
    let expires = s
        .manifest_expires
        .map(|t| humantime::format_rfc3339_seconds(UNIX_EPOCH + Duration::from_secs(t)).to_string())
        .unwrap_or_else(|| "-".into());
    println!(
        "manifest: seq {} ({} members, expires {expires})",
        s.manifest_seq, s.members
    );
    match s.acl_rules {
        None => println!("acl:      none (every member may reach every member)"),
        Some(n) => println!("acl:      {n} rules"),
    }
    println!("listen:   {}", s.listen);
    match (&s.overlay, &s.tun) {
        (Some((v4, v6)), Some(dev)) => println!("overlay:  {v4} {v6} on {dev}"),
        (Some((v4, v6)), None) => println!("overlay:  {v4} {v6} (no TUN device)"),
        _ => {}
    }
    if let Some(n) = s.dht_nodes {
        println!("dht:      {n} nodes, external ip {:?}", s.external_ip);
    }
    println!("peers:    {}", s.peers.len());
    for p in &s.peers {
        let overlay = p.overlay.map(|ip| ip.to_string()).unwrap_or_default();
        let wg = match &p.wg {
            _ if p.blocked => "blocked by ACL".into(),
            Some(w) => format!(
                "wg {} handshake {} tx {} rx {}",
                w.endpoint,
                w.handshake_secs_ago
                    .map_or("never".into(), |s| format!("{s}s ago")),
                w.tx_bytes,
                w.rx_bytes
            ),
            None => "wg -".into(),
        };
        println!("  {:<12} {:<15} {:<22} {wg}", p.name, overlay, p.addr);
    }
}

fn print_manifest(m: &NetworkManifest) {
    println!("network:  {} ({})", m.name, m.network_key);
    println!("net id:   {}", m.net_id);
    println!("seq:      {}", m.seq);
    println!(
        "issued:   {}",
        humantime::format_rfc3339_seconds(UNIX_EPOCH + Duration::from_secs(m.issued_at))
    );
    println!(
        "expires:  {}",
        humantime::format_rfc3339_seconds(UNIX_EPOCH + Duration::from_secs(m.expires_at))
    );
    println!(
        "prefixes: {} {}",
        m.settings.ipv4_prefix, m.settings.ipv6_prefix
    );
    match &m.acl {
        None => println!("acl:      none (every member may reach every member)"),
        Some(rules) => {
            println!("acl:      {} rules", rules.len());
            for (i, r) in rules.iter().enumerate() {
                println!("  {}. {r}", i + 1);
            }
        }
    }
    println!("members:  {}", m.members.len());
    for mem in &m.members {
        let tags = if mem.tags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", mem.tags.join(","))
        };
        println!(
            "  {:<16} {:<15} {:<39} {}{}",
            mem.name,
            mem.ipv4,
            mem.ipv6,
            mem.identity.fingerprint(),
            tags
        );
    }
}
