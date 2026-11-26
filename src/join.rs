// `backscale join --invite`: find the network's manager, ask it to admit us
// and wait on that control session until a manifest listing us arrives.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rootcause::prelude::*;
use tokio::sync::{broadcast, mpsc};
use tracing::debug;

use crate::config::{Config, StateDir};
use crate::control::{ControlConfig, ControlEvent, ControlNode, EnrollAs};
use crate::daemon::load_or_create_keys;
use crate::identity::KeySpec;
use crate::identity::soft::SoftSigner;
use crate::invite::InviteCode;
use crate::manager::EnrollState;
use crate::manifest::Member;
use crate::net::lan::{self, LanRole};
use crate::net::socket::UdpMux;
use crate::net::{TOPIC_PERIOD_SECS, manager_topic};
use backscale_dht::{Dht, DhtConfig};
use backscale_utp::{UtpConfig, UtpSocket};

const RETRY: Duration = Duration::from_secs(15);

pub struct JoinArgs {
    pub invite: InviteCode,
    pub name: Option<String>,
    // A key spec; None creates a software key in the state directory.
    pub identity: Option<String>,
    pub dir: StateDir,
    pub listen: SocketAddr,
    pub peers: Vec<SocketAddr>,
    pub dht: bool,
    pub lan: bool,
    pub wait: Duration,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub async fn join(a: JoinArgs) -> Result<Member, Report> {
    if a.dir.config().exists() {
        bail!("{} already exists", a.dir.config().display());
    }
    std::fs::create_dir_all(&a.dir.0)
        .context("failed to create state directory")
        .attach(format!("path: {}", a.dir.0.display()))?;
    let spec = match &a.identity {
        Some(s) => s.clone(),
        None => {
            let path = a.dir.identity_key();
            if !path.exists() {
                SoftSigner::generate().save(&path)?;
            }
            format!("soft:{}", path.display())
        }
    };
    let signer = spec
        .parse::<KeySpec>()?
        .open()
        .context("failed to open identity key")?;
    let identity = signer.public_key();
    println!("identity: {identity}");
    println!("fingerprint: {}", identity.fingerprint());

    let mux = UdpMux::bind(a.listen).await?;
    let local = mux.local_addr;
    let utp = Arc::new(UtpSocket::new(mux.utp, UtpConfig::default()));
    let control = ControlNode::new(
        ControlConfig {
            network_key: a.invite.network_key.clone(),
            manifest_path: Some(a.dir.manifest()),
            manager: None,
            enroll: Some(EnrollAs {
                invite: a.invite.clone(),
                name: a.name.clone(),
            }),
        },
        signer.as_ref(),
        load_or_create_keys(&a.dir)?,
        utp,
    )?;
    let mut events = control.subscribe();
    control.start();
    let dht = a
        .dht
        .then(|| Arc::new(Dht::new(DhtConfig::default(), mux.dht)));
    let _tasks = mux.tasks;
    let net_id = a.invite.net_id();

    let (found_tx, mut found) = mpsc::channel::<SocketAddr>(64);
    if a.lan {
        tokio::spawn(lan::run(
            net_id,
            local.port(),
            LanRole::find_manager(),
            found_tx.clone(),
        ));
    }
    if let Some(dht) = dht.clone() {
        let found_tx = found_tx.clone();
        tokio::spawn(async move {
            loop {
                match dht.bootstrap().await {
                    Ok(_) => {
                        let now = unix_now();
                        for t in [now, now.saturating_sub(TOPIC_PERIOD_SECS)] {
                            for p in dht.get_peers(manager_topic(&net_id, t)).await {
                                let _ = found_tx.send(p).await;
                            }
                        }
                    }
                    Err(e) => debug!(error = %e, "DHT bootstrap failed"),
                }
                tokio::time::sleep(RETRY).await;
            }
        });
    }

    let candidates: Arc<Mutex<HashSet<SocketAddr>>> = Arc::default();
    candidates.lock().unwrap().extend(&a.peers);
    let dial = |addr: SocketAddr| {
        if addr == local || control.is_self(addr) || control.is_connected_to(addr) {
            return;
        }
        let control = control.clone();
        tokio::spawn(async move {
            if let Err(e) = control.connect(addr).await {
                debug!(%addr, error = %e, "connect failed");
            }
        });
    };
    println!("looking for the network manager...");
    let deadline = tokio::time::sleep(a.wait);
    tokio::pin!(deadline);
    let mut retry = tokio::time::interval(RETRY);
    let mut manager: Option<SocketAddr> = None;
    loop {
        tokio::select! {
            _ = &mut deadline => bail!("gave up waiting after {}", humantime::format_duration(a.wait)),
            _ = retry.tick() => {
                let all: Vec<_> = candidates.lock().unwrap().iter().copied().collect();
                match manager {
                    Some(m) => dial(m),
                    None => all.into_iter().for_each(&dial),
                }
            }
            Some(addr) = found.recv() => {
                if candidates.lock().unwrap().insert(addr) && manager.is_none() {
                    dial(addr);
                }
            }
            ev = events.recv() => match ev {
                Ok(ControlEvent::Enrollment { manager: at, state }) => match state {
                    EnrollState::Pending => {
                        if manager.is_none() {
                            println!("reached the manager at {at}; waiting for approval");
                        }
                        manager = Some(at);
                    }
                    EnrollState::Denied(why) => bail!("enrollment denied: {why}"),
                },
                Ok(ControlEvent::ManifestUpdated { .. }) | Err(broadcast::error::RecvError::Lagged(_)) => {
                    if let Some(m) = control.manifest()
                        && let Some(me) = m.member(&identity)
                    {
                        let me = me.clone();
                        let mut peers: Vec<SocketAddr> = manager.into_iter().collect();
                        for p in &a.peers {
                            if !peers.contains(p) {
                                peers.push(*p);
                            }
                        }
                        let config = Config {
                            network_key: a.invite.network_key.clone(),
                            identity: spec,
                            listen: a.listen,
                            peers,
                            dht: a.dht,
                            lan_discovery: a.lan,
                            tun: true,
                            tun_name: "backscale0".into(),
                        };
                        config.save(&a.dir.config())?;
                        return Ok(me);
                    }
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Closed) => bail!("control plane stopped"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::tests::{invite, network, now, until};
    use crate::identity::Signer;

    fn args(dir: &std::path::Path, code: InviteCode, at: SocketAddr) -> JoinArgs {
        JoinArgs {
            invite: code,
            name: Some("newbie".into()),
            identity: None,
            dir: StateDir(dir.to_path_buf()),
            listen: "127.0.0.1:0".parse().unwrap(),
            peers: vec![at],
            dht: false,
            lan: false,
            wait: Duration::from_secs(20),
        }
    }

    #[tokio::test]
    async fn join_waits_for_approval_then_writes_config() {
        let mut net = network().await;
        let code = InviteCode::generate(net.key.public_key());
        invite(&net, &code);
        let dir = tempfile::tempdir().unwrap();
        let joining = tokio::spawn(join(args(dir.path(), code, net.manager.addr)));

        until("the request", || !net.mgr.pending(now()).is_empty()).await;
        let p = net.mgr.pending(now()).remove(0);
        assert_eq!(p.name.as_deref(), Some("newbie"));
        assert!(!dir.path().join("config.toml").exists());
        net.draft
            .add_member(p.identity.clone(), "newbie".into(), None, None, vec![])
            .unwrap();
        net.publish();

        let me = joining.await.unwrap().unwrap();
        assert_eq!(me.identity, p.identity);
        let config = Config::load(&StateDir(dir.path().into()).config()).unwrap();
        assert_eq!(config.network_key, net.key.public_key());
        assert_eq!(config.peers, vec![net.manager.addr]);
        let signer = config.identity.parse::<KeySpec>().unwrap().open().unwrap();
        assert_eq!(signer.public_key(), p.identity);
        assert!(StateDir(dir.path().into()).manifest().exists());
    }

    #[tokio::test]
    async fn join_reports_denial() {
        let net = network().await;
        let code = InviteCode::generate(net.key.public_key());
        invite(&net, &code);
        let dir = tempfile::tempdir().unwrap();
        let joining = tokio::spawn(join(args(dir.path(), code, net.manager.addr)));
        until("the request", || !net.mgr.pending(now()).is_empty()).await;
        let req = net.mgr.pending(now())[0].req_id;
        let (who, session, psk) = net.mgr.deny(req, "nope".into()).unwrap();
        net.manager
            .control
            .deny_enrollment(session, &who, &psk, "nope".into());
        let err = joining.await.unwrap().unwrap_err();
        assert!(err.to_string().contains("nope"), "{err}");
        assert!(!dir.path().join("config.toml").exists());
    }
}
