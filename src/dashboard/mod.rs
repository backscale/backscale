// `backscale dashboard`: a loopback-only web UI for watching and configuring
// the network. It talks to the local daemon over its control socket and is
// the only place manifests get signed.

pub mod actions;
pub mod auth;
pub mod html;
pub mod server;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rootcause::prelude::*;
use tokio::net::TcpListener;

use self::actions::{Actions, Socket};
use self::auth::Auth;
use self::server::App;
use crate::config::StateDir;
use crate::identity::Signer;
use crate::manifest::ManifestDraft;

const AUTO_APPROVE_EVERY: Duration = Duration::from_secs(2);

pub struct DashboardArgs {
    pub signer: Arc<dyn Signer>,
    pub draft: PathBuf,
    pub listen: SocketAddr,
    pub state_dir: StateDir,
    pub validity: Duration,
}

pub async fn run(a: DashboardArgs) -> Result<(), Report> {
    server::local_only(a.listen)?;
    let draft = ManifestDraft::load(&a.draft)?;
    if draft.network_key != a.signer.public_key() {
        bail!(
            "{} belongs to network key {}, not {}",
            a.draft.display(),
            draft.network_key,
            a.signer.public_key()
        );
    }
    let actions = Actions::new(Socket(a.state_dir), a.signer, a.draft, a.validity);
    let status = actions.status().await?;
    if status.net_id != draft.net_id().to_string() {
        bail!(
            "the local daemon is in network {}, the draft is for {}",
            status.net_id,
            draft.net_id()
        );
    }
    let listener = TcpListener::bind(a.listen)
        .await
        .context("failed to bind the dashboard")
        .attach(format!("address: {}", a.listen))?;
    let addr = listener.local_addr()?;
    let app = Arc::new(App {
        actions,
        auth: Auth::new(addr.port()),
    });
    // Printed, never logged: the token is the only way in.
    println!("dashboard: http://{addr}/");
    println!("token:     {}", app.auth.token_hex());
    println!("(valid until this process exits)");

    let auto = app.clone();
    tokio::spawn(async move {
        let mut failed = HashSet::new();
        let mut tick = tokio::time::interval(AUTO_APPROVE_EVERY);
        loop {
            tick.tick().await;
            auto.actions.auto_approve(&mut failed).await;
        }
    });
    tokio::select! {
        _ = server::serve(listener, app) => Ok(()),
        r = tokio::signal::ctrl_c() => r.context("failed to wait for ctrl-c").map_err(Into::into),
    }
}

#[cfg(test)]
mod tests;
