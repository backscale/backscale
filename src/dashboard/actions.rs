// What the dashboard can do, independent of HTTP. Draft edits and signing
// happen here, in this process; the daemon only stores invites and spreads
// signed manifests.

use std::collections::HashSet;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rootcause::prelude::*;
use tracing::{info, warn};

use crate::config::StateDir;
use crate::daemon::{self, Request, Response, Status};
use crate::identity::Signer;
use crate::invite::{InviteCode, InviteId};
use crate::manager::{Invite, InviteInfo, Pending};
use crate::manifest::{ManifestDraft, NetworkManifest, valid_name};

pub trait DaemonLink: Send + Sync + 'static {
    fn request(&self, req: Request) -> impl Future<Output = Result<Response, Report>> + Send;
}

pub struct Socket(pub StateDir);

impl DaemonLink for Socket {
    fn request(&self, req: Request) -> impl Future<Output = Result<Response, Report>> + Send {
        daemon::request(&self.0, req)
    }
}

pub struct NewInvite {
    pub name: Option<String>,
    pub tags: Vec<String>,
    pub ttl: Duration,
    pub uses: u32,
    pub auto_approve: bool,
}

pub struct Actions<D> {
    link: D,
    signer: Arc<dyn Signer>,
    draft_path: PathBuf,
    validity: Duration,
    // Serialises draft edits and signing.
    lock: tokio::sync::Mutex<()>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn unexpected(r: Response) -> Report {
    report!("unexpected daemon response: {r:?}")
}

// A free name for `wanted`: itself, or with a numeric suffix.
fn free_name(draft: &ManifestDraft, wanted: &str) -> Option<String> {
    let taken = |n: &str| draft.members.iter().any(|m| m.name == n);
    if !taken(wanted) {
        return Some(wanted.to_string());
    }
    (2..100)
        .map(|i| format!("{}-{i}", wanted.trim_end_matches('-')))
        .find(|n| valid_name(n) && !taken(n))
}

impl<D: DaemonLink> Actions<D> {
    pub fn new(link: D, signer: Arc<dyn Signer>, draft_path: PathBuf, validity: Duration) -> Self {
        Actions {
            link,
            signer,
            draft_path,
            validity,
            lock: tokio::sync::Mutex::new(()),
        }
    }

    async fn call(&self, req: Request) -> Result<Response, Report> {
        match self.link.request(req).await? {
            Response::Error(e) => bail!("daemon: {e}"),
            r => Ok(r),
        }
    }

    pub fn draft(&self) -> Result<ManifestDraft, Report> {
        ManifestDraft::load(&self.draft_path)
    }

    pub async fn status(&self) -> Result<Status, Report> {
        match self.call(Request::Status).await? {
            Response::Status(s) => Ok(*s),
            r => Err(unexpected(r)),
        }
    }

    pub async fn published(&self) -> Result<Option<NetworkManifest>, Report> {
        match self.call(Request::Manifest).await? {
            Response::Manifest(None) => Ok(None),
            Response::Manifest(Some(signed)) => Ok(Some(
                signed
                    .verify(&self.signer.public_key(), now())
                    .map_err(|e| e.into_dynamic())?,
            )),
            r => Err(unexpected(r)),
        }
    }

    // Edits the draft without publishing.
    pub async fn edit(
        &self,
        f: impl FnOnce(&mut ManifestDraft) -> Result<(), Report>,
    ) -> Result<(), Report> {
        let _guard = self.lock.lock().await;
        let mut d = self.draft()?;
        f(&mut d)?;
        d.save(&self.draft_path)
    }

    pub async fn publish(&self) -> Result<u64, Report> {
        self.publish_with(|_| Ok(())).await
    }

    // Applies `f` to the draft, signs and publishes the result, and only then
    // saves the draft: a failed signature or publish leaves it untouched.
    async fn publish_with(
        &self,
        f: impl FnOnce(&mut ManifestDraft) -> Result<(), Report> + Send,
    ) -> Result<u64, Report> {
        let _guard = self.lock.lock().await;
        let mut d = self.draft()?;
        f(&mut d)?;
        let manifest = d.next_manifest(now(), self.validity.as_secs());
        let signer = self.signer.clone();
        info!(seq = manifest.seq, "signing manifest");
        let signed = tokio::task::spawn_blocking(move || manifest.sign(signer.as_ref()))
            .await
            .context("signing task failed")??;
        match self.call(Request::Publish(signed)).await? {
            Response::Published(seq) => {
                d.save(&self.draft_path)?;
                info!(seq, "published manifest");
                Ok(seq)
            }
            r => Err(unexpected(r)),
        }
    }

    pub async fn create_invite(&self, n: NewInvite) -> Result<InviteCode, Report> {
        if let Some(name) = &n.name
            && !valid_name(name)
        {
            bail!("invalid member name `{name}`");
        }
        if let Some(t) = n.tags.iter().find(|t| !valid_name(t)) {
            bail!("invalid tag `{t}`");
        }
        if n.uses == 0 {
            bail!("an invite needs at least one use");
        }
        let code = InviteCode::generate(self.signer.public_key());
        let now = now();
        let invite = Invite {
            id: code.id(),
            psk: code.psk(),
            name: n.name,
            tags: n.tags,
            expires_at: now + n.ttl.as_secs(),
            uses_left: n.uses,
            auto_approve: n.auto_approve,
            created_at: now,
        };
        match self.call(Request::AddInvite(invite)).await? {
            Response::Ok => Ok(code),
            r => Err(unexpected(r)),
        }
    }

    pub async fn invites(&self) -> Result<Vec<InviteInfo>, Report> {
        match self.call(Request::ListInvites).await? {
            Response::Invites(v) => Ok(v),
            r => Err(unexpected(r)),
        }
    }

    pub async fn revoke(&self, id: InviteId) -> Result<(), Report> {
        match self.call(Request::RevokeInvite(id)).await? {
            Response::Ok => Ok(()),
            r => Err(unexpected(r)),
        }
    }

    pub async fn enrollments(&self) -> Result<Vec<Pending>, Report> {
        match self.call(Request::Enrollments).await? {
            Response::Enrollments(v) => Ok(v),
            r => Err(unexpected(r)),
        }
    }

    // Admits a pending node: adds it to the draft, then signs and publishes.
    // Name and tags default to the invite's, then to what the node proposed.
    pub async fn approve(
        &self,
        req_id: u64,
        name: Option<String>,
        tags: Option<Vec<String>>,
    ) -> Result<String, Report> {
        let p = self
            .enrollments()
            .await?
            .into_iter()
            .find(|p| p.req_id == req_id)
            .ok_or_else(|| report!("no such enrollment request"))?;
        let wanted = name
            .filter(|n| !n.is_empty())
            .or(p.invite.name.clone())
            .or(p.name.clone())
            .unwrap_or_else(|| format!("node-{}", &p.identity.fingerprint()[..8]));
        let tags = tags.unwrap_or(p.invite.tags.clone());
        let mut chosen = String::new();
        self.publish_with(|d| {
            if d.members.iter().any(|m| m.identity == p.identity) {
                bail!("this node is already a member of the draft");
            }
            chosen = free_name(d, &wanted).ok_or_else(|| report!("no free name for `{wanted}`"))?;
            d.add_member(p.identity.clone(), chosen.clone(), None, None, tags)?;
            Ok(())
        })
        .await?;
        Ok(chosen)
    }

    pub async fn deny(&self, req_id: u64, reason: String) -> Result<(), Report> {
        match self.call(Request::Deny { req_id, reason }).await? {
            Response::Ok => Ok(()),
            r => Err(unexpected(r)),
        }
    }

    // Approves the pending requests whose invite says so. Requests that
    // failed once are left for the admin.
    pub async fn auto_approve(&self, failed: &mut HashSet<u64>) {
        let pending = match self.enrollments().await {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "failed to list enrollments");
                return;
            }
        };
        for p in pending {
            if !p.invite.auto_approve || failed.contains(&p.req_id) {
                continue;
            }
            match self.approve(p.req_id, None, None).await {
                Ok(name) => {
                    info!(%name, peer = %p.identity.fingerprint(), "auto-approved enrollment");
                }
                Err(e) => {
                    warn!(req_id = p.req_id, error = %e, "auto-approval failed; left for the admin");
                    failed.insert(p.req_id);
                }
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::identity::soft::SoftSigner;
    use crate::manager::Manager;
    use crate::manifest::SignedManifest;
    use std::sync::Mutex;

    // A daemon stand-in: a real Manager plus a published-manifest slot.
    pub(crate) struct Fake {
        pub mgr: Manager,
        pub published: Mutex<Option<SignedManifest>>,
        pub refuse_publish: std::sync::atomic::AtomicBool,
    }

    impl DaemonLink for Arc<Fake> {
        fn request(&self, req: Request) -> impl Future<Output = Result<Response, Report>> + Send {
            let me = self.clone();
            async move {
                let now = now();
                Ok(match req {
                    Request::Publish(s) => {
                        if me.refuse_publish.load(std::sync::atomic::Ordering::Relaxed) {
                            return Ok(Response::Error("nope".into()));
                        }
                        let m = s.decode_unverified().unwrap();
                        me.mgr.manifest_adopted(&m);
                        *me.published.lock().unwrap() = Some(s);
                        Response::Published(m.seq)
                    }
                    Request::Manifest => Response::Manifest(me.published.lock().unwrap().clone()),
                    Request::AddInvite(i) => {
                        me.mgr.add_invite(i)?;
                        Response::Ok
                    }
                    Request::ListInvites => Response::Invites(me.mgr.invites(now)),
                    Request::Enrollments => Response::Enrollments(me.mgr.pending(now)),
                    Request::Deny { req_id, reason } => {
                        me.mgr.deny(req_id, reason)?;
                        Response::Ok
                    }
                    _ => Response::Error("unsupported".into()),
                })
            }
        }
    }

    pub(crate) fn setup() -> (Arc<Fake>, Actions<Arc<Fake>>, tempfile::TempDir) {
        let key = SoftSigner::generate();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.toml");
        ManifestDraft::new(key.public_key(), "net".into())
            .unwrap()
            .save(&path)
            .unwrap();
        let fake = Arc::new(Fake {
            mgr: Manager::load(None).unwrap(),
            published: Mutex::new(None),
            refuse_publish: Default::default(),
        });
        let actions = Actions::new(fake.clone(), Arc::new(key), path, Duration::from_secs(3600));
        (fake, actions, dir)
    }

    // Makes a node ask to enroll with `code`.
    pub(crate) fn ask(
        fake: &Fake,
        code: &InviteCode,
        name: Option<&str>,
    ) -> crate::identity::PublicKey {
        let who = SoftSigner::generate().public_key();
        let h = [3; 32];
        let mac = crate::invite::request_mac(&code.psk(), &h, &who);
        fake.mgr
            .request(
                &code.id(),
                &mac,
                &h,
                &who,
                name.map(Into::into),
                "192.0.2.1:1".parse().unwrap(),
                1,
                now(),
            )
            .unwrap();
        who
    }

    fn invite(auto: bool, name: Option<&str>, uses: u32) -> NewInvite {
        NewInvite {
            name: name.map(Into::into),
            tags: vec!["laptop".into()],
            ttl: Duration::from_secs(600),
            uses,
            auto_approve: auto,
        }
    }

    #[tokio::test]
    async fn approve_adds_signs_and_publishes() {
        let (fake, a, _dir) = setup();
        let code = a.create_invite(invite(false, None, 1)).await.unwrap();
        let who = ask(&fake, &code, Some("box"));
        let req = a.enrollments().await.unwrap()[0].req_id;
        assert_eq!(a.approve(req, None, None).await.unwrap(), "box");
        let m = a.published().await.unwrap().unwrap();
        let member = m.member(&who).unwrap();
        assert_eq!(member.tags, vec!["laptop".to_string()]);
        assert_eq!(a.draft().unwrap().last_seq, 1);
        assert!(a.enrollments().await.unwrap().is_empty());
        assert!(a.invites().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn failed_publish_leaves_the_draft_alone() {
        let (fake, a, _dir) = setup();
        let code = a.create_invite(invite(false, None, 1)).await.unwrap();
        ask(&fake, &code, Some("box"));
        let req = a.enrollments().await.unwrap()[0].req_id;
        fake.refuse_publish
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(a.approve(req, None, None).await.is_err());
        let d = a.draft().unwrap();
        assert_eq!(d.last_seq, 0);
        assert!(d.members.is_empty());
    }

    #[tokio::test]
    async fn auto_approve_uses_the_preset_name_and_dedupes() {
        let (fake, a, _dir) = setup();
        let auto = a
            .create_invite(invite(true, Some("kiosk"), 2))
            .await
            .unwrap();
        let manual = a.create_invite(invite(false, None, 1)).await.unwrap();
        let k1 = ask(&fake, &auto, Some("ignored"));
        let k2 = ask(&fake, &auto, None);
        let m = ask(&fake, &manual, Some("manual"));
        let mut failed = HashSet::new();
        a.auto_approve(&mut failed).await;
        assert!(failed.is_empty());
        let pm = a.published().await.unwrap().unwrap();
        let mut names = vec![
            pm.member(&k1).unwrap().name.clone(),
            pm.member(&k2).unwrap().name.clone(),
        ];
        names.sort();
        assert_eq!(names, vec!["kiosk", "kiosk-2"]);
        assert!(pm.member(&m).is_none());
        assert_eq!(a.enrollments().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn invites_are_validated() {
        let (_fake, a, _dir) = setup();
        assert!(
            a.create_invite(invite(false, Some("Bad Name"), 1))
                .await
                .is_err()
        );
        assert!(a.create_invite(invite(false, None, 0)).await.is_err());
        let mut bad_tag = invite(false, None, 1);
        bad_tag.tags = vec!["<x>".into()];
        assert!(a.create_invite(bad_tag).await.is_err());
    }
}
