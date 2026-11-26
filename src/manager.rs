// The network manager's bookkeeping: live invites (persisted) and the nodes
// currently asking to enroll with one (in memory). Signing happens elsewhere,
// in `backscale dashboard`; approving a node means publishing a manifest that
// lists it.

use atomic_write_file::AtomicWriteFile;
use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Mutex;

use rootcause::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::identity::PublicKey;
use crate::invite::{self, InviteId};
use crate::manifest::{NetworkManifest, valid_name};

pub const MAX_PENDING: usize = 64;
pub const MAX_PENDING_PER_INVITE: usize = 4;
pub const MAX_INVITES: usize = 256;

#[derive(Clone, Serialize, Deserialize)]
pub struct Invite {
    pub id: InviteId,
    pub psk: [u8; 32],
    pub name: Option<String>,
    pub tags: Vec<String>,
    pub expires_at: u64,
    pub uses_left: u32,
    pub auto_approve: bool,
    pub created_at: u64,
}

impl Invite {
    fn live(&self, now: u64) -> bool {
        self.uses_left > 0 && now < self.expires_at
    }

    pub fn info(&self) -> InviteInfo {
        InviteInfo {
            id: self.id,
            name: self.name.clone(),
            tags: self.tags.clone(),
            expires_at: self.expires_at,
            uses_left: self.uses_left,
            auto_approve: self.auto_approve,
            created_at: self.created_at,
        }
    }
}

// An invite without its secret, for listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteInfo {
    pub id: InviteId,
    pub name: Option<String>,
    pub tags: Vec<String>,
    pub expires_at: u64,
    pub uses_left: u32,
    pub auto_approve: bool,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pending {
    pub req_id: u64,
    pub invite: InviteInfo,
    pub identity: PublicKey,
    pub name: Option<String>,
    pub addr: SocketAddr,
    pub first_seen: u64,
    pub last_seen: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrollState {
    Pending,
    Denied(String),
}

pub struct Accepted {
    pub psk: [u8; 32],
    pub state: EnrollState,
    // Requests from this session may be kept open until then.
    pub until: u64,
}

struct Request {
    pending: Pending,
    session: u64,
}

#[derive(Default)]
struct State {
    invites: Vec<Invite>,
    requests: HashMap<PublicKey, Request>,
    denied: HashMap<PublicKey, String>,
    next_req: u64,
}

pub struct Manager {
    path: Option<PathBuf>,
    state: Mutex<State>,
}

impl std::fmt::Debug for Manager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Manager")
    }
}

impl Manager {
    pub fn load(path: Option<PathBuf>) -> Result<Self, Report> {
        let mut state = State {
            next_req: 1,
            ..State::default()
        };
        if let Some(p) = &path
            && p.exists()
        {
            let bytes = std::fs::read(p)
                .context("failed to read invites")
                .attach(format!("path: {}", p.display()))?;
            state.invites = postcard::from_bytes(&bytes).context("malformed invites file")?;
        }
        Ok(Manager {
            path,
            state: Mutex::new(state),
        })
    }

    fn save(&self, invites: &[Invite]) {
        let Some(path) = &self.path else { return };
        let write = || -> std::io::Result<()> {
            let mut f = AtomicWriteFile::options().open(path)?;
            use std::os::unix::fs::PermissionsExt;
            f.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
            f.write_all(&postcard::to_stdvec(invites).expect("invites always encode"))?;
            f.commit()
        };
        if let Err(e) = write() {
            warn!(error = %e, "failed to save invites");
        }
    }

    pub fn has_live_invites(&self, now: u64) -> bool {
        self.state
            .lock()
            .unwrap()
            .invites
            .iter()
            .any(|i| i.live(now))
    }

    pub fn add_invite(&self, invite: Invite) -> Result<(), Report> {
        if let Some(n) = &invite.name
            && !valid_name(n)
        {
            bail!("invalid member name `{n}`");
        }
        if let Some(t) = invite.tags.iter().find(|t| !valid_name(t)) {
            bail!("invalid tag `{t}`");
        }
        let mut st = self.state.lock().unwrap();
        if st.invites.iter().any(|i| i.id == invite.id) {
            bail!("invite already exists");
        }
        if st.invites.len() >= MAX_INVITES {
            bail!("too many invites");
        }
        st.invites.push(invite);
        self.save(&st.invites);
        Ok(())
    }

    pub fn invites(&self, now: u64) -> Vec<InviteInfo> {
        let mut st = self.state.lock().unwrap();
        self.prune(&mut st, now);
        st.invites.iter().map(Invite::info).collect()
    }

    // Returns the sessions of requests made with the invite, to be closed.
    pub fn revoke_invite(&self, id: &InviteId) -> Result<Vec<u64>, Report> {
        let mut st = self.state.lock().unwrap();
        let before = st.invites.len();
        st.invites.retain(|i| &i.id != id);
        if st.invites.len() == before {
            bail!("no such invite");
        }
        self.save(&st.invites);
        let mut sessions = vec![];
        st.requests.retain(|_, r| {
            let keep = &r.pending.invite.id != id;
            if !keep {
                sessions.push(r.session);
            }
            keep
        });
        Ok(sessions)
    }

    fn prune(&self, st: &mut State, now: u64) {
        let before = st.invites.len();
        st.invites.retain(|i| i.live(now));
        if st.invites.len() != before {
            self.save(&st.invites);
        }
        let live: Vec<InviteId> = st.invites.iter().map(|i| i.id).collect();
        st.requests
            .retain(|_, r| live.contains(&r.pending.invite.id));
    }

    pub fn pending(&self, now: u64) -> Vec<Pending> {
        let mut st = self.state.lock().unwrap();
        self.prune(&mut st, now);
        let mut v: Vec<Pending> = st.requests.values().map(|r| r.pending.clone()).collect();
        v.sort_by_key(|p| p.req_id);
        v
    }

    // A node asks to enroll over control session `session`, whose Noise
    // handshake hash is `handshake`. None means the request is not
    // authentic (unknown invite or bad MAC) and gets no answer.
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        &self,
        invite_id: &InviteId,
        mac: &[u8; 32],
        handshake: &[u8; 32],
        identity: &PublicKey,
        name: Option<String>,
        addr: SocketAddr,
        session: u64,
        now: u64,
    ) -> Option<Accepted> {
        let mut st = self.state.lock().unwrap();
        self.prune(&mut st, now);
        let invite = st.invites.iter().find(|i| &i.id == invite_id)?.clone();
        if !invite::mac_eq(mac, &invite::request_mac(&invite.psk, handshake, identity)) {
            warn!(%addr, "enrollment request with a bad invite MAC");
            return None;
        }
        let accepted = |state| Accepted {
            psk: invite.psk,
            state,
            until: invite.expires_at,
        };
        if let Some(why) = st.denied.get(identity) {
            return Some(accepted(EnrollState::Denied(why.clone())));
        }
        let name = name.filter(|n| valid_name(n));
        if let Some(r) = st.requests.get_mut(identity) {
            if r.pending.invite.id != invite.id {
                return Some(accepted(EnrollState::Denied(
                    "already enrolling with another invite".into(),
                )));
            }
            r.session = session;
            r.pending.addr = addr;
            r.pending.name = name;
            r.pending.last_seen = now;
            return Some(accepted(EnrollState::Pending));
        }
        let for_invite = st
            .requests
            .values()
            .filter(|r| r.pending.invite.id == invite.id)
            .count();
        if st.requests.len() >= MAX_PENDING || for_invite >= MAX_PENDING_PER_INVITE {
            return Some(accepted(EnrollState::Denied(
                "too many pending enrollments, try again later".into(),
            )));
        }
        let req_id = st.next_req;
        st.next_req += 1;
        info!(req_id, peer = %identity.fingerprint(), %addr, "enrollment request");
        st.requests.insert(
            identity.clone(),
            Request {
                pending: Pending {
                    req_id,
                    invite: invite.info(),
                    identity: identity.clone(),
                    name,
                    addr,
                    first_seen: now,
                    last_seen: now,
                },
                session,
            },
        );
        Some(accepted(EnrollState::Pending))
    }

    // Returns the request's session and the invite's PSK, so the node can be
    // told.
    pub fn deny(&self, req_id: u64, reason: String) -> Result<(PublicKey, u64, [u8; 32]), Report> {
        let mut st = self.state.lock().unwrap();
        let identity = st
            .requests
            .iter()
            .find(|(_, r)| r.pending.req_id == req_id)
            .map(|(k, _)| k.clone())
            .ok_or_else(|| report!("no such enrollment request"))?;
        let r = st.requests.remove(&identity).unwrap();
        let psk = st
            .invites
            .iter()
            .find(|i| i.id == r.pending.invite.id)
            .map(|i| i.psk)
            .ok_or_else(|| report!("the request's invite is gone"))?;
        info!(req_id, peer = %identity.fingerprint(), "enrollment denied");
        st.denied.insert(identity.clone(), reason);
        Ok((identity, r.session, psk))
    }

    // Members listed by a newly adopted manifest have been approved: their
    // requests are done and each uses up its invite once.
    pub fn manifest_adopted(&self, m: &NetworkManifest) {
        let mut st = self.state.lock().unwrap();
        let done: Vec<PublicKey> = st
            .requests
            .keys()
            .filter(|k| m.member(k).is_some())
            .cloned()
            .collect();
        if done.is_empty() {
            return;
        }
        for k in done {
            let r = st.requests.remove(&k).unwrap();
            info!(req_id = r.pending.req_id, peer = %k.fingerprint(), "enrollment approved");
            if let Some(i) = st.invites.iter_mut().find(|i| i.id == r.pending.invite.id) {
                i.uses_left = i.uses_left.saturating_sub(1);
            }
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        st.invites.retain(|i| i.live(now));
        self.save(&st.invites);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Signer;
    use crate::identity::soft::SoftSigner;
    use crate::invite::InviteCode;
    use crate::manifest::ManifestDraft;

    const NOW: u64 = 1_800_000_000;
    const H: [u8; 32] = [7; 32];

    fn invite(code: &InviteCode, uses: u32) -> Invite {
        Invite {
            id: code.id(),
            psk: code.psk(),
            name: Some("node".into()),
            tags: vec!["t".into()],
            expires_at: NOW + 3600,
            uses_left: uses,
            auto_approve: false,
            created_at: NOW,
        }
    }

    fn addr() -> SocketAddr {
        "192.0.2.9:41641".parse().unwrap()
    }

    fn ask(m: &Manager, code: &InviteCode, who: &PublicKey, now: u64) -> Option<EnrollState> {
        let mac = invite::request_mac(&code.psk(), &H, who);
        m.request(&code.id(), &mac, &H, who, None, addr(), 1, now)
            .map(|a| a.state)
    }

    #[test]
    fn request_pending_then_approved_consumes_use() {
        let net = SoftSigner::generate();
        let code = InviteCode::generate(net.public_key());
        let m = Manager::load(None).unwrap();
        m.add_invite(invite(&code, 1)).unwrap();
        let node = SoftSigner::generate().public_key();
        assert_eq!(ask(&m, &code, &node, NOW), Some(EnrollState::Pending));
        assert_eq!(ask(&m, &code, &node, NOW), Some(EnrollState::Pending));
        assert_eq!(m.pending(NOW).len(), 1);

        let mut draft = ManifestDraft::new(net.public_key(), "n".into()).unwrap();
        draft
            .add_member(node.clone(), "node".into(), None, None, vec![])
            .unwrap();
        m.manifest_adopted(&draft.next_manifest(NOW, 3600));
        assert!(m.pending(NOW).is_empty());
        assert!(!m.has_live_invites(NOW));
        assert_eq!(ask(&m, &code, &node, NOW), None);
    }

    #[test]
    fn bad_mac_wrong_session_and_unknown_invite_get_no_answer() {
        let code = InviteCode::generate(SoftSigner::generate().public_key());
        let m = Manager::load(None).unwrap();
        m.add_invite(invite(&code, 1)).unwrap();
        let node = SoftSigner::generate().public_key();
        let wrong = InviteCode::generate(code.network_key.clone());
        let bad = invite::request_mac(&wrong.psk(), &H, &node);
        assert!(
            m.request(&code.id(), &bad, &H, &node, None, addr(), 1, NOW)
                .is_none()
        );
        let replayed = invite::request_mac(&code.psk(), &[8; 32], &node);
        assert!(
            m.request(&code.id(), &replayed, &H, &node, None, addr(), 1, NOW)
                .is_none()
        );
        assert_eq!(ask(&m, &wrong, &node, NOW), None);
        assert!(m.pending(NOW).is_empty());
    }

    #[test]
    fn expired_invite_refused() {
        let code = InviteCode::generate(SoftSigner::generate().public_key());
        let m = Manager::load(None).unwrap();
        m.add_invite(invite(&code, 1)).unwrap();
        let node = SoftSigner::generate().public_key();
        assert_eq!(ask(&m, &code, &node, NOW + 3600), None);
        assert!(m.invites(NOW + 3600).is_empty());
    }

    #[test]
    fn deny_sticks() {
        let code = InviteCode::generate(SoftSigner::generate().public_key());
        let m = Manager::load(None).unwrap();
        m.add_invite(invite(&code, 1)).unwrap();
        let node = SoftSigner::generate().public_key();
        ask(&m, &code, &node, NOW);
        let req = m.pending(NOW)[0].req_id;
        let (who, session, psk) = m.deny(req, "no".into()).unwrap();
        assert_eq!((who, session, psk), (node.clone(), 1, code.psk()));
        assert_eq!(
            ask(&m, &code, &node, NOW),
            Some(EnrollState::Denied("no".into()))
        );
        assert!(m.pending(NOW).is_empty());
    }

    #[test]
    fn pending_caps() {
        let code = InviteCode::generate(SoftSigner::generate().public_key());
        let m = Manager::load(None).unwrap();
        m.add_invite(invite(&code, 100)).unwrap();
        for _ in 0..MAX_PENDING_PER_INVITE {
            let n = SoftSigner::generate().public_key();
            assert_eq!(ask(&m, &code, &n, NOW), Some(EnrollState::Pending));
        }
        let n = SoftSigner::generate().public_key();
        assert!(matches!(
            ask(&m, &code, &n, NOW),
            Some(EnrollState::Denied(_))
        ));
        assert_eq!(m.pending(NOW).len(), MAX_PENDING_PER_INVITE);
    }

    #[test]
    fn invites_persist_and_revoke() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invites");
        let code = InviteCode::generate(SoftSigner::generate().public_key());
        let m = Manager::load(Some(path.clone())).unwrap();
        m.add_invite(invite(&code, 1)).unwrap();
        assert!(m.add_invite(invite(&code, 1)).is_err());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let m = Manager::load(Some(path.clone())).unwrap();
        assert_eq!(m.invites(NOW).len(), 1);
        let node = SoftSigner::generate().public_key();
        ask(&m, &code, &node, NOW);
        assert_eq!(m.revoke_invite(&code.id()).unwrap(), vec![1]);
        assert!(m.pending(NOW).is_empty());
        assert!(Manager::load(Some(path)).unwrap().invites(NOW).is_empty());
    }
}
