use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::*;
use crate::identity::soft::SoftSigner;
use crate::invite::InviteCode;
use crate::manager::Invite;
use crate::manifest::ManifestDraft;
use crate::net::socket::{MuxTasks, UdpMux};
use backscale_utp::UtpConfig;

const WAIT: Duration = Duration::from_secs(10);

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Node {
    control: ControlNode,
    addr: SocketAddr,
    _tasks: MuxTasks,
}

async fn node(
    signer: &SoftSigner,
    network_key: PublicKey,
    manager: Option<Arc<Manager>>,
    enroll: Option<EnrollAs>,
) -> Node {
    let mux = UdpMux::bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let utp = Arc::new(UtpSocket::new(mux.utp, UtpConfig::default()));
    let control = ControlNode::new(
        ControlConfig {
            network_key,
            manifest_path: None,
            manager,
            enroll,
        },
        signer,
        SessionKeys::generate(),
        utp,
    )
    .unwrap();
    control.start();
    Node {
        control,
        addr: mux.local_addr,
        _tasks: mux.tasks,
    }
}

struct Net {
    key: SoftSigner,
    draft: ManifestDraft,
    manager: Node,
    mgr: Arc<Manager>,
}

impl Net {
    fn publish(&mut self) {
        let signed = self
            .draft
            .next_manifest(now(), 3600)
            .sign(&self.key)
            .unwrap();
        self.manager.control.publish(signed).unwrap();
    }
}

async fn network() -> Net {
    let key = SoftSigner::generate();
    let me = SoftSigner::generate();
    let mut draft = ManifestDraft::new(key.public_key(), "net".into()).unwrap();
    draft
        .add_member(me.public_key(), "manager".into(), None, None, vec![])
        .unwrap();
    let mgr = Arc::new(Manager::load(None).unwrap());
    let manager = node(&me, key.public_key(), Some(mgr.clone()), None).await;
    let mut net = Net {
        key,
        draft,
        manager,
        mgr,
    };
    net.publish();
    net
}

fn invite(net: &Net, code: &InviteCode) {
    net.mgr
        .add_invite(Invite {
            id: code.id(),
            psk: code.psk(),
            name: None,
            tags: vec![],
            expires_at: now() + 3600,
            uses_left: 1,
            auto_approve: false,
            created_at: now(),
        })
        .unwrap();
}

async fn enrollee(
    net: &Net,
    code: &InviteCode,
) -> (SoftSigner, Node, broadcast::Receiver<ControlEvent>) {
    let me = SoftSigner::generate();
    let n = node(
        &me,
        code.network_key.clone(),
        None,
        Some(EnrollAs {
            invite: code.clone(),
            name: Some("newbie".into()),
        }),
    )
    .await;
    let events = n.control.subscribe();
    n.control.connect(net.manager.addr).await.unwrap();
    (me, n, events)
}

async fn next_enrollment(events: &mut broadcast::Receiver<ControlEvent>) -> Option<EnrollState> {
    enrollment_within(events, WAIT).await
}

// For answers that must not come; a real one arrives within milliseconds.
async fn no_enrollment(events: &mut broadcast::Receiver<ControlEvent>) -> bool {
    enrollment_within(events, Duration::from_secs(2))
        .await
        .is_none()
}

async fn enrollment_within(
    events: &mut broadcast::Receiver<ControlEvent>,
    wait: Duration,
) -> Option<EnrollState> {
    tokio::time::timeout(wait, async {
        loop {
            match events.recv().await {
                Ok(ControlEvent::Enrollment { state, .. }) => return state,
                Ok(_) => {}
                Err(e) => panic!("{e}"),
            }
        }
    })
    .await
    .ok()
}

async fn until(what: &str, f: impl Fn() -> bool) {
    tokio::time::timeout(WAIT, async {
        while !f() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
}

#[tokio::test]
async fn enrollment_is_approved_on_the_same_session() {
    let mut net = network().await;
    let code = InviteCode::generate(net.key.public_key());
    invite(&net, &code);
    let (me, n, mut events) = enrollee(&net, &code).await;

    assert_eq!(
        next_enrollment(&mut events).await,
        Some(EnrollState::Pending)
    );
    let pending = net.mgr.pending(now());
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].identity, me.public_key());
    assert_eq!(pending[0].name.as_deref(), Some("newbie"));
    until("enrollee to sync the manifest", || {
        n.control.manifest_seq() == 1
    })
    .await;

    net.draft
        .add_member(me.public_key(), "newbie".into(), None, None, vec![])
        .unwrap();
    net.publish();
    until("manager to verify the enrollee", || {
        net.manager.control.is_verified(&me.public_key())
    })
    .await;
    until("enrollee to see itself listed", || {
        n.control
            .manifest()
            .is_some_and(|m| m.member(&me.public_key()).is_some())
    })
    .await;
    assert_eq!(net.manager.control.peers().len(), 1, "one session, reused");
    assert!(net.mgr.pending(now()).is_empty());
    assert!(net.mgr.invites(now()).is_empty(), "single use consumed");
}

#[tokio::test]
async fn wrong_secret_gets_no_answer() {
    let net = network().await;
    let real = InviteCode::generate(net.key.public_key());
    invite(&net, &real);
    let forged = InviteCode {
        network_key: real.network_key.clone(),
        secret: rand::random(),
    };
    let (_, _n, mut events) = enrollee(&net, &forged).await;
    assert!(no_enrollment(&mut events).await);
    assert!(net.mgr.pending(now()).is_empty());
}

#[tokio::test]
async fn a_member_without_the_invite_does_not_answer() {
    let net = network().await;
    let code = InviteCode::generate(net.key.public_key());
    // The invite lives nowhere: the member we reach is not its manager.
    let (_, _n, mut events) = enrollee(&net, &code).await;
    assert!(no_enrollment(&mut events).await);
}

#[tokio::test]
async fn denial_reaches_the_node() {
    let net = network().await;
    let code = InviteCode::generate(net.key.public_key());
    invite(&net, &code);
    let (_, _n, mut events) = enrollee(&net, &code).await;
    assert_eq!(
        next_enrollment(&mut events).await,
        Some(EnrollState::Pending)
    );
    let req = net.mgr.pending(now())[0].req_id;
    let (who, session, psk) = net.mgr.deny(req, "not today".into()).unwrap();
    net.manager
        .control
        .deny_enrollment(session, &who, &psk, "not today".into());
    assert_eq!(
        next_enrollment(&mut events).await,
        Some(EnrollState::Denied("not today".into()))
    );
}
