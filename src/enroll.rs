// Everything a fresh machine needs to join a network, stored on the card
// next to the node's identity key.

use std::net::SocketAddr;

use rootcause::prelude::*;
use serde::{Deserialize, Serialize};

use crate::identity::PublicKey;
use crate::manifest::{NetId, NetworkManifest, SignedManifest};

pub const RECORD_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnrollmentRecord {
    pub version: u8,
    pub network_key: PublicKey,
    pub network_name: String,
    pub node_name: String,
    pub peers: Vec<SocketAddr>,
    // Lets the node know its addresses before reaching any peer. May be
    // omitted when it doesn't fit on the card.
    pub manifest: Option<SignedManifest>,
}

impl EnrollmentRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("enrollment record always encodes")
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Report> {
        let rec: Self = postcard::from_bytes(b).context("malformed enrollment record")?;
        if rec.version != RECORD_VERSION {
            bail!("unsupported enrollment record version {}", rec.version);
        }
        Ok(rec)
    }

    pub fn net_id(&self) -> NetId {
        NetId::from_network_key(&self.network_key)
    }

    // Checks the bundled manifest (if any) against the record's network key
    // and that it lists `identity` under the expected name. Note this proves
    // consistency, not authenticity: whoever can rewrite the card can also
    // swap the network key, so the net id must be checked out of band.
    pub fn check(&self, identity: &PublicKey, now: u64) -> Result<Option<NetworkManifest>, Report> {
        let Some(signed) = &self.manifest else {
            return Ok(None);
        };
        let m = signed
            .verify(&self.network_key, now)
            .map_err(|e| e.into_dynamic())
            .context("bundled manifest does not verify against the record's network key")?;
        let member = m
            .member(identity)
            .ok_or_else(|| report!("the card's key is not a member of the bundled manifest"))?;
        if member.name != self.node_name {
            bail!(
                "bundled manifest names this key `{}`, record says `{}`",
                member.name,
                self.node_name
            );
        }
        Ok(Some(m))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Signer;
    use crate::identity::soft::SoftSigner;
    use crate::manifest::ManifestDraft;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn setup() -> (SoftSigner, SoftSigner, EnrollmentRecord) {
        let net = SoftSigner::generate();
        let node = SoftSigner::generate();
        let mut draft = ManifestDraft::new(net.public_key(), "home".into()).unwrap();
        draft
            .add_member(node.public_key(), "laptop".into(), None, None, vec![])
            .unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let rec = EnrollmentRecord {
            version: RECORD_VERSION,
            network_key: net.public_key(),
            network_name: "home".into(),
            node_name: "laptop".into(),
            peers: vec![
                "203.0.113.5:41641".parse().unwrap(),
                "[2001:db8::5]:41641".parse().unwrap(),
            ],
            manifest: Some(draft.next_manifest(now, 3600).sign(&net).unwrap()),
        };
        (net, node, rec)
    }

    #[test]
    fn roundtrip_and_check() {
        let (_, node, rec) = setup();
        let back = EnrollmentRecord::from_bytes(&rec.to_bytes()).unwrap();
        assert_eq!(back, rec);
        let m = back
            .check(
                &node.public_key(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(m.members[0].name, "laptop");
    }

    #[test]
    fn inconsistent_records_rejected() {
        let (_, node, rec) = setup();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let stranger = SoftSigner::generate();
        assert!(rec.check(&stranger.public_key(), now).is_err());

        let mut renamed = rec.clone();
        renamed.node_name = "desktop".into();
        assert!(renamed.check(&node.public_key(), now).is_err());

        let mut swapped = rec.clone();
        swapped.network_key = SoftSigner::generate().public_key();
        assert!(swapped.check(&node.public_key(), now).is_err());

        let mut bad = rec.to_bytes();
        bad[0] = 9;
        assert!(EnrollmentRecord::from_bytes(&bad).is_err());
    }

    #[test]
    fn small_enough_for_a_piv_object() {
        // A PIV data object holds ~3 KB; the certificate wrapper takes ~400 bytes.
        let (_, _, rec) = setup();
        assert!(rec.to_bytes().len() < 1000, "{}", rec.to_bytes().len());
    }
}
