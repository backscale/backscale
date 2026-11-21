use atomic_write_file::AtomicWriteFile;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};
use rootcause::prelude::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::identity::{PublicKey, Signature, Signer};

pub const MANIFEST_DOMAIN: &[u8] = b"backscale/manifest/v1";
pub const MAX_MANIFEST_BYTES: usize = 1 << 20;
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NetId(pub [u8; 32]);

impl NetId {
    pub fn from_network_key(key: &PublicKey) -> Self {
        let encoded = postcard::to_stdvec(key).expect("public key always encodes");
        NetId(blake3::derive_key("backscale net-id v1", &encoded))
    }

    pub fn default_ipv4_prefix(&self) -> Ipv4Net {
        Ipv4Net::new(Ipv4Addr::new(100, 64 + (self.0[0] & 0x3f), 0, 0), 16).unwrap()
    }

    pub fn default_ipv6_prefix(&self) -> Ipv6Net {
        let mut b = [0u8; 16];
        b[0] = 0xfd;
        b[1..6].copy_from_slice(&self.0[1..6]);
        Ipv6Net::new(Ipv6Addr::from(b), 64).unwrap()
    }
}

impl fmt::Display for NetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for NetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NetId({})", &hex::encode(self.0)[..16])
    }
}

impl Serialize for NetId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            self.0.serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for NetId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            let v = hex::decode(&s).map_err(D::Error::custom)?;
            let arr = v
                .try_into()
                .map_err(|_| D::Error::custom("net id must be 32 bytes"))?;
            Ok(NetId(arr))
        } else {
            Ok(NetId(<[u8; 32]>::deserialize(d)?))
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub ipv4_prefix: Ipv4Net,
    pub ipv6_prefix: Ipv6Net,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub identity: PublicKey,
    pub name: String,
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkManifest {
    pub net_id: NetId,
    pub network_key: PublicKey,
    pub name: String,
    pub seq: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub settings: Settings,
    pub members: Vec<Member>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    TooLarge,
    BadSignature,
    Decode,
    WrongNetwork,
    Invalid(String),
    NotYetValid,
    Expired,
    Stale { have: u64, got: u64 },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestError::TooLarge => write!(f, "manifest is too large"),
            ManifestError::BadSignature => write!(f, "manifest signature is invalid"),
            ManifestError::Decode => write!(f, "manifest could not be decoded"),
            ManifestError::WrongNetwork => write!(f, "manifest belongs to a different network"),
            ManifestError::Invalid(why) => write!(f, "manifest is invalid: {why}"),
            ManifestError::NotYetValid => {
                write!(f, "manifest is not yet valid (issued in the future)")
            }
            ManifestError::Expired => write!(f, "manifest has expired"),
            ManifestError::Stale { have, got } => {
                write!(f, "manifest seq {got} is not newer than current seq {have}")
            }
        }
    }
}

impl std::error::Error for ManifestError {}

fn invalid(why: impl Into<String>) -> Report<ManifestError> {
    report!(ManifestError::Invalid(why.into()))
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-')
        && !name.ends_with('-')
}

impl NetworkManifest {
    pub fn validate(&self) -> Result<(), Report<ManifestError>> {
        if NetId::from_network_key(&self.network_key) != self.net_id {
            return Err(invalid("net_id does not match network key"));
        }
        if self.issued_at >= self.expires_at {
            return Err(invalid("issued_at must be before expires_at"));
        }
        validate_members(&self.settings, &self.members)
    }

    pub fn member(&self, identity: &PublicKey) -> Option<&Member> {
        self.members.iter().find(|m| &m.identity == identity)
    }

    pub fn sign(&self, network_key: &dyn Signer) -> Result<SignedManifest, Report> {
        if network_key.public_key() != self.network_key {
            bail!("signing key does not match the manifest's network key");
        }
        self.validate()
            .context("refusing to sign an invalid manifest")?;
        let body = postcard::to_stdvec(self).context("failed to encode manifest")?;
        let signature = network_key
            .sign_domain(MANIFEST_DOMAIN, &body)
            .context("failed to sign manifest")?;
        Ok(SignedManifest { body, signature })
    }
}

fn validate_members(settings: &Settings, members: &[Member]) -> Result<(), Report<ManifestError>> {
    let mut ids = HashSet::new();
    let mut names = HashSet::new();
    let mut v4 = HashSet::new();
    let mut v6 = HashSet::new();
    let p4 = settings.ipv4_prefix;
    let p6 = settings.ipv6_prefix;
    for m in members {
        let who = &m.name;
        if !valid_name(&m.name) {
            return Err(invalid(format!("invalid member name `{who}`")));
        }
        if !ids.insert(&m.identity) {
            return Err(invalid(format!("duplicate identity for `{who}`")));
        }
        if !names.insert(&m.name) {
            return Err(invalid(format!("duplicate name `{who}`")));
        }
        if !v4.insert(m.ipv4) {
            return Err(invalid(format!("duplicate ipv4 {} (`{who}`)", m.ipv4)));
        }
        if !v6.insert(m.ipv6) {
            return Err(invalid(format!("duplicate ipv6 {} (`{who}`)", m.ipv6)));
        }
        if !p4.contains(&m.ipv4) || m.ipv4 == p4.network() || m.ipv4 == p4.broadcast() {
            return Err(invalid(format!(
                "ipv4 {} of `{who}` is not a host in {p4}",
                m.ipv4
            )));
        }
        if !p6.contains(&m.ipv6) || m.ipv6 == p6.network() {
            return Err(invalid(format!(
                "ipv6 {} of `{who}` is not a host in {p6}",
                m.ipv6
            )));
        }
    }
    Ok(())
}

// `body` is kept verbatim so verification never depends on re-serialization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedManifest {
    pub body: Vec<u8>,
    pub signature: Signature,
}

impl SignedManifest {
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("signed manifest always encodes")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Report<ManifestError>> {
        if bytes.len() > MAX_MANIFEST_BYTES + 256 {
            return Err(report!(ManifestError::TooLarge));
        }
        postcard::from_bytes(bytes)
            .map_err(|e| report!(ManifestError::Decode).attach(e.to_string()))
    }

    /// Decode the body *without* checking the signature. Only for display of
    /// untrusted manifests; never use the result for decisions.
    pub fn decode_unverified(&self) -> Result<NetworkManifest, Report<ManifestError>> {
        postcard::from_bytes(&self.body)
            .map_err(|e| report!(ManifestError::Decode).attach(e.to_string()))
    }

    pub fn verify(
        &self,
        pinned: &PublicKey,
        now: u64,
    ) -> Result<NetworkManifest, Report<ManifestError>> {
        if self.body.len() > MAX_MANIFEST_BYTES {
            return Err(report!(ManifestError::TooLarge));
        }
        pinned
            .verify(MANIFEST_DOMAIN, &self.body, &self.signature)
            .map_err(|e| e.context(ManifestError::BadSignature))?;
        let m = self.decode_unverified()?;
        if &m.network_key != pinned {
            return Err(report!(ManifestError::WrongNetwork));
        }
        m.validate()?;
        if m.issued_at > now + MAX_CLOCK_SKEW_SECS {
            return Err(report!(ManifestError::NotYetValid));
        }
        if now >= m.expires_at {
            return Err(report!(ManifestError::Expired).attach(format!(
                "expired at {}",
                humantime::format_rfc3339_seconds(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(m.expires_at)
                )
            )));
        }
        Ok(m)
    }
}

pub fn adopt(
    current: Option<&NetworkManifest>,
    candidate: &SignedManifest,
    pinned: &PublicKey,
    now: u64,
) -> Result<NetworkManifest, Report<ManifestError>> {
    let m = candidate.verify(pinned, now)?;
    if let Some(cur) = current
        && m.seq <= cur.seq
    {
        return Err(report!(ManifestError::Stale {
            have: cur.seq,
            got: m.seq
        }));
    }
    Ok(m)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ManifestDiff {
    pub added: Vec<Member>,
    pub removed: Vec<Member>,
    pub changed: Vec<Member>,
}

impl ManifestDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

pub fn diff(old: Option<&NetworkManifest>, new: &NetworkManifest) -> ManifestDiff {
    let old_map: BTreeMap<&PublicKey, &Member> = old
        .map(|o| o.members.iter().map(|m| (&m.identity, m)).collect())
        .unwrap_or_default();
    let new_map: BTreeMap<&PublicKey, &Member> =
        new.members.iter().map(|m| (&m.identity, m)).collect();
    let mut d = ManifestDiff::default();
    for (id, m) in &new_map {
        match old_map.get(id) {
            None => d.added.push((*m).clone()),
            Some(o) if o != m => d.changed.push((*m).clone()),
            Some(_) => {}
        }
    }
    for (id, m) in &old_map {
        if !new_map.contains_key(id) {
            d.removed.push((*m).clone());
        }
    }
    d
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestDraft {
    pub network_key: PublicKey,
    pub name: String,
    pub last_seq: u64,
    pub settings: Settings,
    #[serde(default)]
    pub members: Vec<Member>,
}

impl ManifestDraft {
    pub fn new(network_key: PublicKey, name: String) -> Result<Self, Report> {
        if !valid_name(&name) {
            bail!("invalid network name `{name}` (use lowercase letters, digits and `-`)");
        }
        let net_id = NetId::from_network_key(&network_key);
        Ok(ManifestDraft {
            settings: Settings {
                ipv4_prefix: net_id.default_ipv4_prefix(),
                ipv6_prefix: net_id.default_ipv6_prefix(),
            },
            network_key,
            name,
            last_seq: 0,
            members: Vec::new(),
        })
    }

    pub fn net_id(&self) -> NetId {
        NetId::from_network_key(&self.network_key)
    }

    pub fn add_member(
        &mut self,
        identity: PublicKey,
        name: String,
        ipv4: Option<Ipv4Addr>,
        ipv6: Option<Ipv6Addr>,
        tags: Vec<String>,
    ) -> Result<&Member, Report> {
        let ipv4 = match ipv4 {
            Some(ip) => ip,
            None => self.next_free_ipv4()?,
        };
        let ipv6 = match ipv6 {
            Some(ip) => ip,
            None => self.next_free_ipv6()?,
        };
        let mut members = self.members.clone();
        members.push(Member {
            identity,
            name,
            ipv4,
            ipv6,
            tags,
        });
        validate_members(&self.settings, &members).map_err(|e| e.into_dynamic())?;
        self.members = members;
        Ok(self.members.last().unwrap())
    }

    pub fn remove_member(&mut self, who: &str) -> Result<Member, Report> {
        let idx = self
            .members
            .iter()
            .position(|m| m.name == who || m.identity.to_string() == who)
            .ok_or_else(|| report!("no member named or keyed `{who}`"))?;
        Ok(self.members.remove(idx))
    }

    fn next_free_ipv4(&self) -> Result<Ipv4Addr, Report> {
        let used: HashSet<Ipv4Addr> = self.members.iter().map(|m| m.ipv4).collect();
        self.settings
            .ipv4_prefix
            .hosts()
            .find(|ip| !used.contains(ip))
            .ok_or_else(|| report!("ipv4 prefix {} is full", self.settings.ipv4_prefix))
    }

    fn next_free_ipv6(&self) -> Result<Ipv6Addr, Report> {
        let used: HashSet<Ipv6Addr> = self.members.iter().map(|m| m.ipv6).collect();
        let p6 = self.settings.ipv6_prefix;
        p6.hosts()
            .filter(|ip| *ip != p6.network())
            .find(|ip| !used.contains(ip))
            .ok_or_else(|| report!("ipv6 prefix {p6} is full"))
    }

    pub fn next_manifest(&mut self, now: u64, validity_secs: u64) -> NetworkManifest {
        self.last_seq += 1;
        NetworkManifest {
            net_id: self.net_id(),
            network_key: self.network_key.clone(),
            name: self.name.clone(),
            seq: self.last_seq,
            issued_at: now,
            expires_at: now + validity_secs,
            settings: self.settings.clone(),
            members: self.members.clone(),
        }
    }

    pub fn load(path: &std::path::Path) -> Result<Self, Report> {
        let text = std::fs::read_to_string(path)
            .context("failed to read manifest draft")
            .attach(format!("path: {}", path.display()))?;
        Ok(toml::from_str(&text).context("failed to parse manifest draft")?)
    }

    pub fn save(&self, path: &std::path::Path) -> Result<(), Report> {
        let text = toml::to_string_pretty(self).context("failed to encode manifest draft")?;
        let mut f = AtomicWriteFile::open(path)
            .context("failed to write manifest draft")
            .attach(format!("path: {}", path.display()))?;
        f.write_all(text.as_bytes())?;
        f.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::soft::SoftSigner;

    const DAY: u64 = 86400;
    const NOW: u64 = 1_800_000_000;

    fn setup(n: usize) -> (SoftSigner, ManifestDraft, Vec<SoftSigner>) {
        let net = SoftSigner::generate();
        let mut draft = ManifestDraft::new(net.public_key(), "home".into()).unwrap();
        let nodes: Vec<_> = (0..n).map(|_| SoftSigner::generate()).collect();
        for (i, node) in nodes.iter().enumerate() {
            draft
                .add_member(node.public_key(), format!("node{i}"), None, None, vec![])
                .unwrap();
        }
        (net, draft, nodes)
    }

    #[test]
    fn sign_verify_roundtrip() {
        let (net, mut draft, nodes) = setup(3);
        let m = draft.next_manifest(NOW, 30 * DAY);
        let signed = m.sign(&net).unwrap();
        let bytes = signed.to_bytes();
        let back = SignedManifest::from_bytes(&bytes).unwrap();
        let v = back.verify(&net.public_key(), NOW + 10).unwrap();
        assert_eq!(v, m);
        assert_eq!(v.seq, 1);
        assert!(v.member(&nodes[1].public_key()).is_some());
        assert_eq!(v.members[0].ipv4.octets()[2..], [0, 1]);
        assert_eq!(v.members[0].ipv6.segments()[4..], [0, 0, 0, 1]);
        assert_eq!(v.members[2].ipv6.segments()[4..], [0, 0, 0, 3]);
    }

    #[test]
    fn tamper_detected() {
        let (net, mut draft, _) = setup(2);
        let mut signed = draft.next_manifest(NOW, DAY).sign(&net).unwrap();
        let last = signed.body.len() - 1;
        signed.body[last] ^= 1;
        let err = signed.verify(&net.public_key(), NOW).unwrap_err();
        assert_eq!(err.current_context(), &ManifestError::BadSignature);
    }

    #[test]
    fn wrong_network_key() {
        let (net, mut draft, _) = setup(1);
        let signed = draft.next_manifest(NOW, DAY).sign(&net).unwrap();
        let other = SoftSigner::generate();
        let err = signed.verify(&other.public_key(), NOW).unwrap_err();
        assert_eq!(err.current_context(), &ManifestError::BadSignature);
    }

    #[test]
    fn sign_with_wrong_key_refused() {
        let (_, mut draft, nodes) = setup(1);
        assert!(draft.next_manifest(NOW, DAY).sign(&nodes[0]).is_err());
    }

    #[test]
    fn expiry_and_future() {
        let (net, mut draft, _) = setup(1);
        let signed = draft.next_manifest(NOW, DAY).sign(&net).unwrap();
        let pk = net.public_key();
        let err = signed.verify(&pk, NOW + DAY).unwrap_err();
        assert_eq!(err.current_context(), &ManifestError::Expired);
        let err = signed
            .verify(&pk, NOW - 2 * MAX_CLOCK_SKEW_SECS)
            .unwrap_err();
        assert_eq!(err.current_context(), &ManifestError::NotYetValid);
        signed.verify(&pk, NOW - MAX_CLOCK_SKEW_SECS / 2).unwrap();
    }

    #[test]
    fn adopt_requires_newer_seq() {
        let (net, mut draft, _) = setup(2);
        let pk = net.public_key();
        let s1 = draft.next_manifest(NOW, DAY).sign(&net).unwrap();
        let s2 = draft.next_manifest(NOW, DAY).sign(&net).unwrap();
        let m1 = adopt(None, &s1, &pk, NOW).unwrap();
        let m2 = adopt(Some(&m1), &s2, &pk, NOW).unwrap();
        assert_eq!(m2.seq, 2);
        let err = adopt(Some(&m2), &s1, &pk, NOW).unwrap_err();
        assert_eq!(
            err.current_context(),
            &ManifestError::Stale { have: 2, got: 1 }
        );
        let err = adopt(Some(&m2), &s2, &pk, NOW).unwrap_err();
        assert!(matches!(err.current_context(), ManifestError::Stale { .. }));
    }

    #[test]
    fn diff_add_remove_change() {
        let (_, mut draft, nodes) = setup(3);
        let m1 = draft.next_manifest(NOW, DAY);
        draft.remove_member("node0").unwrap();
        draft.members[0].tags.push("server".into());
        let extra = SoftSigner::generate();
        draft
            .add_member(extra.public_key(), "extra".into(), None, None, vec![])
            .unwrap();
        let m2 = draft.next_manifest(NOW, DAY);
        let d = diff(Some(&m1), &m2);
        assert_eq!(d.removed.len(), 1);
        assert_eq!(d.removed[0].identity, nodes[0].public_key());
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].name, "extra");
        // node0's addresses were freed, so `extra` reuses them.
        assert_eq!(d.added[0].ipv4, d.removed[0].ipv4);
        assert_eq!(d.added[0].ipv6, d.removed[0].ipv6);
        assert_eq!(d.changed.len(), 1);
        assert_eq!(d.changed[0].name, "node1");
        assert!(diff(Some(&m2), &m2).is_empty());
        assert_eq!(diff(None, &m2).added.len(), 3);
    }

    #[test]
    fn duplicates_rejected() {
        let (_, mut draft, nodes) = setup(1);
        assert!(
            draft
                .add_member(nodes[0].public_key(), "dup".into(), None, None, vec![])
                .is_err()
        );
        let other = SoftSigner::generate();
        assert!(
            draft
                .add_member(other.public_key(), "node0".into(), None, None, vec![])
                .is_err()
        );
        let ip = draft.members[0].ipv4;
        assert!(
            draft
                .add_member(other.public_key(), "x".into(), Some(ip), None, vec![])
                .is_err()
        );
        assert!(
            draft
                .add_member(other.public_key(), "Bad_Name".into(), None, None, vec![])
                .is_err()
        );
        assert!(
            draft
                .add_member(
                    other.public_key(),
                    "out".into(),
                    Some("10.0.0.1".parse().unwrap()),
                    None,
                    vec![]
                )
                .is_err()
        );
        assert_eq!(draft.members.len(), 1);
    }

    #[test]
    fn draft_toml_roundtrip() {
        let (_, draft, _) = setup(2);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("net.toml");
        draft.save(&path).unwrap();
        assert_eq!(ManifestDraft::load(&path).unwrap(), draft);
    }
}
