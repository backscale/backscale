// An invite code carries the network key and a secret. Everything else is
// derived from the secret, which itself never leaves the two ends.

use std::fmt;
use std::str::FromStr;

use base64ct::{Base64UrlUnpadded, Encoding};
use rootcause::prelude::*;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::identity::PublicKey;
use crate::manifest::NetId;

const PREFIX: &str = "bsinvite1:";

pub type InviteId = [u8; 16];

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteCode {
    pub network_key: PublicKey,
    pub secret: [u8; 32],
}

impl InviteCode {
    pub fn generate(network_key: PublicKey) -> Self {
        InviteCode {
            network_key,
            secret: rand::random(),
        }
    }

    pub fn id(&self) -> InviteId {
        invite_id(&self.secret)
    }

    pub fn psk(&self) -> [u8; 32] {
        blake3::derive_key("backscale invite psk v1", &self.secret)
    }

    pub fn net_id(&self) -> NetId {
        NetId::from_network_key(&self.network_key)
    }
}

pub fn invite_id(secret: &[u8; 32]) -> InviteId {
    blake3::derive_key("backscale invite id v1", secret)[..16]
        .try_into()
        .unwrap()
}

impl fmt::Display for InviteCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = postcard::to_stdvec(self).expect("invite always encodes");
        write!(f, "{PREFIX}{}", Base64UrlUnpadded::encode_string(&bytes))
    }
}

// The secret must not end up in logs.
impl fmt::Debug for InviteCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InviteCode({})", hex::encode(self.id()))
    }
}

impl FromStr for InviteCode {
    type Err = Report;

    fn from_str(s: &str) -> Result<Self, Report> {
        let body = s
            .trim()
            .strip_prefix(PREFIX)
            .ok_or_else(|| report!("not a backscale invite code (expected `{PREFIX}...`)"))?;
        let bytes = Base64UrlUnpadded::decode_vec(body)
            .map_err(|_| report!("invite code is not valid base64url"))?;
        let (code, rest): (InviteCode, _) =
            postcard::take_from_bytes(&bytes).context("malformed invite code")?;
        if !rest.is_empty() {
            bail!("malformed invite code: trailing bytes");
        }
        Ok(code)
    }
}

fn mac(label: &str, psk: &[u8; 32], handshake: &[u8; 32], identity: &PublicKey) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(psk);
    h.update(label.as_bytes());
    h.update(handshake);
    h.update(&postcard::to_stdvec(identity).expect("public key always encodes"));
    *h.finalize().as_bytes()
}

// Binds the enrolling node's request to one control session, so it can't be
// replayed on another.
pub fn request_mac(psk: &[u8; 32], handshake: &[u8; 32], identity: &PublicKey) -> [u8; 32] {
    mac("backscale/enroll/request/v1", psk, handshake, identity)
}

// Proves to the node that it reached the manager holding its invite.
pub fn status_mac(psk: &[u8; 32], handshake: &[u8; 32], identity: &PublicKey) -> [u8; 32] {
    mac("backscale/enroll/status/v1", psk, handshake, identity)
}

pub fn mac_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Signer;
    use crate::identity::soft::SoftSigner;

    fn code() -> InviteCode {
        InviteCode::generate(SoftSigner::generate().public_key())
    }

    #[test]
    fn text_roundtrip() {
        let c = code();
        let s = c.to_string();
        assert!(s.starts_with(PREFIX));
        assert_eq!(s.parse::<InviteCode>().unwrap(), c);
        assert_eq!(format!(" {s}\n").parse::<InviteCode>().unwrap(), c);
        assert!(!format!("{c:?}").contains(&hex::encode(c.secret)));
    }

    #[test]
    fn rejects_bad_codes() {
        let s = code().to_string();
        assert!("".parse::<InviteCode>().is_err());
        assert!(s[PREFIX.len()..].parse::<InviteCode>().is_err());
        assert!(format!("{s}!").parse::<InviteCode>().is_err());
        assert!(format!("{s}AA").parse::<InviteCode>().is_err());
        assert!(s[..s.len() - 4].parse::<InviteCode>().is_err());
    }

    #[test]
    fn derivations_are_distinct() {
        let c = code();
        assert_ne!(&c.psk()[..16], &c.id()[..]);
        assert_ne!(c.psk(), c.secret);
        assert_ne!(code().id(), c.id());
    }

    #[test]
    fn macs_bind_session_identity_and_direction() {
        let c = code();
        let psk = c.psk();
        let id = SoftSigner::generate().public_key();
        let other = SoftSigner::generate().public_key();
        let m = request_mac(&psk, &[1; 32], &id);
        assert!(mac_eq(&m, &request_mac(&psk, &[1; 32], &id)));
        assert!(!mac_eq(&m, &request_mac(&psk, &[2; 32], &id)));
        assert!(!mac_eq(&m, &request_mac(&psk, &[1; 32], &other)));
        assert!(!mac_eq(&m, &request_mac(&code().psk(), &[1; 32], &id)));
        assert!(!mac_eq(&m, &status_mac(&psk, &[1; 32], &id)));
    }
}
