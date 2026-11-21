use std::fmt;

use rootcause::prelude::*;
use serde::{Deserialize, Serialize};

use crate::identity::{PublicKey, Signature, Signer};
use crate::manifest::NetId;

pub const BINDING_DOMAIN: &[u8] = b"backscale/device-binding/v1";
pub const DEFAULT_BINDING_LIFETIME_SECS: u64 = 24 * 3600;

pub struct SessionKeys {
    pub wg: x25519_dalek::StaticSecret,
    pub noise: x25519_dalek::StaticSecret,
}

impl SessionKeys {
    pub fn generate() -> Self {
        SessionKeys {
            wg: x25519_dalek::StaticSecret::from(rand::random::<[u8; 32]>()),
            noise: x25519_dalek::StaticSecret::from(rand::random::<[u8; 32]>()),
        }
    }

    // Two hex lines (wg, noise), written with mode 0600.
    pub fn save(&self, path: &std::path::Path) -> Result<(), Report> {
        use std::io::Write;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(path)
            .context("failed to write session keys")
            .attach(format!("path: {}", path.display()))?;
        writeln!(f, "{}", hex::encode(self.wg.to_bytes()))?;
        writeln!(f, "{}", hex::encode(self.noise.to_bytes()))?;
        Ok(())
    }

    pub fn load(path: &std::path::Path) -> Result<Self, Report> {
        let text = std::fs::read_to_string(path)
            .context("failed to read session keys")
            .attach(format!("path: {}", path.display()))?;
        let keys: Vec<[u8; 32]> = text
            .lines()
            .map(|l| {
                hex::decode(l.trim())
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| report!("session key file is malformed"))
            })
            .collect::<Result<_, _>>()?;
        let [wg, noise] = keys[..] else {
            bail!("session key file must contain two keys");
        };
        Ok(SessionKeys {
            wg: x25519_dalek::StaticSecret::from(wg),
            noise: x25519_dalek::StaticSecret::from(noise),
        })
    }

    pub fn wg_public(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.wg).to_bytes()
    }

    pub fn noise_public(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.noise).to_bytes()
    }

    pub fn bind(
        &self,
        net_id: NetId,
        identity: &dyn Signer,
        now: u64,
        lifetime_secs: u64,
    ) -> Result<SignedBinding, Report> {
        let binding = DeviceBinding {
            net_id,
            identity: identity.public_key(),
            wg_public: self.wg_public(),
            noise_public: self.noise_public(),
            issued_at: now,
            expires_at: now + lifetime_secs,
        };
        let body = postcard::to_stdvec(&binding).context("failed to encode device binding")?;
        let signature = identity
            .sign_domain(BINDING_DOMAIN, &body)
            .context("identity key failed to sign device binding")?;
        Ok(SignedBinding { body, signature })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceBinding {
    pub net_id: NetId,
    pub identity: PublicKey,
    pub wg_public: [u8; 32],
    pub noise_public: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingError {
    Decode,
    BadSignature,
    WrongIdentity,
    WrongNetwork,
    NotYetValid,
    Expired,
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BindingError::Decode => "device binding could not be decoded",
            BindingError::BadSignature => "device binding signature is invalid",
            BindingError::WrongIdentity => "device binding is for a different identity",
            BindingError::WrongNetwork => "device binding is for a different network",
            BindingError::NotYetValid => "device binding is not yet valid",
            BindingError::Expired => "device binding has expired",
        })
    }
}

impl std::error::Error for BindingError {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBinding {
    pub body: Vec<u8>,
    pub signature: Signature,
}

impl SignedBinding {
    pub fn verify(
        &self,
        identity: &PublicKey,
        net_id: NetId,
        now: u64,
    ) -> Result<DeviceBinding, Report<BindingError>> {
        identity
            .verify(BINDING_DOMAIN, &self.body, &self.signature)
            .map_err(|e| e.context(BindingError::BadSignature))?;
        let b: DeviceBinding = postcard::from_bytes(&self.body)
            .map_err(|e| report!(BindingError::Decode).attach(e.to_string()))?;
        if &b.identity != identity {
            return Err(report!(BindingError::WrongIdentity));
        }
        if b.net_id != net_id {
            return Err(report!(BindingError::WrongNetwork));
        }
        if b.issued_at > now + crate::manifest::MAX_CLOCK_SKEW_SECS {
            return Err(report!(BindingError::NotYetValid));
        }
        if now >= b.expires_at {
            return Err(report!(BindingError::Expired));
        }
        Ok(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::soft::SoftSigner;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn keys_persist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.keys");
        let k = SessionKeys::generate();
        k.save(&path).unwrap();
        let l = SessionKeys::load(&path).unwrap();
        assert_eq!(k.wg_public(), l.wg_public());
        assert_eq!(k.noise_public(), l.noise_public());
        std::fs::write(&path, "00\n").unwrap();
        assert!(SessionKeys::load(&path).is_err());
    }

    #[test]
    fn bind_and_verify() {
        let id = SoftSigner::generate();
        let net = NetId([1; 32]);
        let keys = SessionKeys::generate();
        let sb = keys.bind(net, &id, NOW, 3600).unwrap();
        let b = sb.verify(&id.public_key(), net, NOW + 1).unwrap();
        assert_eq!(b.wg_public, keys.wg_public());
        assert_eq!(b.noise_public, keys.noise_public());

        let e = sb
            .verify(&id.public_key(), NetId([2; 32]), NOW)
            .unwrap_err();
        assert_eq!(e.current_context(), &BindingError::WrongNetwork);
        let e = sb.verify(&id.public_key(), net, NOW + 3600).unwrap_err();
        assert_eq!(e.current_context(), &BindingError::Expired);
        let other = SoftSigner::generate();
        let e = sb.verify(&other.public_key(), net, NOW).unwrap_err();
        assert_eq!(e.current_context(), &BindingError::BadSignature);
    }
}
