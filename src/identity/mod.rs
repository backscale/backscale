#[cfg(feature = "openpgp")]
pub mod openpgp;
pub mod pin;
#[cfg(feature = "piv")]
pub mod piv;
pub mod soft;

use std::fmt;
use std::str::FromStr;

use rootcause::prelude::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SigAlg {
    Ed25519,
    EcdsaP256,
}

impl SigAlg {
    fn tag(self) -> &'static str {
        match self {
            SigAlg::Ed25519 => "ed25519",
            SigAlg::EcdsaP256 => "p256",
        }
    }

    fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "ed25519" => Some(SigAlg::Ed25519),
            "p256" => Some(SigAlg::EcdsaP256),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigError {
    AlgorithmMismatch,
    MalformedKey,
    MalformedSignature,
    Invalid,
}

impl fmt::Display for SigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SigError::AlgorithmMismatch => "signature algorithm does not match key algorithm",
            SigError::MalformedKey => "malformed public key",
            SigError::MalformedSignature => "malformed signature",
            SigError::Invalid => "signature verification failed",
        })
    }
}

impl std::error::Error for SigError {}

/// Build the byte string that is actually signed: `domain || 0x00 || msg`.
// The message is hashed first so hardware keys only ever see a few dozen
// bytes, however large the signed structure is.
pub fn signed_message(domain: &[u8], msg: &[u8]) -> Vec<u8> {
    debug_assert!(!domain.contains(&0), "domain must not contain NUL");
    let digest = blake3::hash(msg);
    let mut out = Vec::with_capacity(domain.len() + 33);
    out.extend_from_slice(domain);
    out.push(0);
    out.extend_from_slice(digest.as_bytes());
    out
}

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey {
    alg: SigAlg,
    bytes: Vec<u8>,
}

impl PublicKey {
    pub fn new(alg: SigAlg, bytes: Vec<u8>) -> Result<Self, Report<SigError>> {
        let key = PublicKey { alg, bytes };
        key.validate()?;
        Ok(key)
    }

    pub fn ed25519(bytes: [u8; 32]) -> Result<Self, Report<SigError>> {
        Self::new(SigAlg::Ed25519, bytes.to_vec())
    }

    fn validate(&self) -> Result<(), Report<SigError>> {
        match self.alg {
            SigAlg::Ed25519 => {
                self.ed25519_key()?;
            }
            SigAlg::EcdsaP256 => {
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.bytes)
                    .map_err(|_| report!(SigError::MalformedKey))?;
            }
        }
        Ok(())
    }

    fn ed25519_key(&self) -> Result<ed25519_dalek::VerifyingKey, Report<SigError>> {
        let arr: &[u8; 32] = self
            .bytes
            .as_slice()
            .try_into()
            .map_err(|_| report!(SigError::MalformedKey))?;
        ed25519_dalek::VerifyingKey::from_bytes(arr).map_err(|_| report!(SigError::MalformedKey))
    }

    pub fn alg(&self) -> SigAlg {
        self.alg
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn fingerprint(&self) -> String {
        let h = blake3::Hasher::new_derive_key("backscale key fingerprint v1")
            .update(self.alg.tag().as_bytes())
            .update(&self.bytes)
            .finalize();
        hex::encode(&h.as_bytes()[..8])
    }

    pub fn verify(
        &self,
        domain: &[u8],
        msg: &[u8],
        sig: &Signature,
    ) -> Result<(), Report<SigError>> {
        if sig.alg != self.alg {
            return Err(report!(SigError::AlgorithmMismatch));
        }
        let data = signed_message(domain, msg);
        match self.alg {
            SigAlg::Ed25519 => {
                let key = self.ed25519_key()?;
                let sig = ed25519_dalek::Signature::from_slice(&sig.bytes)
                    .map_err(|_| report!(SigError::MalformedSignature))?;
                key.verify_strict(&data, &sig)
                    .map_err(|_| report!(SigError::Invalid))
            }
            SigAlg::EcdsaP256 => {
                use p256::ecdsa::signature::Verifier;
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.bytes)
                    .map_err(|_| report!(SigError::MalformedKey))?;
                let sig = p256::ecdsa::Signature::from_slice(&sig.bytes)
                    .map_err(|_| report!(SigError::MalformedSignature))?;
                key.verify(&data, &sig)
                    .map_err(|_| report!(SigError::Invalid))
            }
        }
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.alg.tag(), hex::encode(&self.bytes))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

impl FromStr for PublicKey {
    type Err = Report;

    fn from_str(s: &str) -> Result<Self, Report> {
        let (tag, hex_part) = s
            .split_once(':')
            .ok_or_else(|| report!("public key must look like `ed25519:<hex>`"))?;
        let alg = SigAlg::from_tag(tag).ok_or_else(|| report!("unknown key algorithm `{tag}`"))?;
        let bytes = hex::decode(hex_part).context("public key is not valid hex")?;
        Ok(PublicKey::new(alg, bytes).context("invalid public key")?)
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            (self.alg, &self.bytes).serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        if d.is_human_readable() {
            let s = String::deserialize(d)?;
            s.parse()
                .map_err(|e: Report| D::Error::custom(e.to_string()))
        } else {
            let (alg, bytes) = <(SigAlg, Vec<u8>)>::deserialize(d)?;
            PublicKey::new(alg, bytes).map_err(|e| D::Error::custom(e.to_string()))
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    alg: SigAlg,
    bytes: Vec<u8>,
}

impl Signature {
    pub fn new(alg: SigAlg, bytes: Vec<u8>) -> Self {
        Signature { alg, bytes }
    }

    pub fn alg(&self) -> SigAlg {
        self.alg
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Signature({}:{})",
            self.alg.tag(),
            hex::encode(&self.bytes)
        )
    }
}

/// Hardware backends may block (PIN entry, touch), so callers on an async
/// runtime should invoke `sign` via `spawn_blocking`.
pub trait Signer: Send + Sync {
    fn public_key(&self) -> PublicKey;

    fn sign_raw(&self, data: &[u8]) -> Result<Signature, Report>;

    fn sign_domain(&self, domain: &[u8], msg: &[u8]) -> Result<Signature, Report> {
        self.sign_raw(&signed_message(domain, msg))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeySpec {
    Soft(std::path::PathBuf),
    // YubiKey PIV slot, e.g. `piv:82` or `piv:9c@12345678` (serial).
    Piv { slot: u8, serial: Option<u32> },
    // OpenPGP card signing key, e.g. `openpgp` or `openpgp:0006:12345678`.
    OpenPgp { ident: Option<String> },
}

impl FromStr for KeySpec {
    type Err = Report;

    fn from_str(s: &str) -> Result<Self, Report> {
        let (kind, rest) = match s.split_once(':') {
            Some(parts) => parts,
            None if s == "openpgp" => ("openpgp", ""),
            None => ("soft", s),
        };
        match kind {
            "soft" => Ok(KeySpec::Soft(rest.into())),
            "piv" => {
                let (slot, serial) = match rest.split_once('@') {
                    Some((slot, serial)) => (
                        slot,
                        Some(serial.parse().context("invalid YubiKey serial")?),
                    ),
                    None => (rest, None),
                };
                let slot =
                    u8::from_str_radix(slot, 16).context("PIV slot must be hex, e.g. 9c or 82")?;
                Ok(KeySpec::Piv { slot, serial })
            }
            "openpgp" => Ok(KeySpec::OpenPgp {
                ident: (!rest.is_empty() && rest != "openpgp").then(|| rest.to_string()),
            }),
            "tpm" => bail!("key backend `tpm` is not implemented yet"),
            other => bail!("unknown key backend `{other}` (expected soft:, piv:, openpgp:, tpm:)"),
        }
    }
}

impl KeySpec {
    pub fn open(&self) -> Result<Box<dyn Signer>, Report> {
        match self {
            KeySpec::Soft(path) => Ok(Box::new(
                soft::SoftSigner::load(path).attach(format!("key file: {}", path.display()))?,
            )),
            #[cfg(feature = "piv")]
            KeySpec::Piv { slot, serial } => Ok(Box::new(piv::PivSigner::open(*slot, *serial)?)),
            #[cfg(not(feature = "piv"))]
            KeySpec::Piv { .. } => {
                bail!("this build has no YubiKey PIV support (build with --features piv)")
            }
            #[cfg(feature = "openpgp")]
            KeySpec::OpenPgp { ident } => {
                Ok(Box::new(openpgp::OpenPgpSigner::open(ident.as_deref())?))
            }
            #[cfg(not(feature = "openpgp"))]
            KeySpec::OpenPgp { .. } => {
                bail!("this build has no OpenPGP card support (build with --features openpgp)")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_text_roundtrip() {
        let s = soft::SoftSigner::generate();
        let pk = s.public_key();
        let text = pk.to_string();
        assert!(text.starts_with("ed25519:"));
        assert_eq!(text.parse::<PublicKey>().unwrap(), pk);
    }

    #[test]
    fn pubkey_postcard_roundtrip() {
        let pk = soft::SoftSigner::generate().public_key();
        let bytes = postcard::to_stdvec(&pk).unwrap();
        assert_eq!(postcard::from_bytes::<PublicKey>(&bytes).unwrap(), pk);
    }

    #[test]
    fn domain_separation() {
        let s = soft::SoftSigner::generate();
        let sig = s.sign_domain(b"a", b"msg").unwrap();
        s.public_key().verify(b"a", b"msg", &sig).unwrap();
        let err = s.public_key().verify(b"b", b"msg", &sig).unwrap_err();
        assert_eq!(err.current_context(), &SigError::Invalid);
        assert!(s.public_key().verify(b"a", b"msG", &sig).is_err());
    }

    #[test]
    fn p256_verify() {
        use p256::ecdsa::signature::Signer as _;
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let vk = sk.verifying_key().to_sec1_point(true);
        let pk = PublicKey::new(SigAlg::EcdsaP256, vk.as_bytes().to_vec()).unwrap();
        let sig: p256::ecdsa::Signature = sk.sign(&signed_message(b"d", b"m"));
        let sig = Signature::new(SigAlg::EcdsaP256, sig.to_bytes().to_vec());
        pk.verify(b"d", b"m", &sig).unwrap();
        assert!(pk.verify(b"d", b"x", &sig).is_err());
    }

    #[test]
    fn key_specs() {
        assert_eq!(
            "piv:82".parse::<KeySpec>().unwrap(),
            KeySpec::Piv {
                slot: 0x82,
                serial: None
            }
        );
        assert_eq!(
            "piv:9c@123".parse::<KeySpec>().unwrap(),
            KeySpec::Piv {
                slot: 0x9c,
                serial: Some(123)
            }
        );
        assert_eq!(
            "openpgp".parse::<KeySpec>().unwrap(),
            KeySpec::OpenPgp { ident: None }
        );
        assert_eq!(
            "openpgp:0006:1234".parse::<KeySpec>().unwrap(),
            KeySpec::OpenPgp {
                ident: Some("0006:1234".into())
            }
        );
        assert_eq!("/k".parse::<KeySpec>().unwrap(), KeySpec::Soft("/k".into()));
        assert!("piv:zz".parse::<KeySpec>().is_err());
        assert!("tpm:1".parse::<KeySpec>().is_err());
    }

    #[test]
    fn signed_message_is_fixed_size() {
        let small = signed_message(b"d", b"x");
        let big = signed_message(b"d", &vec![7u8; 1 << 20]);
        assert_eq!(small.len(), big.len());
        assert_ne!(small, big);
        assert!(small.starts_with(b"d\0"));
    }

    #[test]
    fn rejects_bad_text() {
        assert!("nope".parse::<PublicKey>().is_err());
        assert!("rsa:00".parse::<PublicKey>().is_err());
        assert!("ed25519:00".parse::<PublicKey>().is_err());
    }
}
