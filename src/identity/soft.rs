use std::io::Write;
use std::path::Path;

use ed25519_dalek::Signer as _;
use rootcause::prelude::*;

use super::{PublicKey, SigAlg, Signature, Signer};

pub struct SoftSigner {
    key: ed25519_dalek::SigningKey,
}

impl SoftSigner {
    pub fn generate() -> Self {
        Self::from_seed(rand::random())
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        SoftSigner {
            key: ed25519_dalek::SigningKey::from_bytes(&seed),
        }
    }

    pub fn load(path: &Path) -> Result<Self, Report> {
        let text = std::fs::read_to_string(path).context("failed to read key file")?;
        let bytes = hex::decode(text.trim()).context("key file is not valid hex")?;
        let seed: [u8; 32] = bytes
            .try_into()
            .map_err(|_| report!("key file must contain exactly 32 bytes"))?;
        Ok(Self::from_seed(seed))
    }

    pub fn save(&self, path: &Path) -> Result<(), Report> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(path)
            .context("failed to create key file")
            .attach(format!("path: {}", path.display()))?;
        writeln!(f, "{}", hex::encode(self.key.to_bytes())).context("failed to write key file")?;
        Ok(())
    }
}

impl Signer for SoftSigner {
    fn public_key(&self) -> PublicKey {
        PublicKey::ed25519(self.key.verifying_key().to_bytes())
            .expect("dalek produced an invalid public key")
    }

    fn sign_raw(&self, data: &[u8]) -> Result<Signature, Report> {
        Ok(Signature::new(
            SigAlg::Ed25519,
            self.key.sign(data).to_bytes().to_vec(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.key");
        let s = SoftSigner::generate();
        s.save(&path).unwrap();
        assert!(s.save(&path).is_err(), "must not overwrite");
        let l = SoftSigner::load(&path).unwrap();
        assert_eq!(s.public_key(), l.public_key());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
