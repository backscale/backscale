// CLI side of YubiKey enrollment (`enroll`, `card show`, `join --card`).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use backscale::config::StateDir;
use backscale::identity::KeySpec;
use rootcause::prelude::*;

#[cfg_attr(not(feature = "piv"), allow(dead_code))]
pub struct EnrollArgs {
    pub slot: String,
    pub network_key: KeySpec,
    pub name: String,
    pub peers: Vec<SocketAddr>,
    pub draft: PathBuf,
    pub out: PathBuf,
    pub validity: Duration,
    pub regenerate: bool,
    pub touch: String,
    pub with_manifest: bool,
}

#[cfg_attr(not(feature = "piv"), allow(dead_code))]
fn parse_slot(slot: &str) -> Result<u8, Report> {
    Ok(u8::from_str_radix(slot, 16).context("PIV slot must be hex, e.g. 82")?)
}

#[cfg(not(feature = "piv"))]
mod imp {
    use super::*;

    fn unsupported() -> Report {
        report!("this build has no YubiKey support (build with --features piv)")
    }

    pub fn enroll(_: EnrollArgs) -> Result<(), Report> {
        Err(unsupported())
    }

    pub fn show(_: &str) -> Result<(), Report> {
        Err(unsupported())
    }

    pub fn join(
        _: &str,
        _: StateDir,
        _: SocketAddr,
        _: Vec<SocketAddr>,
        _: bool,
    ) -> Result<(), Report> {
        Err(unsupported())
    }
}

#[cfg(feature = "piv")]
mod imp {
    use super::*;
    use atomic_write_file::AtomicWriteFile;
    use backscale::config::Config;
    use backscale::enroll::{EnrollmentRecord, RECORD_VERSION};
    use backscale::identity::Signer;
    use backscale::identity::piv::{self, PivSigner};
    use backscale::manifest::ManifestDraft;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn enroll(a: EnrollArgs) -> Result<(), Report> {
        let slot = parse_slot(&a.slot)?;
        let network = a
            .network_key
            .open()
            .context("failed to open the network key")?;
        let mut draft = ManifestDraft::load(&a.draft)?;
        if draft.network_key != network.public_key() {
            bail!("{} belongs to a different network key", a.draft.display());
        }

        let serial = piv::card_serial(None)?;
        let mgm = piv::mgm_from_env()?;
        let generate = |what: &str| -> Result<_, Report> {
            println!("{what} a P-256 key in PIV slot {slot:02x}");
            PivSigner::generate(
                slot,
                Some(serial),
                piv::parse_touch(&a.touch)?,
                mgm.as_deref(),
                a.regenerate,
            )
        };
        let state = piv::slot_state(slot, Some(serial))?;
        let current = match &state {
            piv::SlotState::P256(key) => Some(key.clone()),
            _ => None,
        };
        // Check the draft before touching the card: failing after a
        // regeneration would leave the old key destroyed.
        if let Some(m) = draft.members.iter().find(|m| m.name == a.name)
            && Some(&m.identity) != current.as_ref()
        {
            bail!("`{}` is already a member with a different key", a.name);
        }
        if let Some(key) = &current
            && let Some(m) = draft.members.iter().find(|m| &m.identity == key)
            && m.name != a.name
        {
            bail!(
                "this card's key is already member `{}`; enroll with --name {0} to re-key it",
                m.name
            );
        }

        let identity = match state {
            piv::SlotState::P256(key) if !a.regenerate => {
                println!("reusing the key in PIV slot {slot:02x}");
                key
            }
            piv::SlotState::Other(alg) if !a.regenerate => {
                bail!("PIV slot {slot:02x} holds a {alg} key; pass --regenerate to replace it")
            }
            piv::SlotState::Empty => generate("generating")?,
            _ => generate("replacing the key with")?,
        };

        match draft.members.iter_mut().find(|m| m.name == a.name) {
            Some(m) if m.identity == identity => println!("{} is already a member", a.name),
            Some(m) => {
                m.identity = identity.clone();
                println!("re-keyed {} ({}, {})", m.name, m.ipv4, m.ipv6);
            }
            None => {
                let m = draft
                    .add_member(identity.clone(), a.name.clone(), None, None, vec![])
                    .context("failed to add member")?;
                println!("added {} ({}, {})", m.name, m.ipv4, m.ipv6);
            }
        }
        let manifest = draft.next_manifest(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            a.validity.as_secs(),
        );
        let signed = manifest.sign(network.as_ref())?;
        let mut f = AtomicWriteFile::open(&a.out).context("failed to write signed manifest")?;
        f.write_all(&signed.to_bytes())?;
        f.commit()?;
        draft.save(&a.draft)?;

        let mut rec = EnrollmentRecord {
            version: RECORD_VERSION,
            network_key: network.public_key(),
            network_name: draft.name.clone(),
            node_name: a.name.clone(),
            peers: a.peers,
            manifest: a.with_manifest.then(|| signed.clone()),
        };
        if rec.manifest.is_some() && rec.to_bytes().len() > piv::MAX_ENROLLMENT_BYTES {
            eprintln!(
                "warning: the manifest is too large for the card; storing the enrollment without it"
            );
            rec.manifest = None;
        }
        let subject = format!("backscale {} {}", rec.network_name, rec.node_name);
        piv::write_enrollment(
            slot,
            Some(serial),
            &subject,
            &rec.to_bytes(),
            mgm.as_deref(),
        )?;
        println!(
            "card {serial} enrolled as `{}` in `{}`",
            a.name, rec.network_name
        );
        println!("net id:   {}", rec.net_id());
        println!(
            "manifest: seq {} written to {}",
            manifest.seq,
            a.out.display()
        );
        println!("publish it with: backscale net publish {}", a.out.display());
        Ok(())
    }

    fn read(slot: u8) -> Result<(u32, EnrollmentRecord, PivSigner), Report> {
        let serial = piv::card_serial(None)?;
        let bytes = piv::read_enrollment(slot, Some(serial))?.ok_or_else(|| {
            report!("YubiKey {serial} has no backscale enrollment in PIV slot {slot:02x}")
        })?;
        let rec = EnrollmentRecord::from_bytes(&bytes)?;
        let signer = PivSigner::open(slot, Some(serial))?;
        Ok((serial, rec, signer))
    }

    pub fn show(slot: &str) -> Result<(), Report> {
        let slot = parse_slot(slot)?;
        let (serial, rec, signer) = read(slot)?;
        println!("card:     YubiKey {serial}, PIV slot {slot:02x}");
        println!("network:  {} ({})", rec.network_name, rec.network_key);
        println!("net id:   {}", rec.net_id());
        println!("node:     {} ({})", rec.node_name, signer.public_key());
        for p in &rec.peers {
            println!("peer:     {p}");
        }
        match rec.check(
            &signer.public_key(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ) {
            Ok(Some(m)) => {
                let me = m.member(&signer.public_key()).expect("checked");
                println!(
                    "manifest: seq {}, {} members, expires {}; overlay {} {}",
                    m.seq,
                    m.members.len(),
                    humantime::format_rfc3339_seconds(
                        UNIX_EPOCH + Duration::from_secs(m.expires_at)
                    ),
                    me.ipv4,
                    me.ipv6
                );
            }
            Ok(None) => println!("manifest: not stored on the card"),
            Err(e) => println!("manifest: unusable ({e})"),
        }
        Ok(())
    }

    pub fn join(
        slot: &str,
        dir: StateDir,
        listen: SocketAddr,
        extra_peers: Vec<SocketAddr>,
        dht: bool,
    ) -> Result<(), Report> {
        let slot = parse_slot(slot)?;
        if dir.config().exists() {
            bail!("{} already exists", dir.config().display());
        }
        let (serial, rec, signer) = read(slot)?;
        let identity = signer.public_key();
        std::fs::create_dir_all(&dir.0)
            .context("failed to create state directory")
            .attach(format!("path: {}", dir.0.display()))?;

        let overlay = match rec.check(
            &identity,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ) {
            Ok(Some(m)) => {
                let signed = rec.manifest.as_ref().expect("checked");
                let mut f =
                    AtomicWriteFile::open(dir.manifest()).context("failed to write manifest")?;
                f.write_all(&signed.to_bytes())?;
                f.commit()?;
                m.member(&identity).map(|me| (me.ipv4, me.ipv6))
            }
            Ok(None) => None,
            Err(e) => {
                eprintln!(
                    "warning: the manifest on the card is unusable ({e}); it will be fetched from peers"
                );
                None
            }
        };

        let mut peers = rec.peers.clone();
        for p in extra_peers {
            if !peers.contains(&p) {
                peers.push(p);
            }
        }
        let config = Config {
            network_key: rec.network_key.clone(),
            identity: format!("piv:{slot:02x}@{serial}"),
            listen,
            peers,
            dht,
            tun: true,
            tun_name: "backscale0".into(),
        };
        config.save(&dir.config())?;

        println!(
            "joined `{}` as `{}` using YubiKey {serial}",
            rec.network_name, rec.node_name
        );
        println!("net id:   {}", rec.net_id());
        println!("          check this with your network admin: the card alone can't prove it");
        println!("identity: {identity}");
        if let Some((v4, v6)) = overlay {
            println!("overlay:  {v4} {v6}");
        }
        println!(
            "the daemon needs the PIV PIN: set BACKSCALE_PIN or BACKSCALE_PIN_FILE for `backscale up`"
        );
        Ok(())
    }
}

pub use imp::{enroll, join, show};
