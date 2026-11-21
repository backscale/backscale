// YubiKey PIV identity keys. Firmware before 5.7 has no Ed25519 in PIV, so
// keys here are ECDSA P-256; the card signs a SHA-256 digest of our message.

use rootcause::prelude::*;
use sha2::Digest;
use yubikey::certificate::Certificate;
use yubikey::piv::{self, AlgorithmId, ManagementAlgorithmId, SlotId};
use yubikey::{MgmKey, PinPolicy, Serial, TouchPolicy, YubiKey};

use super::pin::{PinCache, read_pin, touch_notice};
use super::{PublicKey, SigAlg, Signature, Signer};

fn card_err(e: yubikey::Error) -> Report {
    report!("YubiKey PIV error: {e}")
}

fn connect(serial: Option<u32>) -> Result<YubiKey, Report> {
    let yk = match serial {
        Some(s) => YubiKey::open_by_serial(Serial(s)),
        None => YubiKey::open(),
    };
    Ok(yk
        .map_err(card_err)
        .context("failed to open YubiKey (is pcscd running?)")?)
}

fn slot_id(slot: u8) -> Result<SlotId, Report> {
    SlotId::try_from(slot).map_err(|_| report!("{slot:02x} is not a PIV key slot"))
}

fn p256_key(spki_point: &[u8]) -> Result<PublicKey, Report> {
    let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(spki_point)
        .map_err(|_| report!("card returned an invalid P-256 public key"))?;
    Ok(PublicKey::new(
        SigAlg::EcdsaP256,
        vk.to_sec1_point(true).as_bytes().to_vec(),
    )?)
}

pub enum SlotState {
    Empty,
    P256(PublicKey),
    // A key we can't use (another algorithm), described for the error message.
    Other(String),
}

// Reading a slot's metadata needs firmware 5.3+; an empty slot answers with a
// generic error, which older firmware also gives for populated slots.
pub fn slot_state(slot: u8, serial: Option<u32>) -> Result<SlotState, Report> {
    let mut yk = connect(serial)?;
    let v = yk.version();
    if (v.major, v.minor) < (5, 3) {
        bail!(
            "YubiKey firmware {}.{}.{} can't report slot contents (needs 5.3+)",
            v.major,
            v.minor,
            v.patch
        );
    }
    match piv::metadata(&mut yk, slot_id(slot)?) {
        Ok(meta) if meta.algorithm == ManagementAlgorithmId::Asymmetric(AlgorithmId::EccP256) => {
            let spki = meta
                .public
                .ok_or_else(|| report!("card did not report the slot's public key"))?;
            Ok(SlotState::P256(p256_key(
                spki.subject_public_key.raw_bytes(),
            )?))
        }
        Ok(meta) => Ok(SlotState::Other(format!("{:?}", meta.algorithm))),
        Err(yubikey::Error::GenericError) => Ok(SlotState::Empty),
        Err(e) => Err(card_err(e)
            .context("failed to read PIV slot metadata")
            .into_dynamic()),
    }
}

pub fn parse_touch(s: &str) -> Result<TouchPolicy, Report> {
    Ok(match s {
        "never" => TouchPolicy::Never,
        "always" => TouchPolicy::Always,
        "cached" => TouchPolicy::Cached,
        other => bail!("unknown touch policy `{other}` (never, always, cached)"),
    })
}

// BACKSCALE_PIV_MGM (hex), or None for the factory default.
pub fn mgm_from_env() -> Result<Option<Vec<u8>>, Report> {
    match std::env::var("BACKSCALE_PIV_MGM") {
        Ok(h) => Ok(Some(
            hex::decode(h.trim()).context("BACKSCALE_PIV_MGM must be hex")?,
        )),
        Err(_) => Ok(None),
    }
}

pub struct PivSigner {
    slot: u8,
    serial: Option<u32>,
    public: PublicKey,
    touch: bool,
    pin: PinCache,
}

impl PivSigner {
    pub fn open(slot: u8, serial: Option<u32>) -> Result<Self, Report> {
        let mut yk = connect(serial)?;
        let meta = piv::metadata(&mut yk, slot_id(slot)?)
            .map_err(card_err)
            .context("no key in that PIV slot")
            .attach(format!("slot: {slot:02x}"))?;
        if meta.algorithm != ManagementAlgorithmId::Asymmetric(AlgorithmId::EccP256) {
            bail!(
                "PIV slot {slot:02x} holds a {:?} key; only ECDSA P-256 is supported",
                meta.algorithm
            );
        }
        let spki = meta
            .public
            .ok_or_else(|| report!("card did not report the slot's public key"))?;
        let public = p256_key(spki.subject_public_key.raw_bytes())?;
        let touch = matches!(
            meta.policy,
            Some((_, TouchPolicy::Always | TouchPolicy::Cached))
        );
        Ok(PivSigner {
            slot,
            serial: Some(yk.serial().0),
            public,
            touch,
            pin: PinCache::default(),
        })
    }

    // Generates a P-256 key on the card. Refuses to replace an existing key
    // unless `force` is set.
    pub fn generate(
        slot: u8,
        serial: Option<u32>,
        touch: TouchPolicy,
        mgm: Option<&[u8]>,
        force: bool,
    ) -> Result<PublicKey, Report> {
        let mut yk = connect(serial)?;
        let id = slot_id(slot)?;
        if !force && piv::metadata(&mut yk, id).is_ok() {
            bail!("PIV slot {slot:02x} already holds a key; pass --force to replace it");
        }
        let key = match mgm {
            Some(bytes) => MgmKey::from_bytes(bytes).map_err(card_err)?,
            None => MgmKey::default(),
        };
        yk.authenticate(key)
            .map_err(card_err)
            .context("PIV management key rejected")?;
        let spki = piv::generate(&mut yk, id, AlgorithmId::EccP256, PinPolicy::Default, touch)
            .map_err(card_err)
            .context("key generation failed")?;
        p256_key(spki.subject_public_key.raw_bytes())
    }
}

impl Signer for PivSigner {
    fn public_key(&self) -> PublicKey {
        self.public.clone()
    }

    fn sign_raw(&self, data: &[u8]) -> Result<Signature, Report> {
        let pin = self.pin.get("YubiKey PIV")?;
        let mut yk = connect(self.serial)?;
        if let Err(e) = yk.verify_pin(pin.as_bytes()) {
            // Transport hiccups must not mark a good PIN as bad.
            if matches!(
                e,
                yubikey::Error::WrongPin { .. } | yubikey::Error::PinLocked
            ) {
                self.pin.rejected(&pin);
            }
            return Err(card_err(e).context("PIV PIN rejected").into_dynamic());
        }
        self.pin.accepted(pin);
        if self.touch {
            touch_notice("YubiKey");
        }
        let digest = sha2::Sha256::digest(data);
        let der = piv::sign_data(&mut yk, &digest, AlgorithmId::EccP256, slot_id(self.slot)?)
            .map_err(card_err)
            .context("PIV signing failed")?;
        let sig = p256::ecdsa::Signature::from_der(&der)
            .map_err(|_| report!("card returned a malformed ECDSA signature"))?;
        Ok(Signature::new(SigAlg::EcdsaP256, sig.to_bytes().to_vec()))
    }
}

// The enrollment record rides in a private extension of a self-signed X.509
// certificate for the slot's key, so other PIV tools still see a valid cert.
// PEN 32473 is reserved for examples (RFC 5612); register a real PEN before release.
const ENROLL_OID: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.4280.1");

struct EnrollExt(der::asn1::OctetString);

impl const_oid::AssociatedOid for EnrollExt {
    const OID: const_oid::ObjectIdentifier = ENROLL_OID;
}

impl der::Encode for EnrollExt {
    fn encoded_len(&self) -> der::Result<der::Length> {
        self.0.encoded_len()
    }

    fn encode(&self, w: &mut impl der::Writer) -> der::Result<()> {
        self.0.encode(w)
    }
}

impl x509_cert::ext::AsExtension for EnrollExt {
    fn critical(&self, _: &x509_cert::name::Name, _: &[x509_cert::ext::Extension]) -> bool {
        false
    }
}

// A PIV data object holds ~3 KB; leave room for the certificate around the payload.
pub const MAX_ENROLLMENT_BYTES: usize = 2400;

// Needs the PIN (the card self-signs the certificate with the slot's key)
// and the management key (writing the certificate object).
pub fn write_enrollment(
    slot: u8,
    serial: Option<u32>,
    subject: &str,
    payload: &[u8],
    mgm: Option<&[u8]>,
) -> Result<(), Report> {
    if payload.len() > MAX_ENROLLMENT_BYTES {
        bail!(
            "enrollment record is {} bytes, the card holds at most {MAX_ENROLLMENT_BYTES}",
            payload.len()
        );
    }
    use std::str::FromStr;
    let mut yk = connect(serial)?;
    let id = slot_id(slot)?;
    let meta = piv::metadata(&mut yk, id)
        .map_err(card_err)
        .context("no key in that PIV slot")?;
    let spki = meta
        .public
        .ok_or_else(|| report!("card did not report the slot's public key"))?;
    let key = match mgm {
        Some(bytes) => MgmKey::from_bytes(bytes).map_err(card_err)?,
        None => MgmKey::default(),
    };
    yk.authenticate(key)
        .map_err(card_err)
        .context("PIV management key rejected")?;
    let pin = read_pin("YubiKey PIV")?;
    yk.verify_pin(pin.as_bytes())
        .map_err(card_err)
        .context("PIV PIN rejected")?;
    let ext = EnrollExt(der::asn1::OctetString::new(payload).map_err(|e| report!("{e}"))?);
    let name = x509_cert::name::Name::from_str(&format!("CN={subject}"))
        .map_err(|e| report!("bad subject: {e}"))?;
    let validity =
        x509_cert::time::Validity::from_now(std::time::Duration::from_secs(20 * 365 * 86400))
            .map_err(|e| report!("{e}"))?;
    let serial_no = x509_cert::serial_number::SerialNumber::new(&rand::random::<[u8; 8]>())
        .map_err(|e| report!("{e}"))?;
    Certificate::generate_self_signed::<_, p256_yk::NistP256>(
        &mut yk,
        id,
        serial_no,
        validity,
        name,
        spki,
        |b| {
            b.add_extension(&ext)
                .map_err(|_| der::Error::from(der::ErrorKind::Failed))
        },
    )
    .map_err(card_err)
    .context("failed to write the enrollment certificate")?;
    Ok(())
}

// No PIN needed. Ok(None) when the slot has no backscale certificate.
pub fn read_enrollment(slot: u8, serial: Option<u32>) -> Result<Option<Vec<u8>>, Report> {
    use der::Decode;
    let mut yk = connect(serial)?;
    let Ok(cert) = Certificate::read(&mut yk, slot_id(slot)?) else {
        return Ok(None);
    };
    // A certificate left over from a key that has since been replaced.
    let cert_key = cert
        .cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    let slot_key = piv::metadata(&mut yk, slot_id(slot)?)
        .ok()
        .and_then(|m| m.public)
        .map(|spki| spki.subject_public_key.raw_bytes().to_vec());
    if slot_key.as_deref() != Some(cert_key) {
        return Ok(None);
    }
    let exts = cert.cert.tbs_certificate.extensions.unwrap_or_default();
    let Some(ext) = exts.iter().find(|e| e.extn_id == ENROLL_OID) else {
        return Ok(None);
    };
    let inner = der::asn1::OctetString::from_der(ext.extn_value.as_bytes())
        .map_err(|e| report!("malformed enrollment extension: {e}"))?;
    Ok(Some(inner.into_bytes()))
}

pub fn card_serial(serial: Option<u32>) -> Result<u32, Report> {
    Ok(connect(serial)?.serial().0)
}
