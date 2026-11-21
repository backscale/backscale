// OpenPGP card (e.g. YubiKey OpenPGP applet) Ed25519 signing key. The card
// computes EdDSA over the bytes it is given, which signed_message keeps short.

use card_backend::CardBackend;
use card_backend_pcsc::PcscBackend;
use openpgp_card::Card;
use openpgp_card::ocard::KeyType;
use openpgp_card::ocard::algorithm::{AlgorithmAttributes, Curve};
use openpgp_card::ocard::crypto::PublicKeyMaterial;
use openpgp_card::state::Open;
use rootcause::prelude::*;

use super::pin::{PinCache, touch_notice};
use super::{PublicKey, SigAlg, Signature, Signer};

fn card_err(e: impl std::fmt::Display) -> Report {
    report!("OpenPGP card error: {e}")
}

fn open_card(ident: Option<&str>) -> Result<Card<Open>, Report> {
    let cards = PcscBackend::cards(None)
        .map_err(card_err)
        .context("failed to list smart cards (is pcscd running?)")?
        .map(|c| c.map(|b| -> Box<dyn CardBackend + Send + Sync> { b.into() }));
    match ident {
        Some(ident) => Ok(Card::<Open>::open_by_ident(cards, ident)
            .map_err(card_err)
            .attach(format!("card: {ident}"))?),
        None => {
            for backend in cards.flatten() {
                if let Ok(card) = Card::<Open>::new(backend) {
                    return Ok(card);
                }
            }
            bail!("no OpenPGP card found")
        }
    }
}

pub struct OpenPgpSigner {
    ident: String,
    public: PublicKey,
    touch: bool,
    pin: PinCache,
}

impl OpenPgpSigner {
    pub fn open(ident: Option<&str>) -> Result<Self, Report> {
        let mut card = open_card(ident)?;
        let mut tx = card.transaction().map_err(card_err)?;
        let ident = tx.application_identifier().map_err(card_err)?.ident();
        if tx
            .fingerprint(KeyType::Signing)
            .map_err(card_err)?
            .is_none()
        {
            bail!(
                "OpenPGP card {ident} has no signing key (load or generate an Ed25519 key first)"
            );
        }
        let material = tx
            .public_key_material(KeyType::Signing)
            .map_err(card_err)
            .context("card has no signing key")
            .attach(format!("card: {ident}"))?;
        let PublicKeyMaterial::E(ecc) = material else {
            bail!("the card's signing key is RSA; only Ed25519 is supported");
        };
        let AlgorithmAttributes::Ecc(attrs) = ecc.algo() else {
            bail!("unexpected algorithm attributes for the card's signing key");
        };
        if *attrs.curve() != Curve::Ed25519 {
            bail!(
                "the card's signing key uses {:?}; only Ed25519 is supported",
                attrs.curve()
            );
        }
        // Some cards prefix the point with 0x40 (native compressed format).
        let raw = ecc.data();
        let raw = if raw.len() == 33 && raw[0] == 0x40 {
            &raw[1..]
        } else {
            raw
        };
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| report!("card returned a {}-byte Ed25519 key", raw.len()))?;
        let touch = tx
            .user_interaction_flag(KeyType::Signing)
            .ok()
            .flatten()
            .is_some_and(|f| f.touch_policy().touch_required());
        Ok(OpenPgpSigner {
            ident,
            public: PublicKey::ed25519(bytes)?,
            touch,
            pin: PinCache::default(),
        })
    }

    pub fn ident(&self) -> &str {
        &self.ident
    }
}

impl Signer for OpenPgpSigner {
    fn public_key(&self) -> PublicKey {
        self.public.clone()
    }

    fn sign_raw(&self, data: &[u8]) -> Result<Signature, Report> {
        let pin = self.pin.get("OpenPGP card user")?;
        let mut card = open_card(Some(&self.ident))?;
        let mut tx = card.transaction().map_err(card_err)?;
        if let Err(e) = tx.verify_user_signing_pin(pin.to_string().into()) {
            use openpgp_card::ocard::StatusBytes;
            // Transport hiccups must not mark a good PIN as bad.
            if matches!(
                e,
                openpgp_card::Error::CardStatus(
                    StatusBytes::PasswordNotChecked(_)
                        | StatusBytes::SecurityStatusNotSatisfied
                        | StatusBytes::AuthenticationMethodBlocked
                )
            ) {
                self.pin.rejected(&pin);
            }
            return Err(card_err(e)
                .context("OpenPGP user PIN rejected")
                .into_dynamic());
        }
        self.pin.accepted(pin);
        if self.touch {
            touch_notice("OpenPGP card");
        }
        let sig = tx
            .card()
            .pso_compute_digital_signature(data.to_vec())
            .map_err(card_err)
            .context("OpenPGP signing failed")?;
        if sig.len() != 64 {
            bail!("card returned a {}-byte signature, expected 64", sig.len());
        }
        Ok(Signature::new(SigAlg::Ed25519, sig))
    }
}
