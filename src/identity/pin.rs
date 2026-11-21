use std::io::IsTerminal;

use rootcause::prelude::*;
use zeroize::Zeroizing;

// BACKSCALE_PIN, then BACKSCALE_PIN_FILE, then an interactive prompt.
pub fn read_pin(what: &str) -> Result<Zeroizing<String>, Report> {
    if let Ok(pin) = std::env::var("BACKSCALE_PIN") {
        return Ok(Zeroizing::new(pin));
    }
    if let Ok(path) = std::env::var("BACKSCALE_PIN_FILE") {
        let text = Zeroizing::new(
            std::fs::read_to_string(&path)
                .context("failed to read PIN file")
                .attach(format!("path: {path}"))?,
        );
        return Ok(Zeroizing::new(text.trim().to_string()));
    }
    if std::io::stdin().is_terminal() {
        let pin =
            rpassword::prompt_password(format!("{what} PIN: ")).context("failed to read PIN")?;
        return Ok(Zeroizing::new(pin));
    }
    bail!("{what} PIN needed: set BACKSCALE_PIN or BACKSCALE_PIN_FILE")
}

// Remembers the PIN the card last accepted, and refuses to retry one it
// rejected: every failed attempt burns one of the card's few retries.
#[derive(Default)]
pub struct PinCache {
    state: std::sync::Mutex<(Option<Zeroizing<String>>, Option<blake3::Hash>)>,
}

impl PinCache {
    pub fn get(&self, what: &str) -> Result<Zeroizing<String>, Report> {
        let cached = self.state.lock().unwrap().0.clone();
        let pin = match cached {
            Some(p) => p,
            None => read_pin(what)?,
        };
        if self.state.lock().unwrap().1 == Some(blake3::hash(pin.as_bytes())) {
            bail!("{what} PIN was already rejected by the card; not retrying it");
        }
        Ok(pin)
    }

    pub fn accepted(&self, pin: Zeroizing<String>) {
        *self.state.lock().unwrap() = (Some(pin), None);
    }

    pub fn rejected(&self, pin: &str) {
        *self.state.lock().unwrap() = (None, Some(blake3::hash(pin.as_bytes())));
    }
}

pub fn touch_notice(what: &str) {
    tracing::info!("touch your {what} to confirm the signature");
    if std::io::stderr().is_terminal() {
        eprintln!("touch your {what}...");
    }
}
