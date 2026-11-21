use std::sync::{Arc, Mutex};

use rootcause::prelude::*;
use serde::Serialize;
use serde::de::DeserializeOwned;
use snow::TransportState;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const MAX_FRAME: usize = 65535;
const TAG: usize = 16;
pub const MAX_MESSAGE: usize = 2 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Initiator,
    Responder,
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &[u8]) -> Result<(), Report> {
    let len = u16::try_from(frame.len()).map_err(|_| report!("noise frame too large"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(frame).await?;
    Ok(())
}

// Ok(None) on a clean EOF at a frame boundary.
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>, Report> {
    // EOF is only clean on a frame boundary; after one length byte it's a truncation.
    let mut len = [0u8; 2];
    if r.read(&mut len[..1]).await? == 0 {
        return Ok(None);
    }
    r.read_exact(&mut len[1..])
        .await
        .context("truncated noise frame")?;
    let mut frame = vec![0u8; u16::from_be_bytes(len) as usize];
    r.read_exact(&mut frame)
        .await
        .context("truncated noise frame")?;
    Ok(Some(frame))
}

pub struct Established<S> {
    pub reader: SecureReader<ReadHalf<S>>,
    pub writer: SecureWriter<WriteHalf<S>>,
    pub remote_static: [u8; 32],
    // Identical on both ends of a session, so both can rank sessions the same way.
    pub hash: [u8; 32],
}

pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    side: Side,
    local_static: &[u8; 32],
    prologue: &[u8],
) -> Result<Established<S>, Report> {
    let builder = snow::Builder::new(PATTERN.parse().expect("valid noise pattern"))
        .local_private_key(local_static)?
        .prologue(prologue)?;
    let mut hs = match side {
        Side::Initiator => builder.build_initiator()?,
        Side::Responder => builder.build_responder()?,
    };
    let mut buf = vec![0u8; MAX_FRAME];
    let mut scratch = vec![0u8; MAX_FRAME];
    // XX: -> e, <- e ee s es, -> s se
    let mut our_turn = side == Side::Initiator;
    while !hs.is_handshake_finished() {
        if our_turn {
            let n = hs.write_message(&[], &mut buf)?;
            write_frame(&mut stream, &buf[..n]).await?;
            stream.flush().await?;
        } else {
            let frame = read_frame(&mut stream)
                .await?
                .ok_or_else(|| report!("peer closed during handshake"))?;
            hs.read_message(&frame, &mut scratch)
                .context("noise handshake failed (wrong network?)")?;
        }
        our_turn = !our_turn;
    }
    let remote: [u8; 32] = hs
        .get_remote_static()
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| report!("noise handshake produced no remote static key"))?;
    let hash: [u8; 32] = hs
        .get_handshake_hash()
        .try_into()
        .map_err(|_| report!("unexpected noise handshake hash length"))?;
    let noise = Arc::new(Mutex::new(hs.into_transport_mode()?));
    let (r, w) = tokio::io::split(stream);
    Ok(Established {
        reader: SecureReader {
            r,
            noise: noise.clone(),
            buf: Vec::new(),
            scratch: vec![0u8; MAX_FRAME],
        },
        writer: SecureWriter {
            w,
            noise,
            scratch: vec![0u8; MAX_FRAME],
        },
        remote_static: remote,
        hash,
    })
}

pub struct SecureReader<R> {
    r: R,
    noise: Arc<Mutex<TransportState>>,
    buf: Vec<u8>,
    scratch: Vec<u8>,
}

impl<R: AsyncRead + Unpin> SecureReader<R> {
    async fn fill(&mut self, want: usize) -> Result<bool, Report> {
        while self.buf.len() < want {
            let Some(frame) = read_frame(&mut self.r).await? else {
                if self.buf.is_empty() {
                    return Ok(false);
                }
                bail!("connection closed mid-message");
            };
            let n = self
                .noise
                .lock()
                .unwrap()
                .read_message(&frame, &mut self.scratch)
                .context("failed to decrypt control frame")?;
            self.buf.extend_from_slice(&self.scratch[..n]);
        }
        Ok(true)
    }

    pub async fn recv<T: DeserializeOwned>(&mut self) -> Result<Option<T>, Report> {
        if !self.fill(4).await? {
            return Ok(None);
        }
        let len = u32::from_be_bytes(self.buf[..4].try_into().unwrap()) as usize;
        if len > MAX_MESSAGE {
            bail!("control message of {len} bytes exceeds limit");
        }
        if !self.fill(4 + len).await? {
            bail!("connection closed mid-message");
        }
        let msg =
            postcard::from_bytes(&self.buf[4..4 + len]).context("malformed control message")?;
        self.buf.drain(..4 + len);
        Ok(Some(msg))
    }
}

pub struct SecureWriter<W> {
    w: W,
    noise: Arc<Mutex<TransportState>>,
    scratch: Vec<u8>,
}

impl<W: AsyncWrite + Unpin> SecureWriter<W> {
    pub async fn send<T: Serialize>(&mut self, msg: &T) -> Result<(), Report> {
        let body = postcard::to_stdvec(msg).context("failed to encode control message")?;
        if body.len() > MAX_MESSAGE {
            bail!("control message of {} bytes exceeds limit", body.len());
        }
        let mut plain = (body.len() as u32).to_be_bytes().to_vec();
        plain.extend_from_slice(&body);
        for chunk in plain.chunks(MAX_FRAME - TAG) {
            let n = self
                .noise
                .lock()
                .unwrap()
                .write_message(chunk, &mut self.scratch)?;
            write_frame(&mut self.w, &self.scratch[..n]).await?;
        }
        self.w.flush().await?;
        Ok(())
    }

    pub async fn close(&mut self) {
        let _ = self.w.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> ([u8; 32], [u8; 32]) {
        let s = x25519_dalek::StaticSecret::from([b; 32]);
        (s.to_bytes(), x25519_dalek::PublicKey::from(&s).to_bytes())
    }

    #[tokio::test]
    async fn roundtrip_large_and_auth() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (ka, pa) = key(1);
        let (kb, pb) = key(2);
        let (ra, rb) = tokio::join!(
            handshake(a, Side::Initiator, &ka, b"p"),
            handshake(b, Side::Responder, &kb, b"p")
        );
        let ea = ra.unwrap();
        let eb = rb.unwrap();
        assert_eq!(ea.remote_static, pb);
        assert_eq!(eb.remote_static, pa);
        assert_eq!(ea.hash, eb.hash, "both ends see the same handshake hash");
        let (mut ra, mut wa) = (ea.reader, ea.writer);
        let (mut rb, mut wb) = (eb.reader, eb.writer);

        let big: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
        let send = async {
            wa.send(&big).await.unwrap();
            wa.send(&"second").await.unwrap();
            wa.close().await;
        };
        let recv = async {
            let got: Vec<u8> = rb.recv().await.unwrap().unwrap();
            let s: String = rb.recv().await.unwrap().unwrap();
            assert!(rb.recv::<String>().await.unwrap().is_none());
            (got, s)
        };
        let (_, (got, s)) = tokio::join!(send, recv);
        assert!(got == big);
        assert_eq!(s, "second");
        wb.send(&1u8).await.unwrap();
        assert_eq!(ra.recv::<u8>().await.unwrap(), Some(1));
    }

    #[tokio::test]
    async fn prologue_mismatch_fails() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (ka, _) = key(1);
        let (kb, _) = key(2);
        let (ra, rb) = tokio::join!(
            handshake(a, Side::Initiator, &ka, b"net-a"),
            handshake(b, Side::Responder, &kb, b"net-b")
        );
        assert!(ra.is_err() || rb.is_err());
    }
}
