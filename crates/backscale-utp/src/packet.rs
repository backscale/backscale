use std::fmt;

pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 20;
const EXT_SACK: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Type {
    Data = 0,
    Fin = 1,
    State = 2,
    Reset = 3,
    Syn = 4,
}

impl Type {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Type::Data,
            1 => Type::Fin,
            2 => Type::State,
            3 => Type::Reset,
            4 => Type::Syn,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub ty: Type,
    pub conn_id: u16,
    pub ts_micros: u32,
    pub ts_diff_micros: u32,
    pub wnd: u32,
    pub seq_nr: u16,
    pub ack_nr: u16,
    pub sack: Option<Vec<u8>>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    TooShort,
    BadVersion(u8),
    BadType(u8),
    BadExtension,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::TooShort => write!(f, "packet too short"),
            DecodeError::BadVersion(v) => write!(f, "unsupported uTP version {v}"),
            DecodeError::BadType(t) => write!(f, "unknown packet type {t}"),
            DecodeError::BadExtension => write!(f, "malformed extension"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl Packet {
    pub fn new(ty: Type, conn_id: u16, seq_nr: u16, ack_nr: u16) -> Self {
        Packet {
            ty,
            conn_id,
            ts_micros: 0,
            ts_diff_micros: 0,
            wnd: 0,
            seq_nr,
            ack_nr,
            sack: None,
            payload: Vec::new(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let sack_len = self.sack.as_ref().map_or(0, |s| 2 + s.len());
        let mut b = Vec::with_capacity(HEADER_LEN + sack_len + self.payload.len());
        b.push(((self.ty as u8) << 4) | VERSION);
        b.push(if self.sack.is_some() { EXT_SACK } else { 0 });
        b.extend_from_slice(&self.conn_id.to_be_bytes());
        b.extend_from_slice(&self.ts_micros.to_be_bytes());
        b.extend_from_slice(&self.ts_diff_micros.to_be_bytes());
        b.extend_from_slice(&self.wnd.to_be_bytes());
        b.extend_from_slice(&self.seq_nr.to_be_bytes());
        b.extend_from_slice(&self.ack_nr.to_be_bytes());
        if let Some(sack) = &self.sack {
            debug_assert!(sack.len() % 4 == 0 && !sack.is_empty() && sack.len() <= 252);
            b.push(0);
            b.push(sack.len() as u8);
            b.extend_from_slice(sack);
        }
        b.extend_from_slice(&self.payload);
        b
    }

    pub fn decode(b: &[u8]) -> Result<Self, DecodeError> {
        let h: &[u8; HEADER_LEN] = b
            .get(..HEADER_LEN)
            .and_then(|h| h.try_into().ok())
            .ok_or(DecodeError::TooShort)?;
        let version = h[0] & 0x0f;
        if version != VERSION {
            return Err(DecodeError::BadVersion(version));
        }
        let ty = Type::from_u8(h[0] >> 4).ok_or(DecodeError::BadType(h[0] >> 4))?;
        let u16_at = |i: usize| u16::from_be_bytes([h[i], h[i + 1]]);
        let u32_at = |i: usize| u32::from_be_bytes([h[i], h[i + 1], h[i + 2], h[i + 3]]);

        let mut sack = None;
        let mut next_ext = h[1];
        let mut rest = &b[HEADER_LEN..];
        while next_ext != 0 {
            let [ext_next, len, tail @ ..] = rest else {
                return Err(DecodeError::BadExtension);
            };
            let len = *len as usize;
            let data = tail.get(..len).ok_or(DecodeError::BadExtension)?;
            if next_ext == EXT_SACK {
                if len == 0 || !len.is_multiple_of(4) {
                    return Err(DecodeError::BadExtension);
                }
                sack = Some(data.to_vec());
            }
            next_ext = *ext_next;
            rest = &tail[len..];
        }

        Ok(Packet {
            ty,
            conn_id: u16_at(2),
            ts_micros: u32_at(4),
            ts_diff_micros: u32_at(8),
            wnd: u32_at(12),
            seq_nr: u16_at(16),
            ack_nr: u16_at(18),
            sack,
            payload: rest.to_vec(),
        })
    }
}

// Sequence numbers wrap at 2^16; compare by signed distance.
pub fn seq_lt(a: u16, b: u16) -> bool {
    (a.wrapping_sub(b) as i16) < 0
}

pub fn seq_le(a: u16, b: u16) -> bool {
    a == b || seq_lt(a, b)
}

// Bit i (LSB first within each byte) of the mask acknowledges ack_nr + 2 + i.
pub fn sack_contains(mask: &[u8], ack_nr: u16, seq: u16) -> bool {
    let idx = seq.wrapping_sub(ack_nr).wrapping_sub(2) as usize;
    mask.get(idx / 8).is_some_and(|b| b & (1 << (idx % 8)) != 0)
}

pub fn sack_build(
    ack_nr: u16,
    received: impl Iterator<Item = u16>,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    let mut mask = vec![0u8; max_bytes];
    let mut any = false;
    let mut highest = 0;
    for seq in received {
        let idx = seq.wrapping_sub(ack_nr).wrapping_sub(2) as usize;
        if idx < max_bytes * 8 {
            mask[idx / 8] |= 1 << (idx % 8);
            highest = highest.max(idx);
            any = true;
        }
    }
    if !any {
        return None;
    }
    mask.truncate((highest / 32 + 1) * 4);
    Some(mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut p = Packet::new(Type::Data, 0x1234, 65535, 7);
        p.ts_micros = 0xdeadbeef;
        p.ts_diff_micros = 42;
        p.wnd = 1 << 20;
        p.payload = b"hello".to_vec();
        let b = p.encode();
        assert_eq!(b[0], 0x01);
        assert_eq!(b.len(), HEADER_LEN + 5);
        assert_eq!(Packet::decode(&b).unwrap(), p);

        p.ty = Type::State;
        p.payload.clear();
        p.sack = Some(vec![0b101, 0, 0, 0x80]);
        let b = p.encode();
        assert_eq!(b[0], 0x21);
        assert_eq!(Packet::decode(&b).unwrap(), p);
    }

    #[test]
    fn unknown_extension_skipped() {
        let mut b = Packet::new(Type::Syn, 1, 1, 0).encode();
        b[1] = 9;
        b.extend_from_slice(&[0, 2, 0xaa, 0xbb]);
        let p = Packet::decode(&b).unwrap();
        assert_eq!(p.ty, Type::Syn);
        assert!(p.payload.is_empty() && p.sack.is_none());
    }

    #[test]
    fn malformed() {
        assert_eq!(Packet::decode(&[0x01; 19]), Err(DecodeError::TooShort));
        let mut b = Packet::new(Type::Data, 1, 1, 0).encode();
        b[0] = 0x02;
        assert_eq!(Packet::decode(&b), Err(DecodeError::BadVersion(2)));
        b[0] = 0x51;
        assert_eq!(Packet::decode(&b), Err(DecodeError::BadType(5)));
        b[0] = 0x01;
        b[1] = 1;
        assert_eq!(Packet::decode(&b), Err(DecodeError::BadExtension));
        b.extend_from_slice(&[0, 8, 1, 2]);
        assert_eq!(Packet::decode(&b), Err(DecodeError::BadExtension));
        let mut b = Packet::new(Type::Data, 1, 1, 0).encode();
        b[1] = 1;
        b.extend_from_slice(&[0, 3, 1, 2, 3]);
        assert_eq!(Packet::decode(&b), Err(DecodeError::BadExtension));
    }

    #[test]
    fn seq_wrap() {
        assert!(seq_lt(65535, 0));
        assert!(seq_lt(65000, 100));
        assert!(!seq_lt(100, 65000));
        assert!(seq_le(5, 5));
    }

    #[test]
    fn sack_bits() {
        let ack = 65534;
        let mask = sack_build(ack, [0u16, 1, 40].into_iter(), 32).unwrap();
        assert_eq!(mask.len(), 8);
        assert!(sack_contains(&mask, ack, 0));
        assert!(sack_contains(&mask, ack, 1));
        assert!(!sack_contains(&mask, ack, 2));
        assert!(sack_contains(&mask, ack, 40));
        assert!(!sack_contains(&mask, ack, 65535));
        assert!(sack_build(ack, std::iter::empty(), 32).is_none());
    }
}
