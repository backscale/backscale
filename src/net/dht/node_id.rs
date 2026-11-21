use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use rootcause::prelude::*;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha1::Digest;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct NodeId(pub [u8; 20]);

impl NodeId {
    pub fn random() -> Self {
        NodeId(rand::random())
    }

    pub fn sha1(data: &[u8]) -> Self {
        NodeId(sha1::Sha1::digest(data).into())
    }

    pub fn distance(&self, other: &NodeId) -> NodeId {
        let mut d = [0u8; 20];
        for (i, b) in d.iter_mut().enumerate() {
            *b = self.0[i] ^ other.0[i];
        }
        NodeId(d)
    }

    pub fn leading_zeros(&self) -> u32 {
        let mut n = 0;
        for b in self.0 {
            if b == 0 {
                n += 8;
            } else {
                return n + b.leading_zeros();
            }
        }
        n
    }

    // BEP 42: the top 21 bits are derived from the external IP.
    pub fn secure(ip: IpAddr) -> Self {
        let mut id: [u8; 20] = rand::random();
        let r = id[19];
        let crc = bep42_crc(ip, r);
        id[0] = (crc >> 24) as u8;
        id[1] = (crc >> 16) as u8;
        id[2] = ((crc >> 8) as u8 & 0xf8) | (id[2] & 0x07);
        NodeId(id)
    }

    pub fn is_secure_for(&self, ip: IpAddr) -> bool {
        let local = match ip {
            IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()
            }
        };
        if local {
            return true;
        }
        let crc = bep42_crc(ip, self.0[19]);
        self.0[0] == (crc >> 24) as u8
            && self.0[1] == (crc >> 16) as u8
            && self.0[2] & 0xf8 == (crc >> 8) as u8 & 0xf8
    }
}

fn bep42_crc(ip: IpAddr, r: u8) -> u32 {
    let mut b: Vec<u8> = match ip {
        IpAddr::V4(v4) => v4
            .octets()
            .iter()
            .zip([0x03, 0x0f, 0x3f, 0xff])
            .map(|(x, m)| x & m)
            .collect(),
        IpAddr::V6(v6) => v6.octets()[..8]
            .iter()
            .zip([0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7f, 0xff])
            .map(|(x, m)| x & m)
            .collect(),
    };
    b[0] |= (r & 0x07) << 5;
    crc32c::crc32c(&b)
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &hex::encode(self.0)[..12])
    }
}

impl FromStr for NodeId {
    type Err = Report;

    fn from_str(s: &str) -> Result<Self, Report> {
        let v = hex::decode(s).context("node id / infohash must be hex")?;
        Ok(NodeId(v.try_into().map_err(|_| {
            report!("node id / infohash must be 20 bytes")
        })?))
    }
}

impl Serialize for NodeId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let a = serde_bytes::ByteArray::<20>::deserialize(d)?;
        Ok(NodeId(a.into_array()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn bep42_vectors() {
        let vectors: [(&str, u8, &str); 5] = [
            (
                "124.31.75.21",
                1,
                "5fbfbff10c5d6a4ec8a88e4c6ab4c28b95eee401",
            ),
            (
                "21.75.31.124",
                86,
                "5a3ce9c14e7a08645677bbd1cfe7d8f956d53256",
            ),
            (
                "65.23.51.170",
                22,
                "a5d43220bc8f112a3d426c84764f8c2a1150e616",
            ),
            (
                "84.124.73.14",
                65,
                "1b0321dd1bb1fe518101ceef99462b947a01ff41",
            ),
            (
                "43.213.53.83",
                90,
                "e56f6cbf5b7c4be0237986d5243b87aa6d51305a",
            ),
        ];
        for (ip, r, id) in vectors {
            let ip: IpAddr = ip.parse::<Ipv4Addr>().unwrap().into();
            let id: NodeId = id.parse().unwrap();
            assert_eq!(id.0[19], r);
            assert!(id.is_secure_for(ip), "{ip}");
            assert!(NodeId::secure(ip).is_secure_for(ip));
            assert!(!id.is_secure_for("1.2.3.4".parse().unwrap()));
        }
        for ip in ["2001:db8:1234::1", "2a00:1450:4001::5"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert!(NodeId::secure(ip).is_secure_for(ip));
            assert!(!NodeId::secure(ip).is_secure_for("2a01::1".parse().unwrap()));
        }
    }

    #[test]
    fn distance() {
        let a = NodeId([0xff; 20]);
        let mut b = a;
        b.0[2] = 0x7f;
        assert_eq!(a.distance(&b).leading_zeros(), 16);
        assert_eq!(a.distance(&a).leading_zeros(), 160);
    }
}
