use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::ByteBuf;

use super::node_id::NodeId;

pub const ERR_SERVER: i64 = 202;
pub const ERR_PROTOCOL: i64 = 203;
pub const ERR_METHOD: i64 = 204;

// KRPC fields are flattened into one struct per dict; which ones are present
// depends on `y` and `q`, and krpc.rs checks them per query type.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Message {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a: Option<Args>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<(i64, ByteBuf)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<CompactAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub q: Option<ByteBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r: Option<Resp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ro: Option<i64>,
    pub t: ByteBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v: Option<ByteBuf>,
    pub y: ByteBuf,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Args {
    pub id: NodeId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implied_port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info_hash: Option<NodeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<NodeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<ByteBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub want: Option<Vec<ByteBuf>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Resp {
    pub id: NodeId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes: Option<CompactNodes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodes6: Option<CompactNodes6>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<ByteBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<CompactAddr>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompactAddr(pub SocketAddr);

impl CompactAddr {
    fn to_bytes(self) -> Vec<u8> {
        let mut b = match self.0.ip() {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        b.extend_from_slice(&self.0.port().to_be_bytes());
        b
    }

    fn from_bytes(b: &[u8]) -> Option<Self> {
        let (ip, port): (IpAddr, &[u8]) = match b.len() {
            6 => (<[u8; 4]>::try_from(&b[..4]).ok()?.into(), &b[4..]),
            18 => (<[u8; 16]>::try_from(&b[..16]).ok()?.into(), &b[16..]),
            _ => return None,
        };
        Some(CompactAddr(SocketAddr::new(
            ip,
            u16::from_be_bytes([port[0], port[1]]),
        )))
    }
}

impl Serialize for CompactAddr {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.to_bytes())
    }
}

impl<'de> Deserialize<'de> for CompactAddr {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let b = ByteBuf::deserialize(d)?;
        CompactAddr::from_bytes(&b)
            .ok_or_else(|| serde::de::Error::custom("compact address must be 6 or 18 bytes"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeInfo {
    pub id: NodeId,
    pub addr: SocketAddr,
}

fn encode_nodes(nodes: &[NodeInfo], v6: bool) -> Vec<u8> {
    let mut b = Vec::new();
    for n in nodes.iter().filter(|n| n.addr.is_ipv6() == v6) {
        b.extend_from_slice(&n.id.0);
        b.extend_from_slice(&CompactAddr(n.addr).to_bytes());
    }
    b
}

fn decode_nodes<E: serde::de::Error>(b: &[u8], entry: usize) -> Result<Vec<NodeInfo>, E> {
    if !b.len().is_multiple_of(entry) {
        return Err(E::custom("compact node info has a bad length"));
    }
    b.chunks_exact(entry)
        .map(|c| {
            let addr =
                CompactAddr::from_bytes(&c[20..]).ok_or_else(|| E::custom("bad compact node"))?;
            Ok(NodeInfo {
                id: NodeId(c[..20].try_into().map_err(|_| E::custom("bad node id"))?),
                addr: addr.0,
            })
        })
        .collect()
}

// `nodes` (26-byte IPv4 entries) and `nodes6` (38-byte IPv6 entries, BEP 32).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompactNodes(pub Vec<NodeInfo>);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompactNodes6(pub Vec<NodeInfo>);

impl Serialize for CompactNodes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&encode_nodes(&self.0, false))
    }
}

impl<'de> Deserialize<'de> for CompactNodes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let b = ByteBuf::deserialize(d)?;
        Ok(CompactNodes(decode_nodes(&b, 26)?))
    }
}

impl Serialize for CompactNodes6 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&encode_nodes(&self.0, true))
    }
}

impl<'de> Deserialize<'de> for CompactNodes6 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let b = ByteBuf::deserialize(d)?;
        Ok(CompactNodes6(decode_nodes(&b, 38)?))
    }
}

impl Message {
    pub fn encode(&self) -> Vec<u8> {
        bt_bencode::to_vec(self).expect("KRPC message always encodes")
    }

    pub fn decode(b: &[u8]) -> Result<Self, bt_bencode::Error> {
        bt_bencode::from_slice(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(raw: &[u8]) -> Message {
        let m = Message::decode(raw).unwrap();
        assert_eq!(m.encode(), raw, "re-encoding must be byte-identical");
        m
    }

    // Examples from BEP 5.
    #[test]
    fn bep5_ping() {
        let q = roundtrip(b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe");
        assert_eq!(&q.q.unwrap()[..], b"ping");
        assert_eq!(q.a.unwrap().id.0, *b"abcdefghij0123456789");
        let r = roundtrip(b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re");
        assert_eq!(&r.y[..], b"r");
    }

    #[test]
    fn bep5_error() {
        let e = roundtrip(b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:y1:ee");
        let (code, msg) = e.e.unwrap();
        assert_eq!(code, 201);
        assert_eq!(&msg[..], b"A Generic Error Ocurred");
    }

    #[test]
    fn bep5_find_node_and_get_peers() {
        roundtrip(b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e1:q9:find_node1:t2:aa1:y1:qe");
        roundtrip(b"d1:ad2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e1:q9:get_peers1:t2:aa1:y1:qe");
        let r = roundtrip(b"d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:axje.u6:idhtnmee1:t2:aa1:y1:re");
        let values = r.r.unwrap().values.unwrap();
        assert_eq!(values.len(), 2);
        assert_eq!(
            values[0].0,
            SocketAddr::new(IpAddr::from(*b"axje"), u16::from_be_bytes(*b".u"))
        );
        roundtrip(b"d1:ad2:id20:abcdefghij012345678912:implied_porti1e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe1:q13:announce_peer1:t2:aa1:y1:qe");
    }

    #[test]
    fn compact_nodes() {
        let n = NodeInfo {
            id: NodeId([7; 20]),
            addr: "1.2.3.4:5678".parse().unwrap(),
        };
        let m = Message {
            t: ByteBuf::from(b"xy".to_vec()),
            y: ByteBuf::from(b"r".to_vec()),
            r: Some(Resp {
                id: NodeId([1; 20]),
                nodes: Some(CompactNodes(vec![n, n])),
                ..Default::default()
            }),
            ip: Some(CompactAddr("9.8.7.6:1".parse().unwrap())),
            ..Default::default()
        };
        let back = Message::decode(&m.encode()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn bep32_ipv6_fields() {
        let v6: SocketAddr = "[2001:db8::7]:6881".parse().unwrap();
        let n6 = NodeInfo {
            id: NodeId([3; 20]),
            addr: v6,
        };
        let m = Message {
            t: ByteBuf::from(b"aa".to_vec()),
            y: ByteBuf::from(b"r".to_vec()),
            ip: Some(CompactAddr(v6)),
            r: Some(Resp {
                id: NodeId([1; 20]),
                nodes6: Some(CompactNodes6(vec![n6])),
                values: Some(vec![
                    CompactAddr(v6),
                    CompactAddr("1.2.3.4:5".parse().unwrap()),
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let bytes = m.encode();
        let window = b"6:nodes638:";
        assert!(bytes.windows(window.len()).any(|w| w == window));
        assert_eq!(Message::decode(&bytes).unwrap(), m);

        let q = Message::decode(b"d1:ad2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz1234564:wantl2:n42:n6ee1:q9:find_node1:t2:aa1:y1:qe").unwrap();
        let want = q.a.unwrap().want.unwrap();
        assert_eq!(
            want,
            vec![ByteBuf::from(b"n4".to_vec()), ByteBuf::from(b"n6".to_vec())]
        );
        assert!(
            Message::decode(b"d1:rd2:id20:abcdefghij01234567896:nodes63:abce1:t2:aa1:y1:re")
                .is_err()
        );
    }

    #[test]
    fn unknown_fields_ignored_and_garbage_rejected() {
        let m = Message::decode(
            b"d1:ad2:id20:abcdefghij01234567893:zzzi5ee1:q4:ping1:t2:aa1:y1:q3:zzzli1eee",
        )
        .unwrap();
        assert_eq!(&m.q.unwrap()[..], b"ping");
        assert!(Message::decode(b"d1:ad2:id3:abce1:q4:ping1:t2:aa1:y1:qe").is_err());
        assert!(Message::decode(b"d1:t2:aa").is_err());
        assert!(Message::decode(b"d1:y1:re").is_err());
        assert!(
            Message::decode(b"d1:rd2:id20:abcdefghij01234567895:nodes3:abce1:t2:aa1:y1:re")
                .is_err()
        );
    }
}
