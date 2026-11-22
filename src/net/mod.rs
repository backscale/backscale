pub mod dht;
pub mod lan;
pub mod socket;

use crate::manifest::NetId;
use dht::node_id::NodeId;

pub const TOPIC_PERIOD_SECS: u64 = 3600;

// The DHT infohash a network rendezvouses on. It rotates every period so
// outside observers can't follow a network over time.
pub fn topic(net_id: &NetId, unix: u64) -> NodeId {
    let epoch = unix / TOPIC_PERIOD_SECS;
    let mut input = b"backscale topic v1".to_vec();
    input.extend_from_slice(&epoch.to_be_bytes());
    let h = blake3::keyed_hash(&net_id.0, &input);
    NodeId(h.as_bytes()[..20].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_rotates_hourly() {
        let net = NetId([9; 32]);
        let t0 = 1_800_000_000 / 3600 * 3600;
        assert_eq!(topic(&net, t0), topic(&net, t0 + 3599));
        assert_ne!(topic(&net, t0), topic(&net, t0 + 3600));
        assert_ne!(topic(&net, t0), topic(&NetId([8; 32]), t0));
    }
}
