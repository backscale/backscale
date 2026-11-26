pub mod lan;
pub mod socket;

use crate::manifest::NetId;
use backscale_dht::NodeId;

pub const TOPIC_PERIOD_SECS: u64 = 3600;

// The DHT infohash a network rendezvouses on. It rotates every period so
// outside observers can't follow a network over time.
pub fn topic(net_id: &NetId, unix: u64) -> NodeId {
    labelled_topic(b"backscale topic v1", net_id, unix)
}

// Where the member holding live invites can be found by enrolling nodes.
pub fn manager_topic(net_id: &NetId, unix: u64) -> NodeId {
    labelled_topic(b"backscale manager topic v1", net_id, unix)
}

fn labelled_topic(label: &[u8], net_id: &NetId, unix: u64) -> NodeId {
    let epoch = unix / TOPIC_PERIOD_SECS;
    let mut input = label.to_vec();
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

    #[test]
    fn manager_topic_is_separate() {
        let net = NetId([9; 32]);
        let t0 = 1_800_000_000 / 3600 * 3600;
        assert_ne!(manager_topic(&net, t0), topic(&net, t0));
        assert_eq!(manager_topic(&net, t0), manager_topic(&net, t0 + 3599));
        assert_ne!(manager_topic(&net, t0), manager_topic(&net, t0 + 3600));
    }
}
