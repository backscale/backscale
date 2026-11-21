use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::node_id::NodeId;
use super::wire::NodeInfo;

pub const K: usize = 8;
const GOOD_FOR: Duration = Duration::from_secs(15 * 60);
const MAX_FAILURES: u32 = 2;

#[derive(Debug, Clone)]
pub struct Entry {
    pub info: NodeInfo,
    pub last_response: Instant,
    pub failures: u32,
}

impl Entry {
    pub fn is_good(&self, now: Instant) -> bool {
        self.failures == 0 && now.duration_since(self.last_response) < GOOD_FOR
    }

    pub fn is_bad(&self) -> bool {
        self.failures >= MAX_FAILURES
    }
}

#[derive(Debug, Clone)]
struct Bucket {
    entries: Vec<Entry>,
    last_changed: Instant,
}

// Bucket i holds nodes whose XOR distance from us has exactly i leading zero
// bits. Equivalent to the split-on-own-bucket scheme in BEP 5, but simpler.
pub struct RoutingTable {
    own: NodeId,
    buckets: Vec<Bucket>,
}

impl RoutingTable {
    pub fn new(own: NodeId) -> Self {
        let now = Instant::now();
        RoutingTable {
            own,
            buckets: vec![
                Bucket {
                    entries: Vec::new(),
                    last_changed: now,
                };
                160
            ],
        }
    }

    pub fn own_id(&self) -> NodeId {
        self.own
    }

    fn bucket_of(&self, id: &NodeId) -> Option<usize> {
        let lz = self.own.distance(id).leading_zeros() as usize;
        (lz < 160).then_some(lz)
    }

    // Record a node that answered one of our queries.
    pub fn insert_responded(&mut self, info: NodeInfo, now: Instant) {
        let Some(b) = self.bucket_of(&info.id) else {
            return;
        };
        let bucket = &mut self.buckets[b];
        if let Some(e) = bucket.entries.iter_mut().find(|e| e.info.id == info.id) {
            e.info.addr = info.addr;
            e.last_response = now;
            e.failures = 0;
            bucket.last_changed = now;
            return;
        }
        if bucket.entries.iter().any(|e| e.info.addr == info.addr) {
            return;
        }
        let entry = Entry {
            info,
            last_response: now,
            failures: 0,
        };
        if bucket.entries.len() < K {
            bucket.entries.push(entry);
            bucket.last_changed = now;
        } else if let Some(bad) = bucket.entries.iter().position(|e| e.is_bad()) {
            bucket.entries[bad] = entry;
            bucket.last_changed = now;
        }
    }

    pub fn has_room(&self, id: &NodeId) -> bool {
        self.bucket_of(id).is_some_and(|b| {
            let entries = &self.buckets[b].entries;
            entries.len() < K || entries.iter().any(|e| e.is_bad())
        })
    }

    pub fn mark_failed(&mut self, id: &NodeId) {
        if let Some(b) = self.bucket_of(id)
            && let Some(e) = self.buckets[b]
                .entries
                .iter_mut()
                .find(|e| &e.info.id == id)
        {
            e.failures += 1;
        }
    }

    pub fn remove(&mut self, id: &NodeId) {
        if let Some(b) = self.bucket_of(id) {
            self.buckets[b].entries.retain(|e| &e.info.id != id);
        }
    }

    pub fn closest(&self, target: &NodeId, n: usize) -> Vec<NodeInfo> {
        let mut all: Vec<NodeInfo> = self
            .buckets
            .iter()
            .flat_map(|b| b.entries.iter())
            .filter(|e| !e.is_bad())
            .map(|e| e.info)
            .collect();
        all.sort_by_key(|n| target.distance(&n.id));
        all.truncate(n);
        all
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.entries.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn nodes(&self) -> Vec<NodeInfo> {
        self.buckets
            .iter()
            .flat_map(|b| b.entries.iter().map(|e| e.info))
            .collect()
    }

    pub fn questionable(&self, now: Instant) -> Vec<NodeInfo> {
        self.buckets
            .iter()
            .flat_map(|b| b.entries.iter())
            .filter(|e| !e.is_good(now) && !e.is_bad())
            .map(|e| e.info)
            .collect()
    }

    // Random targets inside buckets that haven't changed recently. Only
    // buckets up to the deepest non-empty one are worth refreshing.
    pub fn stale_bucket_targets(&self, now: Instant, max_age: Duration) -> Vec<NodeId> {
        let deepest = self
            .buckets
            .iter()
            .rposition(|b| !b.entries.is_empty())
            .unwrap_or(0);
        (0..=deepest)
            .filter(|&i| now.duration_since(self.buckets[i].last_changed) >= max_age)
            .map(|i| self.random_id_in_bucket(i))
            .collect()
    }

    pub fn sparse_bucket_targets(&self) -> Vec<NodeId> {
        let deepest = self
            .buckets
            .iter()
            .rposition(|b| !b.entries.is_empty())
            .unwrap_or(0);
        (0..=deepest)
            .filter(|&i| self.buckets[i].entries.len() < K)
            .map(|i| self.random_id_in_bucket(i))
            .collect()
    }

    fn random_id_in_bucket(&self, i: usize) -> NodeId {
        let mut id = NodeId::random();
        for bit in 0..=i {
            let (byte, mask) = (bit / 8, 0x80u8 >> (bit % 8));
            let own_bit = self.own.0[byte] & mask;
            let want = if bit == i { own_bit ^ mask } else { own_bit };
            id.0[byte] = (id.0[byte] & !mask) | want;
        }
        id
    }

    pub fn contains_addr(&self, addr: &SocketAddr) -> bool {
        self.buckets
            .iter()
            .any(|b| b.entries.iter().any(|e| &e.info.addr == addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: NodeId, port: u16) -> NodeInfo {
        NodeInfo {
            id,
            addr: SocketAddr::new([10, 0, 0, 1].into(), port),
        }
    }

    #[test]
    fn bucket_capacity_and_bad_replacement() {
        let own = NodeId([0; 20]);
        let mut t = RoutingTable::new(own);
        let now = Instant::now();
        let ids: Vec<NodeId> = (0..10)
            .map(|i| {
                let mut id = NodeId([0; 20]);
                id.0[0] = 0x80;
                id.0[19] = i;
                id
            })
            .collect();
        for (i, id) in ids.iter().enumerate() {
            t.insert_responded(node(*id, i as u16), now);
        }
        assert_eq!(t.len(), K);
        t.mark_failed(&ids[0]);
        t.mark_failed(&ids[0]);
        t.insert_responded(node(ids[9], 9), now);
        assert_eq!(t.len(), K);
        assert!(t.nodes().iter().any(|n| n.id == ids[9]));
        assert!(!t.nodes().iter().any(|n| n.id == ids[0]));
    }

    #[test]
    fn closest_sorted() {
        let own = NodeId::random();
        let mut t = RoutingTable::new(own);
        let now = Instant::now();
        for i in 0..200u16 {
            t.insert_responded(node(NodeId::random(), i), now);
        }
        let target = NodeId::random();
        let c = t.closest(&target, K);
        assert_eq!(c.len(), K);
        for w in c.windows(2) {
            assert!(target.distance(&w[0].id) <= target.distance(&w[1].id));
        }
    }

    #[test]
    fn refresh_target_lands_in_bucket() {
        let own = NodeId::random();
        let t = RoutingTable::new(own);
        for i in [0, 5, 17, 100] {
            let id = t.random_id_in_bucket(i);
            assert_eq!(own.distance(&id).leading_zeros() as usize, i);
        }
    }
}
