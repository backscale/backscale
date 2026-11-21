use std::time::Duration;

use tokio::time::Instant;

pub const TARGET: Duration = Duration::from_millis(100);
const GAIN: f64 = 1.0;
const BASE_HISTORY_BUCKET: Duration = Duration::from_secs(60);
const MAX_CWND: usize = 4 << 20;

// One-way delay samples come from the peer's clock minus ours, so they carry
// an arbitrary constant offset. Only differences against the minimum ("base")
// are meaningful, and comparisons must survive u32 wrap-around.
#[derive(Debug, Clone)]
struct BaseDelay {
    buckets: [Option<u32>; 2],
    bucket_started: Instant,
}

impl BaseDelay {
    fn new(now: Instant) -> Self {
        BaseDelay {
            buckets: [None, None],
            bucket_started: now,
        }
    }

    fn update(&mut self, sample: u32, now: Instant) {
        if now.duration_since(self.bucket_started) >= BASE_HISTORY_BUCKET {
            self.buckets = [None, self.buckets[0]];
            self.bucket_started = now;
        }
        let cur = &mut self.buckets[0];
        if cur.is_none_or(|b| (sample.wrapping_sub(b) as i32) < 0) {
            *cur = Some(sample);
        }
    }

    fn queuing(&self, sample: u32) -> Duration {
        let base = self
            .buckets
            .iter()
            .flatten()
            .copied()
            .reduce(|a, b| if (b.wrapping_sub(a) as i32) < 0 { b } else { a });
        match base {
            Some(b) => Duration::from_micros(sample.wrapping_sub(b).min(i32::MAX as u32) as u64),
            None => Duration::ZERO,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Ledbat {
    mss: usize,
    cwnd: usize,
    ssthresh: usize,
    base: BaseDelay,
    last_queuing: Duration,
}

impl Ledbat {
    pub fn new(mss: usize, now: Instant) -> Self {
        Ledbat {
            mss,
            cwnd: 2 * mss,
            ssthresh: MAX_CWND,
            base: BaseDelay::new(now),
            last_queuing: Duration::ZERO,
        }
    }

    pub fn cwnd(&self) -> usize {
        self.cwnd
    }

    pub fn queuing_delay(&self) -> Duration {
        self.last_queuing
    }

    fn min_cwnd(&self) -> usize {
        2 * self.mss
    }

    pub fn on_ack(&mut self, bytes_acked: usize, delay_sample: Option<u32>, now: Instant) {
        if let Some(s) = delay_sample {
            self.base.update(s, now);
            self.last_queuing = self.base.queuing(s);
        }
        let q = self.last_queuing;
        if self.cwnd < self.ssthresh {
            if q > TARGET / 2 {
                self.ssthresh = self.cwnd;
            } else {
                self.cwnd = (self.cwnd + bytes_acked).min(MAX_CWND);
                return;
            }
        }
        let off_target = (TARGET.as_secs_f64() - q.as_secs_f64()) / TARGET.as_secs_f64();
        let delta = GAIN * off_target.clamp(-1.0, 1.0) * bytes_acked as f64 * self.mss as f64
            / self.cwnd as f64;
        let cwnd = (self.cwnd as f64 + delta).round() as usize;
        self.cwnd = cwnd.clamp(self.min_cwnd(), MAX_CWND);
    }

    pub fn on_loss(&mut self) {
        self.cwnd = (self.cwnd / 2).max(self.min_cwnd());
        self.ssthresh = self.cwnd;
    }

    pub fn on_timeout(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(self.min_cwnd());
        self.cwnd = self.mss;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSS: usize = 1000;

    #[tokio::test(start_paused = true)]
    async fn slow_start_then_backs_off_on_delay() {
        let now = Instant::now();
        let mut l = Ledbat::new(MSS, now);
        let offset = u32::MAX - 1000;
        l.on_ack(MSS, Some(offset), now);
        for _ in 0..20 {
            l.on_ack(MSS, Some(offset.wrapping_add(5_000)), now);
        }
        assert!(
            l.cwnd() >= 20 * MSS,
            "slow start should grow cwnd: {}",
            l.cwnd()
        );
        let before = l.cwnd();
        for _ in 0..200 {
            l.on_ack(MSS, Some(offset.wrapping_add(300_000)), now);
        }
        assert!(l.cwnd() < before, "cwnd must shrink above target");
        assert_eq!(l.queuing_delay(), Duration::from_millis(300));
        for _ in 0..2000 {
            l.on_ack(MSS, Some(offset.wrapping_add(300_000)), now);
        }
        assert_eq!(l.cwnd(), 2 * MSS);
    }

    #[tokio::test(start_paused = true)]
    async fn loss_and_timeout() {
        let now = Instant::now();
        let mut l = Ledbat::new(MSS, now);
        for _ in 0..30 {
            l.on_ack(MSS, None, now);
        }
        let w = l.cwnd();
        l.on_loss();
        assert_eq!(l.cwnd(), w / 2);
        l.on_timeout();
        assert_eq!(l.cwnd(), MSS);
    }
}
