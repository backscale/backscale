use std::time::Duration;

const INITIAL_RTO: Duration = Duration::from_secs(1);
const MIN_RTO: Duration = Duration::from_millis(500);
const MAX_RTO: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct Rtt {
    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
}

impl Default for Rtt {
    fn default() -> Self {
        Rtt {
            srtt: None,
            rttvar: Duration::ZERO,
            rto: INITIAL_RTO,
        }
    }
}

impl Rtt {
    // RFC 6298, with BEP 29's 500 ms floor.
    pub fn sample(&mut self, rtt: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(rtt);
                self.rttvar = rtt / 2;
            }
            Some(srtt) => {
                let err = srtt.abs_diff(rtt);
                self.rttvar = (self.rttvar * 3 + err) / 4;
                self.srtt = Some((srtt * 7 + rtt) / 8);
            }
        }
        self.rto = (self.srtt.unwrap() + self.rttvar * 4).clamp(MIN_RTO, MAX_RTO);
    }

    pub fn backoff(&mut self) {
        self.rto = (self.rto * 2).min(MAX_RTO);
    }

    pub fn rto(&self) -> Duration {
        self.rto
    }

    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converges_and_backs_off() {
        let mut r = Rtt::default();
        assert_eq!(r.rto(), INITIAL_RTO);
        for _ in 0..50 {
            r.sample(Duration::from_millis(200));
        }
        assert!(r.srtt().unwrap().abs_diff(Duration::from_millis(200)) < Duration::from_millis(5));
        assert!(r.rto() >= MIN_RTO && r.rto() < Duration::from_millis(600));
        for _ in 0..10 {
            r.backoff();
        }
        assert_eq!(r.rto(), MAX_RTO);
        r.sample(Duration::from_millis(1));
        assert!(r.rto() >= MIN_RTO);
    }
}
