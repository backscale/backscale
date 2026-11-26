// Who may use the dashboard: whoever can read the token printed on the
// terminal. The browser trades it once for an HttpOnly, SameSite=Strict
// session cookie; state changes additionally need a matching Origin and the
// session's CSRF token in a custom header.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use subtle::ConstantTimeEq;
use tokio::time::Instant;

pub const COOKIE: &str = "bs_session";
pub const CSRF_HEADER: &str = "x-backscale-csrf";
const SESSION_LIFETIME: Duration = Duration::from_secs(12 * 3600);
const MAX_SESSIONS: usize = 16;
const MAX_BACKOFF: Duration = Duration::from_secs(30);

pub struct Session {
    pub csrf: String,
    expires: Instant,
    seq: u64,
}

pub struct Auth {
    token: [u8; 32],
    port: u16,
    sessions: Mutex<HashMap<String, Session>>,
    failures: Mutex<u32>,
    next_seq: std::sync::atomic::AtomicU64,
}

impl Auth {
    pub fn new(port: u16) -> Self {
        Auth {
            token: rand::random(),
            port,
            sessions: Mutex::default(),
            failures: Mutex::default(),
            next_seq: Default::default(),
        }
    }

    pub fn token_hex(&self) -> String {
        hex::encode(self.token)
    }

    // DNS rebinding protection: only our loopback names are served.
    pub fn host_ok(&self, host: Option<&str>) -> bool {
        let Some(host) = host else { return false };
        let p = self.port;
        [
            format!("127.0.0.1:{p}"),
            format!("localhost:{p}"),
            format!("[::1]:{p}"),
        ]
        .iter()
        .any(|h| h == host)
    }

    pub fn origin_ok(&self, origin: Option<&str>) -> bool {
        origin
            .and_then(|o| o.strip_prefix("http://"))
            .is_some_and(|h| self.host_ok(Some(h)))
    }

    // How long to make a login attempt wait, given earlier failures.
    pub fn backoff(&self) -> Duration {
        let n = *self.failures.lock().unwrap();
        Duration::from_secs(n.into()).min(MAX_BACKOFF)
    }

    // A new session id if `candidate` is the token.
    pub fn login(&self, candidate: &str) -> Option<String> {
        let ok = hex::decode(candidate.trim())
            .ok()
            .is_some_and(|c| c.len() == 32 && bool::from(c.ct_eq(&self.token)));
        if !ok {
            *self.failures.lock().unwrap() += 1;
            return None;
        }
        *self.failures.lock().unwrap() = 0;
        let id = hex::encode(rand::random::<[u8; 32]>());
        let mut s = self.sessions.lock().unwrap();
        let now = Instant::now();
        s.retain(|_, v| v.expires > now);
        if s.len() >= MAX_SESSIONS
            && let Some(oldest) = s.iter().min_by_key(|(_, v)| v.seq).map(|(k, _)| k.clone())
        {
            s.remove(&oldest);
        }
        s.insert(
            id.clone(),
            Session {
                csrf: hex::encode(rand::random::<[u8; 32]>()),
                expires: now + SESSION_LIFETIME,
                seq: self
                    .next_seq
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            },
        );
        Some(id)
    }

    pub fn logout(&self, id: &str) {
        self.sessions.lock().unwrap().remove(id);
    }

    // The session's CSRF token, if `cookie_header` carries a live session.
    pub fn session(&self, cookie_header: Option<&str>) -> Option<(String, String)> {
        let id = cookie_header?
            .split(';')
            .filter_map(|kv| kv.trim().split_once('='))
            .find(|(k, _)| *k == COOKIE)
            .map(|(_, v)| v.to_string())?;
        let s = self.sessions.lock().unwrap();
        let sess = s.get(&id).filter(|v| v.expires > Instant::now())?;
        Some((id, sess.csrf.clone()))
    }

    pub fn csrf_ok(expected: &str, got: Option<&str>) -> bool {
        got.is_some_and(|g| {
            g.len() == expected.len() && bool::from(g.as_bytes().ct_eq(expected.as_bytes()))
        })
    }

    pub fn cookie(id: &str) -> String {
        format!("{COOKIE}={id}; HttpOnly; SameSite=Strict; Path=/")
    }

    pub fn clear_cookie() -> String {
        format!("{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_origins() {
        let a = Auth::new(4000);
        assert!(a.host_ok(Some("127.0.0.1:4000")));
        assert!(a.host_ok(Some("localhost:4000")));
        assert!(a.host_ok(Some("[::1]:4000")));
        assert!(!a.host_ok(Some("127.0.0.1:4001")));
        assert!(!a.host_ok(Some("evil.example:4000")));
        assert!(!a.host_ok(Some("127.0.0.1")));
        assert!(!a.host_ok(None));
        assert!(a.origin_ok(Some("http://localhost:4000")));
        assert!(!a.origin_ok(Some("https://localhost:4000")));
        assert!(!a.origin_ok(Some("http://evil.example")));
        assert!(!a.origin_ok(Some("null")));
        assert!(!a.origin_ok(None));
    }

    #[test]
    fn login_sessions_and_backoff() {
        let a = Auth::new(1);
        assert!(a.login("00").is_none());
        assert!(a.login(&"00".repeat(32)).is_none());
        assert_eq!(a.backoff(), Duration::from_secs(2));
        let id = a.login(&a.token_hex()).unwrap();
        assert_eq!(a.backoff(), Duration::ZERO);
        let (sid, csrf) = a.session(Some(&format!("x=1; {COOKIE}={id}"))).unwrap();
        assert_eq!(sid, id);
        assert!(Auth::csrf_ok(&csrf, Some(&csrf)));
        assert!(!Auth::csrf_ok(&csrf, Some("x")));
        assert!(!Auth::csrf_ok(&csrf, None));
        assert!(a.session(Some(&format!("{COOKIE}=nope"))).is_none());
        a.logout(&id);
        assert!(a.session(Some(&format!("{COOKIE}={id}"))).is_none());
    }

    #[test]
    fn session_count_is_capped() {
        let a = Auth::new(1);
        let first = a.login(&a.token_hex()).unwrap();
        for _ in 0..MAX_SESSIONS {
            a.login(&a.token_hex()).unwrap();
        }
        assert!(a.sessions.lock().unwrap().len() <= MAX_SESSIONS);
        assert!(a.session(Some(&format!("{COOKIE}={first}"))).is_none());
    }
}
