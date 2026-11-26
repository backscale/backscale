use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::actions::tests::{Fake, setup};
use super::auth::Auth;
use super::server::{App, serve};

struct Reply {
    status: u16,
    head: String,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<String> {
        self.head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    }
}

struct Dash {
    addr: SocketAddr,
    app: Arc<App<Arc<Fake>>>,
    _dir: tempfile::TempDir,
}

async fn dash() -> Dash {
    let (_fake, actions, dir) = setup();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Arc::new(App {
        actions,
        auth: Auth::new(addr.port()),
    });
    tokio::spawn(serve(listener, app.clone()));
    Dash {
        addr,
        app,
        _dir: dir,
    }
}

impl Dash {
    fn origin(&self) -> String {
        format!("http://{}", self.addr)
    }

    async fn raw(&self, request: String) -> Reply {
        let mut s = TcpStream::connect(self.addr).await.unwrap();
        s.write_all(request.as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        let (head, body) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
        let status = head.split(' ').nth(1).unwrap().parse().unwrap();
        Reply {
            status,
            head: head.to_string(),
            body: body.to_string(),
        }
    }

    async fn send(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Reply {
        let mut r = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
            self.addr,
            body.len()
        );
        if !body.is_empty() {
            r.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
        }
        for (k, v) in headers {
            r.push_str(&format!("{k}: {v}\r\n"));
        }
        r.push_str("\r\n");
        r.push_str(body);
        self.raw(r).await
    }

    // Logs in; returns the cookie header and the CSRF token.
    async fn login(&self) -> (String, String) {
        let origin = self.origin();
        let r = self
            .send(
                "POST",
                "/login",
                &[("Origin", &origin)],
                &format!("token={}", self.app.auth.token_hex()),
            )
            .await;
        assert_eq!(r.status, 303, "{}", r.head);
        let set = r.header("set-cookie").unwrap();
        let cookie = set.split(';').next().unwrap().to_string();
        let (_, csrf) = self.app.auth.session(Some(&cookie)).unwrap();
        (cookie, csrf)
    }
}

#[tokio::test]
async fn unauthenticated_gets_the_login_page_with_strict_headers() {
    let d = dash().await;
    let r = d.send("GET", "/", &[], "").await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("Dashboard token"));
    assert!(!r.body.contains(&d.app.auth.token_hex()));
    let csp = r.header("content-security-policy").unwrap();
    assert!(csp.contains("default-src 'none'") && csp.contains("script-src 'self'"));
    assert!(csp.contains("frame-ancestors 'none'"));
    assert_eq!(r.header("x-frame-options").as_deref(), Some("DENY"));
    assert_eq!(
        r.header("x-content-type-options").as_deref(),
        Some("nosniff")
    );
    assert_eq!(r.header("cache-control").as_deref(), Some("no-store"));
    assert_eq!(r.header("referrer-policy").as_deref(), Some("no-referrer"));

    let r = d.send("GET", "/f/status", &[], "").await;
    assert_eq!(r.status, 401);
    assert_eq!(r.header("hx-redirect").as_deref(), Some("/"));
    let r = d.send("GET", "/assets/htmx.min.js", &[], "").await;
    assert_eq!(r.status, 200);
}

#[tokio::test]
async fn foreign_host_is_refused() {
    let d = dash().await;
    let port = d.addr.port();
    for host in [format!("evil.example:{port}"), "127.0.0.1".to_string()] {
        let r = d
            .raw(format!(
                "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            ))
            .await;
        assert_eq!(r.status, 421, "{host}");
    }
}

#[tokio::test]
async fn login_needs_the_token_and_our_origin() {
    let d = dash().await;
    let token = format!("token={}", d.app.auth.token_hex());
    let r = d.send("POST", "/login", &[], &token).await;
    assert_eq!(r.status, 403, "no Origin");
    let r = d
        .send(
            "POST",
            "/login",
            &[("Origin", "http://evil.example")],
            &token,
        )
        .await;
    assert_eq!(r.status, 403, "foreign Origin");
    let origin = d.origin();
    let r = d
        .send("POST", "/login", &[("Origin", &origin)], "token=00")
        .await;
    assert_eq!(r.status, 403, "wrong token");
    assert!(r.header("set-cookie").is_none());

    let r = d
        .send("POST", "/login", &[("Origin", &origin)], &token)
        .await;
    assert_eq!(r.status, 303);
    let cookie = r.header("set-cookie").unwrap();
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
}

#[tokio::test]
async fn state_changes_need_session_origin_and_csrf() {
    let d = dash().await;
    let (cookie, csrf) = d.login().await;
    let origin = d.origin();

    let page = d.send("GET", "/", &[("Cookie", &cookie)], "").await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains(&csrf));

    let r = d
        .send(
            "POST",
            "/a/acl/clear",
            &[("Cookie", &cookie), ("Origin", &origin)],
            "x=1",
        )
        .await;
    assert_eq!(r.status, 403, "no CSRF header");
    let r = d
        .send(
            "POST",
            "/a/acl/clear",
            &[("Cookie", &cookie), ("x-backscale-csrf", &csrf)],
            "x=1",
        )
        .await;
    assert_eq!(r.status, 403, "no Origin");
    let r = d
        .send(
            "POST",
            "/a/acl/clear",
            &[("Origin", &origin), ("x-backscale-csrf", &csrf)],
            "x=1",
        )
        .await;
    assert_eq!(r.status, 401, "no session");
    let ok = [
        ("Cookie", cookie.as_str()),
        ("Origin", origin.as_str()),
        ("x-backscale-csrf", csrf.as_str()),
    ];
    let r = d.send("POST", "/a/acl/clear", &ok, "x=1").await;
    assert_eq!(r.status, 200);
    assert!(r.body.contains("ACL cleared"));
    assert_eq!(r.header("hx-trigger").as_deref(), Some("draft-changed"));

    let big = "x=".to_string() + &"a".repeat(70 * 1024);
    let r = d.send("POST", "/a/acl/clear", &ok, &big).await;
    assert_eq!(r.status, 413);

    let r = d.send("POST", "/logout", &ok, "").await;
    assert_eq!(r.status, 200);
    let r = d.send("GET", "/f/acl", &[("Cookie", &cookie)], "").await;
    assert_eq!(r.status, 401, "session gone after logout");
}

#[tokio::test]
async fn hostile_input_is_escaped_end_to_end() {
    let d = dash().await;
    let (cookie, csrf) = d.login().await;
    let origin = d.origin();
    let ok = [
        ("Cookie", cookie.as_str()),
        ("Origin", origin.as_str()),
        ("x-backscale-csrf", csrf.as_str()),
    ];
    let r = d
        .send(
            "POST",
            "/a/invite/create",
            &ok,
            "name=%3Cscript%3Ealert(1)%3C%2Fscript%3E&ttl=1h&uses=1",
        )
        .await;
    assert_eq!(r.status, 200);
    assert!(!r.body.contains("<script>alert"), "{}", r.body);
    assert!(r.body.contains("&lt;script&gt;"), "{}", r.body);
}
