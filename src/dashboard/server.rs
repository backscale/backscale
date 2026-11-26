use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{self, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use rootcause::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use super::actions::{Actions, DaemonLink, NewInvite};
use super::auth::{Auth, CSRF_HEADER};
use super::html::{self, Note};
use crate::identity::PublicKey;
use crate::manifest::Selector;

const MAX_BODY: usize = 64 * 1024;
const MAX_CONNS: usize = 32;
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
// Signing with a hardware key can wait on a PIN or a touch.
const CONN_TIMEOUT: Duration = Duration::from_secs(600);

const HTMX: &[u8] = include_bytes!("assets/htmx.min.js");
const CSS: &[u8] = include_bytes!("assets/style.css");
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

pub struct App<D> {
    pub actions: Actions<D>,
    pub auth: Auth,
}

type Resp = Response<Full<Bytes>>;

fn respond(status: StatusCode, ctype: &str, body: impl Into<Bytes>) -> Resp {
    let mut r = Response::new(Full::new(body.into()));
    *r.status_mut() = status;
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_str(ctype).unwrap());
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CSP),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    h.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
    r
}

fn html(body: String) -> Resp {
    respond(StatusCode::OK, "text/html; charset=utf-8", body)
}

fn plain(status: StatusCode, msg: &'static str) -> Resp {
    respond(status, "text/plain; charset=utf-8", msg)
}

fn with_header(mut r: Resp, name: &'static str, value: &str) -> Resp {
    if let Ok(v) = HeaderValue::from_str(value) {
        r.headers_mut().insert(name, v);
    }
    r
}

fn header_str(req: &Request<Incoming>, name: impl header::AsHeaderName) -> Option<&str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

async fn form(body: Incoming) -> Option<HashMap<String, String>> {
    let bytes = Limited::new(body, MAX_BODY)
        .collect()
        .await
        .ok()?
        .to_bytes();
    Some(form_urlencoded::parse(&bytes).into_owned().collect())
}

fn list(s: Option<&String>) -> Vec<String> {
    s.map(|s| {
        s.split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

fn selectors(s: Option<&String>) -> Result<Vec<Selector>, Report> {
    let v: Result<Vec<Selector>, Report> = list(s).iter().map(|s| s.parse()).collect();
    let v = v?;
    if v.is_empty() {
        bail!("a rule needs at least one selector on each side");
    }
    Ok(v)
}

pub async fn serve<D: DaemonLink>(listener: TcpListener, app: Arc<App<D>>) {
    let slots = Arc::new(Semaphore::new(MAX_CONNS));
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "dashboard accept failed");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            debug!("too many dashboard connections");
            continue;
        };
        let app = app.clone();
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |req| {
                let app = app.clone();
                async move { Ok::<_, Infallible>(handle(&app, req).await) }
            });
            let conn = hyper::server::conn::http1::Builder::new()
                .timer(Timer)
                .header_read_timeout(HEADER_TIMEOUT)
                .max_buf_size(16 * 1024)
                .serve_connection(Io(stream), service);
            let _ = tokio::time::timeout(CONN_TIMEOUT, conn).await;
            drop(permit);
        });
    }
}

pub async fn handle<D: DaemonLink>(app: &App<D>, req: Request<Incoming>) -> Resp {
    if !app.auth.host_ok(header_str(&req, header::HOST)) {
        return plain(StatusCode::MISDIRECTED_REQUEST, "unexpected Host header\n");
    }
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    match (&method, path.as_str()) {
        (&Method::GET, "/assets/htmx.min.js") => {
            return respond(StatusCode::OK, "text/javascript; charset=utf-8", HTMX);
        }
        (&Method::GET, "/assets/style.css") => {
            return respond(StatusCode::OK, "text/css; charset=utf-8", CSS);
        }
        _ => {}
    }
    let session = app.auth.session(header_str(&req, header::COOKIE));
    if method == Method::POST && !app.auth.origin_ok(header_str(&req, header::ORIGIN)) {
        return plain(StatusCode::FORBIDDEN, "cross-origin request refused\n");
    }
    match (&method, path.as_str(), session) {
        (&Method::GET, "/", None) => html(html::login_page(None)),
        (&Method::POST, "/login", _) => login(app, req).await,
        (&Method::GET, "/", Some((_, csrf))) => match app.actions.draft() {
            Ok(d) => html(html::page(&csrf, &d)),
            Err(e) => respond(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain; charset=utf-8",
                format!("failed to load the draft: {e}\n"),
            ),
        },
        (_, _, None) => with_header(
            plain(StatusCode::UNAUTHORIZED, "log in first\n"),
            "hx-redirect",
            "/",
        ),
        (&Method::GET, p, Some(_)) if p.starts_with("/f/") => fragment(app, &p[3..], None).await,
        (&Method::POST, p, Some((id, csrf))) => {
            if !Auth::csrf_ok(&csrf, header_str(&req, CSRF_HEADER)) {
                return plain(StatusCode::FORBIDDEN, "missing or wrong CSRF token\n");
            }
            if p == "/logout" {
                app.auth.logout(&id);
                let r = with_header(html(String::new()), "hx-redirect", "/");
                return with_header(r, "set-cookie", &Auth::clear_cookie());
            }
            let Some(f) = form(req.into_body()).await else {
                return plain(StatusCode::PAYLOAD_TOO_LARGE, "request body too large\n");
            };
            action(app, p, &f).await
        }
        _ => plain(StatusCode::NOT_FOUND, "not found\n"),
    }
}

async fn login<D: DaemonLink>(app: &App<D>, req: Request<Incoming>) -> Resp {
    tokio::time::sleep(app.auth.backoff()).await;
    let token = form(req.into_body())
        .await
        .and_then(|f| f.get("token").cloned())
        .unwrap_or_default();
    match app.auth.login(&token) {
        Some(id) => {
            info!("dashboard login");
            let mut r = plain(StatusCode::SEE_OTHER, "");
            r.headers_mut()
                .insert(header::LOCATION, HeaderValue::from_static("/"));
            with_header(r, "set-cookie", &Auth::cookie(&id))
        }
        None => {
            warn!("dashboard login with a wrong token");
            let mut r = html(html::login_page(Some("Wrong token.")));
            *r.status_mut() = StatusCode::FORBIDDEN;
            r
        }
    }
}

async fn fragment<D: DaemonLink>(app: &App<D>, name: &str, n: Option<Note>) -> Resp {
    let a = &app.actions;
    let n = n.as_ref();
    let body = match name {
        "status" => a.status().await.map(|s| html::status(&s)),
        "enrollments" => a.enrollments().await.map(|p| html::enrollments(&p, n)),
        "invites" => a.invites().await.map(|i| html::invites(&i, None, n)),
        "members" => match a.draft() {
            Ok(d) => Ok(html::members(&d, a.status().await.ok().as_ref(), n)),
            Err(e) => Err(e),
        },
        "acl" => a.draft().map(|d| html::acl(&d, n)),
        "publish" => match (a.draft(), a.published().await) {
            (Ok(d), Ok(p)) => Ok(html::publish(&d, p.as_ref(), n)),
            (Err(e), _) | (_, Err(e)) => Err(e),
        },
        _ => return plain(StatusCode::NOT_FOUND, "not found\n"),
    };
    html(body.unwrap_or_else(|e| html::error_section(name, &e.to_string())))
}

fn note<T>(r: Result<T, Report>, ok: impl FnOnce(T) -> String) -> Note {
    match r {
        Ok(v) => Note::Ok(ok(v)),
        Err(e) => Note::Err(e.to_string()),
    }
}

async fn action<D: DaemonLink>(app: &App<D>, path: &str, f: &HashMap<String, String>) -> Resp {
    let a = &app.actions;
    let get = |k: &str| f.get(k).map(|s| s.trim().to_string()).unwrap_or_default();
    let (section, n, trigger) = match path {
        "/a/member/add" => {
            let r = async {
                let identity: PublicKey = get("identity").parse()?;
                let name = get("name");
                let tags = list(f.get("tags"));
                a.edit(|d| d.add_member(identity, name, None, None, tags).map(|_| ()))
                    .await
            }
            .await;
            ("members", note(r, |_| "added to the draft".into()), true)
        }
        "/a/member/remove" => {
            let who = get("who");
            let r = a.edit(|d| d.remove_member(&who).map(|_| ())).await;
            (
                "members",
                note(r, |_| format!("removed {who} from the draft")),
                true,
            )
        }
        "/a/member/tags" => {
            let who = get("who");
            let want = list(f.get("tags"));
            let r = a
                .edit(|d| {
                    let current = d
                        .members
                        .iter()
                        .find(|m| m.name == who)
                        .map(|m| m.tags.clone())
                        .ok_or_else(|| report!("no member `{who}`"))?;
                    let remove: Vec<String> =
                        current.into_iter().filter(|t| !want.contains(t)).collect();
                    d.set_tags(&who, &want, &remove).map(|_| ())
                })
                .await;
            (
                "members",
                note(r, |_| format!("updated {who}'s tags")),
                true,
            )
        }
        "/a/acl/add" => {
            let r = async {
                let (from, to) = (selectors(f.get("from"))?, selectors(f.get("to"))?);
                a.edit(|d| d.add_acl(from, to)).await
            }
            .await;
            ("acl", note(r, |_| "rule added".into()), true)
        }
        "/a/acl/remove" => {
            let r = async {
                let n: usize = get("n").parse().context("bad rule number")?;
                a.edit(|d| d.remove_acl(n).map(|_| ())).await
            }
            .await;
            ("acl", note(r, |_| "rule removed".into()), true)
        }
        "/a/acl/clear" => {
            let r = a
                .edit(|d| {
                    d.clear_acl();
                    Ok(())
                })
                .await;
            ("acl", note(r, |_| "ACL cleared".into()), true)
        }
        "/a/publish" => {
            let r = a.publish().await;
            (
                "publish",
                note(r, |seq| format!("published seq {seq}")),
                true,
            )
        }
        "/a/invite/create" => {
            let r = async {
                let ttl = humantime::parse_duration(&get("ttl")).context("bad validity")?;
                let uses: u32 = get("uses").parse().context("bad use count")?;
                let name = Some(get("name")).filter(|n| !n.is_empty());
                a.create_invite(NewInvite {
                    name,
                    tags: list(f.get("tags")),
                    ttl,
                    uses,
                    auto_approve: get("auto") == "1",
                })
                .await
            }
            .await;
            return match r {
                Ok(code) => {
                    info!(id = %hex::encode(code.id()), "invite created");
                    let list = a.invites().await.unwrap_or_default();
                    html(html::invites(&list, Some(&code), None))
                }
                Err(e) => fragment(app, "invites", Some(Note::Err(e.to_string()))).await,
            };
        }
        "/a/invite/revoke" => {
            let r = async {
                let id: [u8; 16] = hex::decode(get("id"))
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| report!("bad invite id"))?;
                a.revoke(id).await
            }
            .await;
            ("invites", note(r, |_| "invite revoked".into()), false)
        }
        "/a/enroll/approve" => {
            let r = async {
                let req: u64 = get("req").parse().context("bad request id")?;
                let name = Some(get("name")).filter(|n| !n.is_empty());
                a.approve(req, name, Some(list(f.get("tags")))).await
            }
            .await;
            (
                "enrollments",
                note(r, |name| format!("approved {name}")),
                true,
            )
        }
        "/a/enroll/deny" => {
            let r = async {
                let req: u64 = get("req").parse().context("bad request id")?;
                let reason = Some(get("reason"))
                    .filter(|r| !r.is_empty())
                    .unwrap_or_else(|| "denied by the network admin".into());
                a.deny(req, reason).await
            }
            .await;
            ("enrollments", note(r, |_| "denied".into()), false)
        }
        _ => return plain(StatusCode::NOT_FOUND, "not found\n"),
    };
    let r = fragment(app, section, Some(n)).await;
    if trigger {
        with_header(r, "hx-trigger", "draft-changed")
    } else {
        r
    }
}

// hyper's IO traits over a tokio stream, without unsafe: reads go through a
// small buffer.
struct Io(TcpStream);

impl hyper::rt::Read for Io {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let mut tmp = [0u8; 8192];
        let n = buf.remaining().min(tmp.len());
        let mut rb = ReadBuf::new(&mut tmp[..n]);
        match Pin::new(&mut self.0).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => {
                buf.put_slice(rb.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl hyper::rt::Write for Io {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[derive(Clone)]
struct Timer;

struct Sleep(Pin<Box<tokio::time::Sleep>>);

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.0.as_mut().poll(cx)
    }
}

impl hyper::rt::Sleep for Sleep {}

impl hyper::rt::Timer for Timer {
    fn sleep(&self, d: Duration) -> Pin<Box<dyn hyper::rt::Sleep>> {
        Box::pin(Sleep(Box::pin(tokio::time::sleep(d))))
    }

    fn sleep_until(&self, deadline: std::time::Instant) -> Pin<Box<dyn hyper::rt::Sleep>> {
        Box::pin(Sleep(Box::pin(tokio::time::sleep_until(deadline.into()))))
    }
}

pub fn local_only(addr: SocketAddr) -> Result<(), Report> {
    if !addr.ip().is_loopback() {
        bail!("the dashboard only listens on loopback addresses, not {addr}");
    }
    Ok(())
}
