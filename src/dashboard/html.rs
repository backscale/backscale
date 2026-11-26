// Every value interpolated into markup goes through `e`.

use std::fmt::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::daemon::Status;
use crate::invite::InviteCode;
use crate::manager::{InviteInfo, Pending};
use crate::manifest::{ManifestDraft, NetworkManifest, diff};

pub enum Note {
    Ok(String),
    Err(String),
}

pub fn e(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn when(unix: u64) -> String {
    humantime::format_rfc3339_seconds(UNIX_EPOCH + Duration::from_secs(unix)).to_string()
}

fn left(unix: u64) -> String {
    let n = now();
    if unix <= n {
        return "expired".into();
    }
    format!(
        "in {}",
        humantime::format_duration(Duration::from_secs((unix - n) / 60 * 60))
    )
}

fn note(n: Option<&Note>) -> String {
    match n {
        None => String::new(),
        Some(Note::Ok(m)) => format!(r#"<p class="ok">{}</p>"#, e(m)),
        Some(Note::Err(m)) => format!(r#"<p class="err">{}</p>"#, e(m)),
    }
}

fn section(id: &str, title: &str, trigger: &str, body: &str) -> String {
    format!(
        r#"<section id="{id}" hx-get="/f/{id}" hx-trigger="{trigger}" hx-swap="outerHTML"><h2>{title}</h2>{body}</section>"#,
        id = e(id),
        title = e(title),
        trigger = e(trigger),
    )
}

// A form posting to `action` that replaces section `target`.
fn form(action: &str, target: &str, extra: &str, body: &str) -> String {
    format!(
        r##"<form hx-post="{a}" hx-target="#{t}" hx-swap="outerHTML" {extra}>{body}</form>"##,
        a = e(action),
        t = e(target),
    )
}

fn hidden(name: &str, value: &str) -> String {
    format!(
        r#"<input type="hidden" name="{}" value="{}">"#,
        e(name),
        e(value)
    )
}

pub fn error_section(id: &str, msg: &str) -> String {
    section(id, id, "load delay:3s", &note(Some(&Note::Err(msg.into()))))
}

const HEAD: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><meta name="htmx-config" content='{"allowEval":false,"allowScriptTags":false,"includeIndicatorStyles":false,"historyCacheSize":0,"selfRequestsOnly":true}'><link rel="stylesheet" href="/assets/style.css"><script src="/assets/htmx.min.js"></script><title>backscale dashboard</title></head>"#;

pub fn login_page(error: Option<&str>) -> String {
    format!(
        r#"{HEAD}<body><main class="login"><h1>backscale</h1><form method="post" action="/login"><label>Dashboard token<input type="password" name="token" autocomplete="off" autofocus required></label><button>Log in</button></form>{}<p class="muted">The token is printed on the terminal running <code>backscale dashboard</code>.</p></main></body></html>"#,
        note(error.map(|m| Note::Err(m.into())).as_ref())
    )
}

pub fn page(csrf: &str, draft: &ManifestDraft) -> String {
    let headers = format!(r#"{{"X-Backscale-CSRF":"{csrf}"}}"#);
    format!(
        r#"{HEAD}<body hx-headers='{headers}'><header><h1>backscale · {name}</h1><span class="muted">net {net}</span><button hx-post="/logout">Log out</button></header><main>{status}{enroll}{invites}{members}{acl}{publish}</main></body></html>"#,
        headers = e(&headers),
        name = e(&draft.name),
        net = e(&draft.net_id().to_string()),
        status = section("status", "Status", "load", ""),
        enroll = section("enrollments", "Enrollment requests", "load", ""),
        invites = section("invites", "Invites", "load", ""),
        members = section("members", "Members (draft)", "load", ""),
        acl = section("acl", "ACL (draft)", "load", ""),
        publish = section("publish", "Sign & publish", "load", ""),
    )
}

pub fn status(s: &Status) -> String {
    let mut b = String::new();
    let _ = write!(
        b,
        r#"<dl><dt>this node</dt><dd>{name} <code>{fp}</code></dd><dt>manifest</dt><dd>seq {seq}, {members} members, expires {exp}</dd><dt>listen</dt><dd>{listen}</dd><dt>dht</dt><dd>{dht}</dd></dl>"#,
        name = e(s.name.as_deref().unwrap_or("not a member")),
        fp = e(&s.identity.fingerprint()),
        seq = s.manifest_seq,
        members = s.members,
        exp = e(&s.manifest_expires.map_or("-".into(), left)),
        listen = e(&s.listen.to_string()),
        dht = e(&match s.dht_nodes {
            Some(n) => format!(
                "{n} nodes, external ip {}",
                s.external_ip.map_or("unknown".into(), |i| i.to_string())
            ),
            None => "off".into(),
        }),
    );
    b.push_str("<table><tr><th>peer</th><th>overlay</th><th>address</th><th>tunnel</th></tr>");
    for p in &s.peers {
        let wg = match &p.wg {
            _ if p.blocked => "blocked by ACL".to_string(),
            Some(w) => format!(
                "handshake {}, tx {} rx {}",
                w.handshake_secs_ago
                    .map_or("never".into(), |s| format!("{s}s ago")),
                w.tx_bytes,
                w.rx_bytes
            ),
            None => "-".into(),
        };
        let _ = write!(
            b,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            e(&p.name),
            e(&p.overlay.map(|i| i.to_string()).unwrap_or_default()),
            e(&p.addr.to_string()),
            e(&wg)
        );
    }
    b.push_str("</table>");
    section("status", "Status", "every 3s", &b)
}

pub fn enrollments(pending: &[Pending], n: Option<&Note>) -> String {
    let mut b = note(n);
    if pending.is_empty() {
        b.push_str(r#"<p class="muted">No pending requests.</p>"#);
    }
    for p in pending {
        let name = p.invite.name.clone().or(p.name.clone()).unwrap_or_default();
        let approve = form(
            "/a/enroll/approve",
            "enrollments",
            "",
            &format!(
                r#"{}<input name="name" value="{}" placeholder="name"><input name="tags" value="{}" placeholder="tags"><button>Approve</button>"#,
                hidden("req", &p.req_id.to_string()),
                e(&name),
                e(&p.invite.tags.join(",")),
            ),
        );
        let deny = form(
            "/a/enroll/deny",
            "enrollments",
            "",
            &format!(
                r#"{}<input name="reason" placeholder="reason"><button class="danger">Deny</button>"#,
                hidden("req", &p.req_id.to_string())
            ),
        );
        let _ = write!(
            b,
            r#"<div class="card"><p><b>{proposed}</b> <code>{fp}</code> from {addr}, invite <code>{inv}</code>{auto}</p>{approve}{deny}</div>"#,
            proposed = e(p.name.as_deref().unwrap_or("(no name proposed)")),
            fp = e(&p.identity.fingerprint()),
            addr = e(&p.addr.to_string()),
            inv = e(&hex::encode(&p.invite.id[..4])),
            auto = if p.invite.auto_approve {
                " (auto-approve pending)"
            } else {
                ""
            },
        );
    }
    section("enrollments", "Enrollment requests", "every 3s", &b)
}

pub fn invites(list: &[InviteInfo], fresh: Option<&InviteCode>, n: Option<&Note>) -> String {
    let mut b = note(n);
    if let Some(code) = fresh {
        let _ = write!(
            b,
            r#"<div class="card code"><p>New invite. It is shown only once; give it to the new node:</p><pre>backscale join --invite {}</pre></div>"#,
            e(&code.to_string())
        );
    }
    b.push_str("<table><tr><th>id</th><th>name</th><th>tags</th><th>uses left</th><th>expires</th><th>approval</th><th></th></tr>");
    for i in list {
        let id = hex::encode(i.id);
        let revoke = form(
            "/a/invite/revoke",
            "invites",
            r#"hx-confirm="Revoke this invite?""#,
            &format!(
                r#"{}<button class="danger">Revoke</button>"#,
                hidden("id", &id)
            ),
        );
        let _ = write!(
            b,
            "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            e(&id[..8]),
            e(i.name.as_deref().unwrap_or("-")),
            e(&i.tags.join(",")),
            i.uses_left,
            e(&left(i.expires_at)),
            if i.auto_approve {
                "automatic"
            } else {
                "manual"
            },
            revoke
        );
    }
    b.push_str("</table>");
    b.push_str(&form(
        "/a/invite/create",
        "invites",
        "",
        r#"<input name="name" placeholder="name (optional)"><input name="tags" placeholder="tags, comma separated"><input name="ttl" value="24h" size="6" title="valid for"><input name="uses" value="1" size="3" title="uses"><label><input type="checkbox" name="auto" value="1"> approve automatically</label><button>Create invite</button>"#,
    ));
    section("invites", "Invites", "invites-changed from:body", &b)
}

pub fn members(d: &ManifestDraft, s: Option<&Status>, n: Option<&Note>) -> String {
    let mut b = note(n);
    b.push_str("<table><tr><th>name</th><th>overlay</th><th>tags</th><th>identity</th><th>online</th><th></th></tr>");
    for m in &d.members {
        let online = match s {
            Some(s) if s.identity == m.identity => "this node",
            Some(s) if s.peers.iter().any(|p| p.identity == m.identity) => "yes",
            Some(_) => "no",
            None => "?",
        };
        let tags = form(
            "/a/member/tags",
            "members",
            "",
            &format!(
                r#"{}<input name="tags" value="{}" size="16"><button>Set</button>"#,
                hidden("who", &m.name),
                e(&m.tags.join(","))
            ),
        );
        let remove = form(
            "/a/member/remove",
            "members",
            &format!(r#"hx-confirm="Remove {} from the draft?""#, e(&m.name)),
            &format!(
                r#"{}<button class="danger">Remove</button>"#,
                hidden("who", &m.name)
            ),
        );
        let _ = write!(
            b,
            "<tr><td>{}</td><td>{}<br>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
            e(&m.name),
            e(&m.ipv4.to_string()),
            e(&m.ipv6.to_string()),
            tags,
            e(&m.identity.fingerprint()),
            online,
            remove
        );
    }
    b.push_str("</table>");
    b.push_str(&form(
        "/a/member/add",
        "members",
        "",
        r#"<input name="identity" placeholder="ed25519:… or p256:…" size="40" required><input name="name" placeholder="name" required><input name="tags" placeholder="tags"><button>Add member</button>"#,
    ));
    section("members", "Members (draft)", "draft-changed from:body", &b)
}

pub fn acl(d: &ManifestDraft, n: Option<&Note>) -> String {
    let mut b = note(n);
    match &d.acl {
        None => b.push_str(r#"<p class="muted">No ACL: every member may reach every member.</p>"#),
        Some(r) if r.is_empty() => {
            b.push_str(r#"<p class="err">Empty ACL: no member may reach any other.</p>"#)
        }
        Some(rules) => {
            b.push_str("<ol>");
            for (i, r) in rules.iter().enumerate() {
                let join = |v: &[crate::manifest::Selector]| {
                    v.iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let remove = form(
                    "/a/acl/remove",
                    "acl",
                    "",
                    &format!(
                        r#"{}<button class="danger">Remove</button>"#,
                        hidden("n", &(i + 1).to_string())
                    ),
                );
                let _ = write!(
                    b,
                    "<li>{} ⟷ {} {}</li>",
                    e(&join(&r.from)),
                    e(&join(&r.to)),
                    remove
                );
            }
            b.push_str("</ol>");
        }
    }
    b.push_str(&form(
        "/a/acl/add",
        "acl",
        "",
        r#"<input name="from" placeholder="from: *, name or tag:x" required><input name="to" placeholder="to" required><button>Add rule</button>"#,
    ));
    if d.acl.is_some() {
        b.push_str(&form(
            "/a/acl/clear",
            "acl",
            r#"hx-confirm="Drop the ACL and allow everything?""#,
            r#"<button class="danger">Clear ACL</button>"#,
        ));
    }
    section("acl", "ACL (draft)", "draft-changed from:body", &b)
}

pub fn publish(d: &ManifestDraft, published: Option<&NetworkManifest>, n: Option<&Note>) -> String {
    let mut b = note(n);
    let preview = d.clone().next_manifest(now(), 0);
    let changes = diff(published, &preview);
    let acl_changed = published.map(|p| &p.acl) != Some(&preview.acl);
    match published {
        Some(p) => {
            let _ = write!(
                b,
                "<p>Published: seq {}, issued {}, expires {}.</p>",
                p.seq,
                e(&when(p.issued_at)),
                e(&left(p.expires_at))
            );
        }
        None => b.push_str("<p>Nothing published yet.</p>"),
    }
    if changes.is_empty() && !acl_changed {
        b.push_str(r#"<p class="muted">The draft matches the published manifest.</p>"#);
    } else {
        b.push_str("<ul>");
        for (what, list) in [
            ("add", &changes.added),
            ("remove", &changes.removed),
            ("change", &changes.changed),
        ] {
            for m in list {
                let _ = write!(b, "<li>{what} {}</li>", e(&m.name));
            }
        }
        if acl_changed {
            b.push_str("<li>ACL changed</li>");
        }
        b.push_str("</ul>");
    }
    b.push_str(&form(
        "/a/publish",
        "publish",
        r#"hx-confirm="Sign the draft and publish it to the network?""#,
        r#"<button>Sign &amp; publish</button> <span class="muted">Signing happens in the dashboard process; a hardware key asks for its PIN or touch on the terminal.</span>"#,
    ));
    section(
        "publish",
        "Sign & publish",
        "draft-changed from:body, every 10s",
        &b,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes() {
        assert_eq!(e(r#"<script>"'&"#), "&lt;script&gt;&quot;&#39;&amp;");
    }

    #[test]
    fn hostile_values_are_escaped() {
        let inv = InviteInfo {
            id: [1; 16],
            name: Some("<img src=x onerror=alert(1)>".into()),
            tags: vec!["\"><script>".into()],
            expires_at: now() + 60,
            uses_left: 1,
            auto_approve: false,
            created_at: 0,
        };
        let html = invites(&[inv], None, Some(&Note::Err("<b>x</b>".into())));
        assert!(!html.contains("<img"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("<b>x"));
        assert!(html.contains("&lt;img"));
    }
}
