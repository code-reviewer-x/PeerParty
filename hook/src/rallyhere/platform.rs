//! Platform sessions (`API §6.6`): a session of the game's platform (a Steam lobby made
//! through PeerParty's Steam layer, say) linked to its RallyHere session, so that a
//! player who accepts the platform's invite finds the session.
//!
//! The link is part of the session's lobby: the session JSON's `platform_session` list
//! (every member's copy shows it) and, beside it, a public attribute `LINK` holding the
//! platform session's id, decoded and lowercased, which a LAN search matches. The id
//! arrives as base64 of `"<PLATFORM>:<id>"`, from the game: it is bounded and decoded
//! defensively, and anything that isn't text is refused. Only the leader writes the link.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use peerparty_core::{Attr, Filter, Lan, Lobby, Op, Query, Value, find_attr};

use super::session::{LINK, join, leave, MAX_TEXT, NS, Session, Why, apply, find, no_lan, not_found, not_owner, render, render_for, search, short, told};
use super::{Reply, State, World};
use crate::log;
use crate::util::encoding;
use crate::util::json::Json;

/// The longest `psid_b64` taken.
const MAX_PSID: usize = 128;
/// How long a lookup waits for the LAN's answers.
const LOOKUP_WAIT: Duration = Duration::from_millis(1500);

fn bad_request(what: &str) -> Reply {
    Reply::err(400, "invalid_request", what, true)
}

fn link_not_found() -> Reply {
    Reply::err(404, "platform_session_not_found", "Platform session not found.", true)
}

/// The platform session id a `psid_b64` names: text, without control characters, at most
/// `MAX_PSID` characters encoded. None for anything else.
pub fn decode(psid_b64: &str) -> Option<String> {
    if psid_b64.is_empty() || psid_b64.len() > MAX_PSID {
        return None;
    }
    let text = String::from_utf8(encoding::base64_decode(psid_b64)?).ok()?;
    if text.trim().is_empty() || text.chars().any(char::is_control) {
        return None;
    }
    Some(text)
}

/// What a lobby's link attribute holds for a decoded id.
fn key(decoded: &str) -> String {
    decoded.trim().to_lowercase()
}

/// A platform name from a path: short, letters, digits, `-` and `_`.
fn platform_ok(p: &str) -> bool {
    !p.is_empty() && p.len() <= 32 && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The `platform_session` entry (`API §6.6`) for a session of `kind`.
fn entry(platform: &str, kind: &str, psid_b64: &str) -> Json {
    Json::obj(vec![
        ("platform", Json::str(platform)),
        ("platform_session_type", Json::str(short(kind, MAX_TEXT))),
        ("platform_session_id_base64", Json::str(psid_b64)),
        ("players", Json::Arr(Vec::new())),
    ])
}

/// The link attribute of a session's `platform_session` list: its first entry's id.
pub fn link_attr(list: &Json) -> Option<Attr> {
    let psid = list.as_arr().first()?.get("platform_session_id_base64").as_str()?.to_string();
    Some(Attr { key: LINK.into(), value: Value::Str(key(&decode(&psid)?)), public: true })
}

/// The link a lobby carries.
fn link_of(l: &Lobby) -> Option<String> {
    find_attr(&l.attrs, LINK).map(|a| a.value.text()).filter(|k| !k.is_empty())
}

/// The session among `found` that carries `link`: a lobby of ours (what a stranger
/// answers is checked again) whose attribute and `platform_session` list agree.
pub fn pick(found: Vec<Lobby>, link: &str) -> Option<Lobby> {
    found.into_iter().find(|l| l.namespace == NS && link_of(l).as_deref() == Some(link) && Session::from_lobby(l).platform_session.is_some())
}

/// The session linked to `link` on the LAN: one we are in, else a search.
fn locate(lan: &Lan, link: &str, deadline: Instant) -> Option<Lobby> {
    if let Some(l) = pick(lan.my_lobbies(NS), link) {
        return Some(l);
    }
    let mut q = Query::new(NS);
    q.max_results = 8;
    q.filters.push(Filter::Attr { key: LINK.into(), op: Op::Eq, value: Value::Str(link.into()) });
    pick(search(lan, q, deadline), link)
}

/// `POST /session/v1/platform/{platform}/platform-session/{psid_b64}/session/{id}` (the
/// leader): links the platform session to the session, replacing the list.
pub fn link(world: &World, platform: &str, psid_b64: &str, id: &str) -> Reply {
    let Some(lan) = &world.lan else { return no_lan() };
    if !platform_ok(platform) {
        return bad_request("The platform is not valid.");
    }
    if decode(psid_b64).is_none() {
        return bad_request("The platform session id is not valid.");
    }
    let Some(l) = find(lan, id) else { return not_found() };
    if l.owner != lan.me() {
        return not_owner();
    }
    let mut s = Session::from_lobby(&l);
    let e = entry(platform, &s.kind, psid_b64);
    s.platform_session = Some(Json::Arr(vec![e.clone()]));
    let mut edited = l.clone();
    edited.attrs = s.to_attrs();
    if let Err(r) = told(lan, &l.id, Why::Other, || apply(lan, &l.id, &edited)) {
        return r;
    }
    log!("rallyhere: session {} linked to a {platform} session", l.id);
    Reply::ok(e)
}

/// `DELETE` of the same path (the leader): `404 platform_session_not_found` when the
/// session isn't linked to that platform session.
pub fn unlink(world: &World, platform: &str, psid_b64: &str, id: &str) -> Reply {
    let Some(lan) = &world.lan else { return no_lan() };
    let Some(l) = find(lan, id) else { return not_found() };
    if l.owner != lan.me() {
        return not_owner();
    }
    let linked = decode(psid_b64).map(|d| key(&d)).is_some_and(|k| link_of(&l).as_deref() == Some(k.as_str()));
    if !platform_ok(platform) || !linked {
        return link_not_found();
    }
    let mut s = Session::from_lobby(&l);
    s.platform_session = None;
    let mut edited = l.clone();
    edited.attrs = s.to_attrs();
    if let Err(r) = told(lan, &l.id, Why::Other, || apply(lan, &l.id, &edited)) {
        return r;
    }
    log!("rallyhere: session {} unlinked from its platform session", l.id);
    Reply::empty(204)
}

/// `GET /session/v1/platform/{platform}/session/{psid_b64}`: the session linked to the
/// platform session, found on the LAN, or `404 session_not_found`.
pub fn lookup(world: &World, platform: &str, psid_b64: &str) -> Reply {
    let Some(lan) = &world.lan else { return no_lan() };
    let Some(decoded) = decode(psid_b64).filter(|_| platform_ok(platform)) else { return not_found() };
    let link = key(&decoded);
    match locate(lan, &link, Instant::now() + LOOKUP_WAIT) {
        Some(l) if lan.my_lobbies(NS).iter().any(|m| m.id == l.id) => Reply::ok(render_for(lan, &l)),
        Some(l) => Reply::ok(render(&l)),
        None => not_found(),
    }
}

/// `POST /session/v1/platform/{platform}/platform-session/{psid_b64}/player/me`: the
/// player accepted a platform invite; the session linked to that platform session is
/// joined as `POST /session/v1/session/{id}/player/me` does, and answered as the joiner's
/// own GET of it (the real answer isn't captured). `404 session_not_found` when nothing
/// is linked to the id.
pub fn join_linked(world: &World, state: &Mutex<State>, platform: &str, psid_b64: &str, body: &Json) -> Reply {
    let Some(lan) = &world.lan else { return no_lan() };
    let Some(decoded) = decode(psid_b64).filter(|_| platform_ok(platform)) else { return bad_request("The platform session id is not valid.") };
    let Some(found) = locate(lan, &key(&decoded), Instant::now() + LOOKUP_WAIT) else { return not_found() };
    let r = join(world, state, &found.id, body);
    if r.status != 200 {
        return r;
    }
    match lan.lobby(&found.id) {
        Some(l) => Reply::ok(render_for(lan, &l)),
        None => r,
    }
}

/// `DELETE` of the same path: the player leaves the session linked to the platform
/// session (one it is in); `404 session_not_found` when it is in none.
pub fn leave_linked(world: &World, platform: &str, psid_b64: &str) -> Reply {
    let Some(lan) = &world.lan else { return no_lan() };
    let Some(decoded) = decode(psid_b64).filter(|_| platform_ok(platform)) else { return bad_request("The platform session id is not valid.") };
    match pick(lan.my_lobbies(NS), &key(&decoded)) {
        Some(l) => leave(world, &l.id),
        None => not_found(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peerparty_core::PeerId;

    fn b64(s: &str) -> String {
        encoding::base64(s.as_bytes())
    }

    fn lobby(id: &str, ns: &str, psid: Option<&str>) -> Lobby {
        let mut l = Lobby::new(ns);
        l.id = id.into();
        l.owner = PeerId([1; 16]);
        let s = Session {
            kind: "example_match".into(),
            region: "1".into(),
            created: "t".into(),
            joinability: Default::default(),
            teams: vec![super::super::session::Team { id: 0, max_size: 4 }],
            browser: None,
            instance: None,
            platform_session: psid.map(|p| Json::Arr(vec![entry("Steam", "example_match", &b64(p))])),
            short_code: None,
            overrides: Vec::new(),
        };
        l.attrs = s.to_attrs();
        l
    }

    #[test]
    fn a_steam_lobby_id_decodes_and_garbage_does_not() {
        assert_eq!(decode(&b64("STEAM:109775244200441988")).as_deref(), Some("STEAM:109775244200441988"));
        // Unpadded reads the same.
        assert_eq!(decode(b64("STEAM:1").trim_end_matches('=')).as_deref(), Some("STEAM:1"));
        for bad in ["", "!!!", "a b", "/w==", &b64("a\u{0}b"), &b64("   "), &"QUJD".repeat(33)] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
        // Exactly the bound passes, one past it doesn't.
        assert!(decode(&"QUJD".repeat(32)).is_some());
        assert!(decode(&format!("{}QQ==", "QUJD".repeat(32))).is_none());
    }

    #[test]
    fn the_link_is_an_attribute_and_part_of_the_json() {
        let l = lobby("s1", NS, Some("STEAM:42"));
        assert_eq!(link_of(&l).as_deref(), Some("steam:42"));
        let j = render(&l);
        let p = j.get("platform_session");
        assert_eq!(p.as_arr().len(), 1);
        assert_eq!(p.as_arr()[0].to_string(), format!(r#"{{"platform":"Steam","platform_session_type":"example_match","platform_session_id_base64":"{}","players":[]}}"#, b64("STEAM:42")));
        // Unlinked: no attribute and no field.
        let none = lobby("s2", NS, None);
        assert_eq!(link_of(&none), None);
        assert_eq!(render(&none).get("platform_session"), &Json::Null);
    }

    #[test]
    fn a_lookup_picks_the_linked_session_only() {
        let found = vec![lobby("other", NS, Some("STEAM:1")), lobby("foreign", "something.else", Some("STEAM:42")), lobby("mine", NS, Some("STEAM:42")), lobby("plain", NS, None)];
        assert_eq!(pick(found.clone(), "steam:42").map(|l| l.id).as_deref(), Some("mine"));
        assert!(pick(found, "steam:7").is_none());
        assert!(pick(Vec::new(), "steam:42").is_none());
    }
}
