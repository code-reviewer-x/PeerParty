//! A session's player-hosted instance (`API §6.4`) and its connection strings.
//!
//! The leader's game hosts the match and tells the service where to reach it: the
//! instance is one JSON object kept in the session's lobby (`Session::instance`), so every
//! member's copy answers it. Only the leader writes it (`not_owner` for anyone else).
//!
//! A connection string a game gives is often an address on the host's own PC:
//! `127.0.0.1:7777`, `0.0.0.0:7777`, or its LAN address. A reader on another copy can't use
//! it as it is, so it is answered rewritten to where the host is from that copy: its LAN
//! address, or its stand-in address on internet play (`Lan::game_address`, the one the
//! other SDK layers hand out). Only the host's copy knows which addresses are its own, so
//! it decides when it writes: each connection string whose IPv4 `ip:port` has a loopback,
//! unspecified or local interface address is named in a private marker of the lobby's
//! instance attribute (`MARK`; `render` never shows it). A reader rewrites the marked
//! strings only, keeping a scheme before the IP and anything after the port; every other
//! string (an EOS P2P address, a third-party server) goes through unchanged, and the host
//! reads its own as it wrote them. The host is the instance's host player; when that player
//! is no longer in the session the strings go through unchanged. Strings are never logged:
//! an address that is logged goes through `peerparty_core::redact`.
//!
//! A public session's players take a lobby's text values up to `PUBLIC_VALUE_BYTES` only
//! (core's cap on what strangers send): a longer instance would reach them as none at all.
//! So while this copy plays public sessions an instance that long is refused (`413`, and a
//! log line) rather than stored. It isn't split over several attributes: each value is
//! checked for addresses on its own on the way to a stranger (`redact::scrub`), and an
//! address cut in two would get through unreplaced.

use std::borrow::Cow;
use std::net::Ipv4Addr;

use peerparty_core::fwd::Forwarder;
use peerparty_core::{Lan, Lobby, PUBLIC_VALUE_BYTES, PeerId};

use super::config::InstanceDefaults;
use super::session::{K_INSTANCE, MAX_ATTR, MAX_TEXT, MAX_VALUE, Session, Why, apply, bound_instance, bounded_map, find, no_lan, not_found, not_owner, render_for, short, text_field, told};
use super::users::{player_id, player_uuid};
use super::{Reply, World, now_iso};
use crate::log;
use crate::util::encoding;
use crate::util::json::Json;

/// The instance's private key naming the connection strings that are the host's own.
const MARK: &str = "own_conn";
/// The connection strings of the join parameters.
const CONN: [&str; 2] = ["public_conn_str", "private_conn_str"];

fn instance_not_found() -> Reply {
    Reply::err(404, "session_instance_not_found", "Session instance not found.", true)
}

fn too_large() -> Reply {
    Reply::err(413, "payload_too_large", "The instance is too large.", true)
}

fn too_large_for_public() -> Reply {
    Reply::err(413, "payload_too_large", "The instance is too large for a public session.", true)
}

#[cfg(test)]
thread_local! {
    /// Whether a test's copy counts as playing public sessions.
    pub(super) static TEST_PUBLIC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether `lan`'s copy plays public sessions, whose players take only short lobby values.
fn plays_public(lan: &Lan) -> bool {
    #[cfg(test)]
    if TEST_PUBLIC.with(std::cell::Cell::get) {
        return true;
    }
    lan.public_status().is_some()
}

/// Whether the instance attribute `text` reaches a public session's players: no longer than
/// core's cap once our copy has written its stand-in over each address in it on the way out
/// (`redact::scrub`), each counted as long as a stand-in can be (198.18.0.0/15).
fn fits_public(text: &str) -> bool {
    let widest = Ipv4Addr::new(198, 19, 255, 255);
    peerparty_core::redact::scrub(K_INSTANCE, text, widest).map_or(text.len(), |s| s.len()) <= PUBLIC_VALUE_BYTES
}

/// The session lobby when `lan`'s copy leads it.
fn led(lan: &Lan, id: &str) -> Result<Lobby, Reply> {
    let l = find(lan, id).ok_or_else(not_found)?;
    if l.owner != lan.me() {
        return Err(not_owner());
    }
    Ok(l)
}

/// Sets the lobby's instance to `instance` (or clears it), told to our player. An
/// instance too large for a lobby attribute is refused: every copy would read it as none;
/// so is one too large for a public session's players while we play public sessions.
fn store(lan: &Lan, l: &Lobby, instance: Option<Json>) -> Result<(), Reply> {
    if let Some(i) = &instance {
        let text = i.to_string();
        if text.len() > MAX_ATTR {
            return Err(too_large());
        }
        if plays_public(lan) && !fits_public(&text) {
            crate::log::throttled(&format!("rallyhere instance too large {}", l.id), 2, |n| {
                log!("rallyhere: instance of session {} refused (413): {} bytes, more than the {PUBLIC_VALUE_BYTES} a public session's players take n={n}", l.id, text.len())
            });
            return Err(too_large_for_public());
        }
    }
    let mut s = Session::from_lobby(l);
    s.instance = instance;
    let mut edited = l.clone();
    edited.attrs = s.to_attrs();
    told(lan, &l.id, Why::Other, || apply(lan, &l.id, &edited))
}

/// `key` set to `value` in an object's pairs.
fn put(pairs: &mut Vec<(String, Json)>, key: &str, value: Json) {
    match pairs.iter_mut().find(|(k, _)| k == key) {
        Some(e) => e.1 = value,
        None => pairs.push((key.to_string(), value)),
    }
}

#[cfg(test)]
thread_local! {
    /// The defaults a test runs with instead of the config file's.
    pub(super) static TEST_DEFAULTS: std::cell::RefCell<Option<InstanceDefaults>> = const { std::cell::RefCell::new(None) };
}

/// The title's instance defaults (`config.json`, else the harvested shape, empty without
/// either).
fn defaults() -> Cow<'static, InstanceDefaults> {
    #[cfg(test)]
    if let Some(d) = TEST_DEFAULTS.with(|t| t.borrow().clone()) {
        return Cow::Owned(d);
    }
    Cow::Borrowed(&super::harvest::title_data().instance)
}

/// `pairs[key]` completed with `defaults`: the keys it has are kept, the others added.
fn fill(pairs: &mut Vec<(String, Json)>, key: &str, defaults: &[(String, Json)]) {
    if defaults.is_empty() {
        return;
    }
    match pairs.iter_mut().find(|(k, _)| k == key) {
        Some((_, Json::Obj(have))) => {
            for (k, v) in defaults {
                if !have.iter().any(|(h, _)| h == k) {
                    have.push((k.clone(), v.clone()));
                }
            }
        }
        Some((_, other)) => *other = Json::Obj(defaults.to_vec()),
        None => pairs.push((key.to_string(), Json::Obj(defaults.to_vec()))),
    }
}

/// The instance `instance` with the title's default startup and join parameters filled in
/// for the keys it has not got. Defaults are the config's: never stored in the lobby.
fn complete(instance: Json, d: &InstanceDefaults) -> Json {
    match instance {
        Json::Obj(mut pairs) if !(d.startup.is_empty() && d.join.is_empty()) => {
            fill(&mut pairs, "instance_startup_params", &d.startup);
            fill(&mut pairs, "join_params", &d.join);
            Json::Obj(pairs)
        }
        other => other,
    }
}

/// The instance as a copy shows it: without its private marker, completed with the
/// title's defaults.
pub fn visible(instance: Json) -> Json {
    match instance {
        Json::Obj(pairs) => complete(Json::Obj(pairs.into_iter().filter(|(k, _)| k != MARK).collect()), &defaults()),
        other => other,
    }
}

/// The startup parameters a game sent, kept: `map` and `mode` as text, `misc_params` and
/// the keys the title's defaults name as a string or a map of text. Anything else is dropped.
fn startup_params(p: &Json, d: &InstanceDefaults) -> Json {
    let mut out: Vec<(String, Json)> = Vec::new();
    let extra = d.startup.iter().map(|(k, _)| k.as_str()).filter(|k| !matches!(*k, "map" | "mode" | "misc_params"));
    for key in ["map", "mode", "misc_params"].into_iter().chain(extra) {
        let value = match p.get(key) {
            Json::Obj(_) if !matches!(key, "map" | "mode") => bounded_map(p.get(key)),
            Json::Str(s) if !matches!(key, "map" | "mode") => Json::str(short(s, MAX_VALUE)),
            v => match text_field(v) {
                Some(t) => Json::str(t),
                None => continue,
            },
        };
        put(&mut out, key, value);
    }
    Json::Obj(out)
}

/// `POST /session/v1/session/{id}/instance` (the leader): a new instance hosted by the
/// caller, replacing any earlier one.
pub fn create(world: &World, id: &str, body: &Json) -> Reply {
    let Some(lan) = &world.lan else { return no_lan() };
    let l = match led(lan, id) {
        Ok(l) => l,
        Err(r) => return r,
    };
    let mut pairs: Vec<(String, Json)> = Vec::new();
    let instance_id = text_field(body.get("instance_id")).filter(|i| !i.is_empty()).unwrap_or_else(encoding::uuid);
    put(&mut pairs, "instance_id", Json::str(instance_id));
    put(&mut pairs, "host_type", Json::str(text_field(body.get("host_type")).filter(|t| !t.is_empty()).unwrap_or_else(|| "player".into())));
    put(&mut pairs, "host_player_id", Json::int(player_id(lan.me())));
    put(&mut pairs, "host_player_uuid", Json::str(player_uuid(lan.me())));
    put(&mut pairs, "join_status", Json::str("requested"));
    if let Json::Obj(_) = body.get("instance_startup_params") {
        put(&mut pairs, "instance_startup_params", startup_params(body.get("instance_startup_params"), &defaults()));
    }
    put(&mut pairs, "created", Json::str(now_iso()));
    put(&mut pairs, "instance_health", Json::str("unknown"));
    let instance = bound_instance(Json::Obj(pairs));
    if let Err(r) = store(lan, &l, Some(instance.clone())) {
        return r;
    }
    log!("rallyhere: instance set for session {}", l.id);
    Reply::ok(visible(instance))
}

/// The instance `old` with a PATCH `body` merged in: status, version and match id, and the
/// join parameters (connection strings replaced, custom data merged by key). `locals` are
/// the host's own addresses: each connection string given is marked as the host's own, or
/// not, by its IP.
pub fn patched(old: Vec<(String, Json)>, body: &Json, locals: &[Ipv4Addr]) -> Json {
    let mut pairs = old;
    for key in ["join_status", "version", "match_id"] {
        if let Some(v) = text_field(body.get(key)) {
            put(&mut pairs, key, Json::str(v));
        }
    }
    if let Json::Obj(_) = body.get("join_params") {
        let given = body.get("join_params");
        let before = pairs.iter().find(|(k, _)| k == "join_params").map(|(_, v)| v.clone()).unwrap_or(Json::Null);
        let mut params: Vec<(String, Json)> = before.as_obj().to_vec();
        let mut own: Vec<String> = pairs.iter().find(|(k, _)| k == MARK).map(|(_, v)| v.as_arr().iter().filter_map(|f| f.as_str().map(str::to_string)).collect()).unwrap_or_default();
        for key in CONN {
            if let Some(v) = given.get(key).as_str() {
                put(&mut params, key, Json::str(v));
                own.retain(|f| f != key);
                if owns(v, locals) {
                    own.push(key.to_string());
                }
            }
        }
        if let Json::Obj(custom) = given.get("custom_data") {
            let mut merged: Vec<(String, Json)> = before.get("custom_data").as_obj().to_vec();
            for (k, v) in custom {
                put(&mut merged, k, v.clone());
            }
            put(&mut params, "custom_data", Json::Obj(merged));
        }
        put(&mut pairs, "join_params", Json::Obj(params));
        put(&mut pairs, MARK, Json::Arr(own.into_iter().map(Json::str).collect()));
    }
    bound_instance(Json::Obj(pairs))
}

/// `PATCH /session/v1/session/{id}/instance` (the leader): the given fields merged in.
pub fn patch(world: &World, id: &str, body: &Json) -> Reply {
    let Some(lan) = &world.lan else { return no_lan() };
    let l = match led(lan, id) {
        Ok(l) => l,
        Err(r) => return r,
    };
    let Some(Json::Obj(old)) = Session::from_lobby(&l).instance else { return instance_not_found() };
    let instance = patched(old, body, &peerparty_core::local_ipv4());
    if let Err(r) = store(lan, &l, Some(instance.clone())) {
        return r;
    }
    Reply::ok(visible(instance))
}

/// `GET /session/v1/session/{id}/instance`: the instance, as this copy reaches its host.
pub fn get(world: &World, id: &str, if_none_match: Option<&str>) -> Reply {
    let Some(lan) = &world.lan else { return no_lan() };
    let Some(l) = find(lan, id) else { return not_found() };
    let session = render_for(lan, &l);
    match session.get("instance") {
        i @ Json::Obj(_) => Reply::cached(i.to_string(), if_none_match),
        _ => instance_not_found(),
    }
}

/// `DELETE /session/v1/session/{id}/instance` (the leader).
pub fn delete(world: &World, id: &str) -> Reply {
    let Some(lan) = &world.lan else { return no_lan() };
    let l = match led(lan, id) {
        Ok(l) => l,
        Err(r) => return r,
    };
    if Session::from_lobby(&l).instance.is_none() {
        return Reply::err(404, "instance_not_found", "Instance not found.", true);
    }
    if let Err(r) = store(lan, &l, None) {
        return r;
    }
    log!("rallyhere: instance of session {} removed", l.id);
    Reply::empty(204)
}

/// `POST /session/v1/session/{id}/instance/health` (the leader): the host's report of
/// its instance's health, every few seconds.
pub fn health(world: &World, id: &str, body: &Json) -> Reply {
    let Some(lan) = &world.lan else { return no_lan() };
    let l = match led(lan, id) {
        Ok(l) => l,
        Err(r) => return r,
    };
    let Some(Json::Obj(mut pairs)) = Session::from_lobby(&l).instance else { return instance_not_found() };
    let ours = pairs.iter().find(|(k, _)| k == "instance_id").and_then(|(_, v)| v.as_str()).map(str::to_string);
    if let Some(given) = body.get("instance_id").as_str()
        && ours.as_deref() != Some(given)
    {
        return instance_not_found();
    }
    let Some(health) = text_field(body.get("instance_health")).filter(|h| !h.is_empty()) else {
        return Reply::err(400, "invalid_request", "instance_health is missing.", true);
    };
    let health = short(&health, MAX_TEXT);
    put(&mut pairs, "instance_health", Json::str(health.clone()));
    if let Err(r) = store(lan, &l, Some(Json::Obj(pairs))) {
        return r;
    }
    Reply::ok(Json::obj(vec![("updated_instance_health", Json::str(health))]))
}

// ---- connection strings ----

/// The end of a leading `scheme://` in `s` (0 when there is none).
fn scheme_len(s: &str) -> usize {
    match s.find("://") {
        Some(i) if i > 0 && s[..i].bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-')) => i + 3,
        _ => 0,
    }
}

/// Where the IP is in a connection string that is an IPv4 `ip:port` (after an optional
/// scheme, with anything after the port): the byte range of the IP, and the IP.
fn address_in(conn: &str) -> Option<(std::ops::Range<usize>, Ipv4Addr)> {
    let start = scheme_len(conn);
    let rest = &conn[start..];
    let colon = rest.find(':')?;
    let ip = rest[..colon].parse::<Ipv4Addr>().ok()?;
    let port: String = rest[colon + 1..].chars().take_while(char::is_ascii_digit).collect();
    if port.is_empty() || port.len() > 5 || port.parse::<u32>().is_ok_and(|p| p > 65535) {
        return None;
    }
    Some((start..start + colon, ip))
}

/// Whether a connection string is an address of the host's own PC: an IPv4 `ip:port` whose
/// IP is loopback, unspecified or one of `locals`.
fn owns(conn: &str, locals: &[Ipv4Addr]) -> bool {
    address_in(conn).is_some_and(|(_, ip)| ip.is_loopback() || ip.is_unspecified() || locals.contains(&ip))
}

/// A connection string for a reader that reaches the host at `to`: an IPv4 `ip:port` has
/// its IP replaced, with its scheme and what follows the port kept; any other string is
/// returned as it is.
pub fn rewrite(conn: &str, to: Ipv4Addr) -> String {
    match address_in(conn) {
        Some((ip, _)) => format!("{}{to}{}", &conn[..ip.start], &conn[ip.end..]),
        None => conn.to_string(),
    }
}

/// The instance `raw` (as the lobby holds it) for a reader that reaches the host at `to`:
/// the strings its host marked as its own rewritten, the marker gone.
pub fn for_reader(raw: &Json, to: Ipv4Addr) -> Json {
    let marked: Vec<&str> = raw.get(MARK).as_arr().iter().filter_map(Json::as_str).collect();
    let Json::Obj(pairs) = raw else { return raw.clone() };
    let out = pairs
        .iter()
        .map(|(k, v)| {
            if k != "join_params" || !matches!(v, Json::Obj(_)) {
                return (k.clone(), v.clone());
            }
            let params = v.as_obj().iter().map(|(pk, pv)| match pv.as_str() {
                Some(s) if CONN.contains(&pk.as_str()) && marked.contains(&pk.as_str()) => (pk.clone(), Json::str(rewrite(s, to))),
                _ => (pk.clone(), pv.clone()),
            });
            (k.clone(), Json::Obj(params.collect()))
        })
        .collect();
    visible(Json::Obj(out))
}

/// The address that reaches `host` from `lan`'s copy: its LAN address, or on internet play
/// its stand-in.
fn reach(lan: &Lan, host: PeerId) -> Ipv4Addr {
    match lan.game_address(host) {
        Some(std::net::IpAddr::V4(v)) => v,
        _ => Forwarder::address_of(host),
    }
}

/// The session JSON `session` of lobby `l` as `lan`'s copy answers it: when the instance's
/// host is another member, its own connection strings are rewritten to where it is from
/// here.
pub fn for_viewer(lan: &Lan, l: &Lobby, session: Json) -> Json {
    let Some(raw) = Session::from_lobby(l).instance else { return session };
    let uuid = raw.get("host_player_uuid").as_str().unwrap_or_default();
    let Some(host) = l.members.iter().map(|m| m.id).find(|id| player_uuid(*id).eq_ignore_ascii_case(uuid)) else { return session };
    if host == lan.me() {
        return session;
    }
    let Json::Obj(pairs) = session else { return session };
    let to = reach(lan, host);
    Json::Obj(pairs.into_iter().map(|(k, v)| if k == "instance" { (k, for_reader(&raw, to)) } else { (k, v) }).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rallyhere::config;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn json(s: &str) -> Json {
        Json::parse(s).unwrap()
    }

    #[test]
    fn the_ip_is_replaced_and_the_scheme_the_port_and_the_suffix_are_kept() {
        let to = ip("10.0.0.5");
        assert_eq!(rewrite("127.0.0.1:7777", to), "10.0.0.5:7777");
        assert_eq!(rewrite("0.0.0.0:7777", to), "10.0.0.5:7777");
        assert_eq!(rewrite("192.168.1.20:7777?name=x#y", to), "10.0.0.5:7777?name=x#y");
        assert_eq!(rewrite("udp://127.0.0.1:7777", to), "udp://10.0.0.5:7777");
        assert_eq!(rewrite("unreal://0.0.0.0:7777/Game?opt=1", to), "unreal://10.0.0.5:7777/Game?opt=1");
    }

    #[test]
    fn anything_that_is_not_an_ipv4_and_port_passes_unchanged() {
        let to = ip("10.0.0.5");
        for s in [
            "unreal://EOS:0123456789abcdef0123456789abcdef:GameNetDriver:7",
            "EOS:0123456789abcdef:GameNetDriver:1",
            "example.test:7777",
            "localhost:7777",
            "127.0.0.1",
            "127.0.0.1:",
            "127.0.0.1:99999",
            "127.0.0.1:x",
            "999.0.0.1:7777",
            "::1:7777",
            "[::1]:7777",
            "",
            "://127.0.0.1:7777",
            "a b://127.0.0.1:7777",
        ] {
            assert_eq!(rewrite(s, to), s, "{s}");
            assert!(!owns(s, &[ip("127.0.0.1")]), "{s}");
        }
    }

    #[test]
    fn a_connection_string_is_the_hosts_own_by_its_ip() {
        let locals = [ip("192.168.1.20")];
        for s in ["127.0.0.1:7777", "0.0.0.0:7777", "192.168.1.20:7777", "udp://192.168.1.20:7777?x=1"] {
            assert!(owns(s, &locals), "{s}");
        }
        for s in ["203.0.113.9:7777", "192.168.1.21:7777"] {
            assert!(!owns(s, &locals), "{s}");
        }
    }

    /// An instance as the host's copy stores it after its PATCH.
    fn stored(body: &str, locals: &[Ipv4Addr]) -> Json {
        let old = json(r#"{"instance_id":"i","host_player_uuid":"u","join_status":"requested"}"#);
        patched(old.as_obj().to_vec(), &json(body), locals)
    }

    #[test]
    fn the_host_marks_its_own_strings_and_a_reader_on_a_tunnel_gets_its_stand_in() {
        // The host's LAN address is 192.168.1.20: a reader through a tunnel can't use it.
        let raw = stored(
            r#"{"join_params":{"public_conn_str":"192.168.1.20:7777?team=1","private_conn_str":"unreal://EOS:0123456789abcdef0123456789abcdef:GameNetDriver:3","custom_data":{"k":"192.168.1.20:1"}}}"#,
            &[ip("192.168.1.20")],
        );
        let host = PeerId([7; 16]);
        let stand_in = Forwarder::address_of(host);
        let shown = for_reader(&raw, stand_in);
        let p = shown.get("join_params");
        assert_eq!(p.get("public_conn_str").as_str(), Some(format!("{stand_in}:7777?team=1").as_str()));
        assert_eq!(p.get("private_conn_str").as_str(), Some("unreal://EOS:0123456789abcdef0123456789abcdef:GameNetDriver:3"));
        assert_eq!(p.get("custom_data").get("k").as_str(), Some("192.168.1.20:1"));
        assert!(shown.get(MARK).is_null() && visible(raw.clone()).get(MARK).is_null());
        // A third-party server's address and a name aren't the host's: unchanged.
        let raw = stored(r#"{"join_params":{"public_conn_str":"203.0.113.9:7777","private_conn_str":"example.test:7777"}}"#, &[ip("192.168.1.20")]);
        let p = for_reader(&raw, stand_in);
        assert_eq!((p.get("join_params").get("public_conn_str").as_str(), p.get("join_params").get("private_conn_str").as_str()), (Some("203.0.113.9:7777"), Some("example.test:7777")));
        // A later PATCH of one string re-decides it alone; the other keeps its mark.
        let both = stored(r#"{"join_params":{"public_conn_str":"127.0.0.1:1","private_conn_str":"0.0.0.0:2"}}"#, &[]);
        let then = patched(both.as_obj().to_vec(), &json(r#"{"join_params":{"public_conn_str":"203.0.113.9:1"}}"#), &[]);
        let p = for_reader(&then, stand_in);
        assert_eq!((p.get("join_params").get("public_conn_str").as_str(), p.get("join_params").get("private_conn_str").as_str()), (Some("203.0.113.9:1"), Some(format!("{stand_in}:2").as_str())));
    }

    #[test]
    fn an_instance_fits_a_public_session_unless_too_long_with_its_stand_ins() {
        // A full instance as a game hosts one, connection strings and token included.
        let mut full = stored(
            r#"{"join_status":"joinable","version":"1.0.123456","match_id":"0b2c5e9a-1111-4222-8333-444455556666",
              "join_params":{"public_conn_str":"192.168.1.20:7777","private_conn_str":"unreal://EOS:0123456789abcdef0123456789abcdef:GameNetDriver:3",
              "custom_data":{"rh.SessionSecurityToken":"0123456789abcdef0123456789abcdef"}}}"#,
            &[ip("192.168.1.20")],
        );
        if let Json::Obj(p) = &mut full {
            p.push(("instance_startup_params".into(), json(r#"{"map":"/Game/Maps/Example/ExampleMap_P","mode":"example_mode","misc_params":"?listen?bIsLanMatch=1"}"#)));
            p.push(("created".into(), Json::str("2026-11-27T10:00:00.000000Z")));
        }
        assert!(fits_public(&full.to_string()), "{} bytes", full.to_string().len());
        // At the cap it fits; one byte over doesn't.
        let at = "x".repeat(PUBLIC_VALUE_BYTES);
        assert!(fits_public(&at) && !fits_public(&format!("{at}x")));
        // Addresses count as long as the stand-in our copy writes over them for a stranger.
        let near = format!("{}\"1.2.3.4:7777\"", "x".repeat(PUBLIC_VALUE_BYTES - 20));
        assert!(near.len() <= PUBLIC_VALUE_BYTES && !fits_public(&near), "{near}");
    }

    /// Runs `f` with the title's instance defaults read from a config.json's text.
    fn with_defaults<R>(config: &str, f: impl FnOnce() -> R) -> R {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                TEST_DEFAULTS.with(|t| *t.borrow_mut() = None);
            }
        }
        let _reset = Reset;
        let d = config::parse(config).unwrap().instance;
        TEST_DEFAULTS.with(|t| *t.borrow_mut() = Some(d));
        f()
    }

    const DEFAULTS: &str = r#"{"instance": {
        "instance_startup_params": {"map": "", "mode": "", "misc_params": ""},
        "join_params": {"custom_data": {}, "private_conn_str": "", "public_conn_str": ""}}}"#;

    #[test]
    fn defaults_complete_what_the_game_sent_and_never_replace_it() {
        with_defaults(DEFAULTS, || {
            let sent = json(r#"{"instance_id":"i","instance_startup_params":{"map":"/Game/Maps/X","misc_params":"?a=1"},"join_params":{"public_conn_str":"1.2.3.4:7777","custom_data":{"k":"v"}}}"#);
            let shown = visible(sent);
            assert_eq!(shown.get("instance_startup_params").to_string(), r#"{"map":"/Game/Maps/X","misc_params":"?a=1","mode":""}"#);
            assert_eq!(shown.get("join_params").to_string(), r#"{"public_conn_str":"1.2.3.4:7777","custom_data":{"k":"v"},"private_conn_str":""}"#);
            // Nothing sent yet: both objects are the defaults.
            let shown = visible(json(r#"{"instance_id":"i","own_conn":["public_conn_str"]}"#));
            assert_eq!(shown.get("instance_startup_params").to_string(), r#"{"map":"","mode":"","misc_params":""}"#);
            assert_eq!(shown.get("join_params").to_string(), r#"{"custom_data":{},"private_conn_str":"","public_conn_str":""}"#);
            assert!(shown.get(MARK).is_null(), "the marker stays private");
            // A sent object for a default string is still the game's.
            let shown = visible(json(r#"{"instance_startup_params":{"misc_params":{"a":"b"}}}"#));
            assert_eq!(shown.get("instance_startup_params").get("misc_params").get("a").as_str(), Some("b"));
            // Not an object: not an instance, left alone.
            assert_eq!(visible(Json::Null), Json::Null);
        });
    }

    #[test]
    fn without_defaults_the_output_is_unchanged() {
        let sent = json(r#"{"instance_id":"i","instance_startup_params":{"map":"m"},"own_conn":[]}"#);
        assert_eq!(visible(sent).to_string(), r#"{"instance_id":"i","instance_startup_params":{"map":"m"}}"#);
        assert_eq!(visible(json(r#"{"instance_id":"i"}"#)).to_string(), r#"{"instance_id":"i"}"#);
        with_defaults(r#"{"instance": {"join_params": {"custom_data": {}}}}"#, || {
            let shown = visible(json(r#"{"instance_id":"i"}"#));
            assert!(shown.get("instance_startup_params").is_null(), "one object configured, the other not invented");
            assert_eq!(shown.get("join_params").to_string(), r#"{"custom_data":{}}"#);
        });
    }

    #[test]
    fn a_string_misc_params_is_kept_and_bounded() {
        let d = config::parse(r#"{"instance": {"instance_startup_params": {"extra": ""}}}"#).unwrap().instance;
        let p = startup_params(&json(r#"{"map":"m","mode":"x","misc_params":"?listen","extra":"e","ignored":1}"#), &d);
        assert_eq!(p.to_string(), r#"{"map":"m","mode":"x","misc_params":"?listen","extra":"e"}"#);
        let p = startup_params(&json(r#"{"misc_params":{"a":"b","c":{"no":1}},"map":{"x":1},"extra":{"k":"v"}}"#), &InstanceDefaults::default());
        assert_eq!(p.to_string(), r#"{"misc_params":{"a":"b"}}"#, "a map of text stays one, nothing else is invented");
        let long = "x".repeat(MAX_VALUE + 50);
        let p = startup_params(&Json::obj(vec![("misc_params", Json::str(long.clone())), ("map", Json::str(long))]), &InstanceDefaults::default());
        assert_eq!(p.get("misc_params").as_str().unwrap().len(), MAX_VALUE);
        assert!(p.get("map").as_str().unwrap().len() <= MAX_TEXT);
    }

    #[test]
    fn a_reader_rewrites_the_hosts_strings_and_not_the_defaults() {
        with_defaults(r#"{"instance": {"join_params": {"private_conn_str": "", "public_conn_str": "", "custom_data": {}}}}"#, || {
            let raw = stored(r#"{"join_params":{"public_conn_str":"127.0.0.1:7777"}}"#, &[]);
            let shown = for_reader(&raw, ip("10.0.0.9"));
            assert_eq!(shown.get("join_params").get("public_conn_str").as_str(), Some("10.0.0.9:7777"));
            assert_eq!(shown.get("join_params").get("private_conn_str").as_str(), Some(""), "an empty default stays empty");
            assert!(shown.get("join_params").get("custom_data").as_obj().is_empty());
            let first = for_reader(&json(r#"{"instance_id":"i"}"#), ip("10.0.0.9"));
            assert_eq!(first.get("join_params").get("public_conn_str").as_str(), Some(""), "present before the host patches");
        });
    }

    #[test]
    fn a_hostile_instance_never_panics_the_rewrite() {
        // The owner's strings and marker are anything; the rewrite and the check hold.
        let mut rng = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let pieces = ["127.0.0.1", ":", "7777", "://", "unreal", "é", "999", "0.0.0.0", "::", "[", "]", " ", "\u{0}", "1.2.3", "99999", "-1", "a", "/"];
        for _ in 0..2000 {
            let s: String = (0..(next() % 12)).map(|_| pieces[next() as usize % pieces.len()]).collect();
            let out = rewrite(&s, ip("198.18.0.1"));
            assert!(out == s || address_in(&s).is_some(), "{s:?} -> {out:?}");
            let _ = owns(&s, &[ip("1.2.3.4")]);
            let raw = Json::obj(vec![
                ("join_params", Json::obj(vec![("public_conn_str", Json::str(&s)), ("private_conn_str", Json::Int(5))])),
                (MARK, if next() % 2 == 0 { Json::str(&s) } else { Json::Arr(vec![Json::str("public_conn_str"), Json::Null, Json::str(&s)]) }),
            ]);
            let shown = for_reader(&raw, ip("198.18.0.1"));
            assert!(shown.get(MARK).is_null());
        }
        for odd in [Json::Null, Json::str("x"), Json::Arr(vec![])] {
            let _ = for_reader(&odd, ip("198.18.0.1"));
        }
    }
}
