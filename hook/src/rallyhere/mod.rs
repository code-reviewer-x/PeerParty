//! A local stand-in for the web API of RallyHere, the game backend (identity, sessions,
//! notifications) behind some Unreal Engine games, for those games played on the LAN.
//!
//! The game's own RallyHere plugin keeps running. In a game started through PeerParty,
//! lookups of the title's RallyHere hosts resolve to this process's loopback address
//! (127.80.x.y), where PeerParty's HTTPS server (https/) answers requests whose `Host` is
//! one of them (`HTTPS`). The game's libcurl pins PeerParty's key and skips the name check
//! for every host the DNS table answers (curl/tls.rs), so the certificate needs no names here.
//!
//! Each title has its own API domain, so no host is built in and none is learned from
//! traffic: the layer is on only when the hosts are known, from `PEERPARTY_RALLYHERE_HOSTS`
//! (comma separated; it replaces the file's) or from the game's config file (config.rs,
//! which also holds its session templates). `PEERPARTY_RALLYHERE=0` or
//! `PEERPARTY_SKIP=rallyhere` turns it off; `=1` without hosts logs that they are missing
//! and stays off. A config file that is there but refused keeps it off too, with the one
//! log line that says why, even when the launcher's cache holds another.
//!
//! - config.rs: the config file, read defensively.
//! - harvest.rs: in official mode, the title data the real service answers, kept for later
//!   runs; the stand-in reads config.json's first, then these.
//! - users.rs: sign-in (always granted), the tokens, the bearer check, logout and links;
//!   every id derives from the LAN PeerId.
//! - services.rs: time, key-values, events, friends, presence, matches, recently played,
//!   performance stats and developer files.
//! - inventory.rs: every `/inventory/` route behind one entry point; reads empty, grants
//!   nothing, refuses store writes.
//! - instance.rs: a session's player-hosted instance, and its connection strings as another
//!   copy reaches the host.
//! - session.rs: sessions as LAN lobbies, their templates, and the thread that keeps the
//!   LAN going for this layer; it tells each member's copy of every change.
//! - notify.rs: the notification queue per player and its long-poll.
//!
//! Any other route gets RallyHere's error envelope with `not_implemented` and a `gap:` line
//! in the log, so a game fails fast instead of waiting.

pub mod config;
pub mod harvest;
pub mod instance;
pub mod inventory;
pub mod notify;
mod platform;
pub mod services;
pub mod session;
pub mod users;
mod voip;

use std::path::PathBuf;
use std::sync::{LazyLock, Mutex, OnceLock};

use peerparty_core::{Lan, PeerId};
use config::Config;
use services::Presence;
use users::Platform;

use crate::https::server::Request;
use crate::log;
use crate::net;
use crate::util::json::Json;

/// The title's RallyHere API on the local HTTPS server. Its certificate needs no names
/// (see the module comment).
pub static HTTPS: crate::https::HttpsService = crate::https::HttpsService {
    name: "rallyhere",
    cert_names: Vec::new,
    is_host,
    handle,
    upgrade: None,
    reads_root_early: || false,
};

/// Lookups of the title's RallyHere hosts.
pub static DNS: crate::net::dns::DnsService = crate::net::dns::DnsService { layer: "rallyhere", is_host, redirect };

/// What the switch and the known hosts make of the layer.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    On,
    Off,
    /// Asked for with `PEERPARTY_RALLYHERE=1` but no host is known: off, and worth a log line.
    MissingHosts,
}

fn decide(switch: Option<bool>, have_hosts: bool) -> Decision {
    match (switch, have_hosts) {
        (Some(false), _) => Decision::Off,
        (_, true) => Decision::On,
        (Some(true), false) => Decision::MissingHosts,
        (None, false) => Decision::Off,
    }
}

/// The hosts to answer: the environment's when it names any, else the config file's.
fn pick_hosts(env: &[String], file: &[String]) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for h in if env.is_empty() { file } else { env } {
        let h = config::normalize(h);
        if !h.is_empty() && h.len() <= config::MAX_STR && !hosts.contains(&h) && hosts.len() < config::MAX_HOSTS {
            hosts.push(h);
        }
    }
    hosts
}

/// The hosts of the environment (`env`), else of the player's config.json (`local`), else of
/// the launcher's cached config.json (`cached`, read only then). `local` is None when the
/// player's config.json is there but refused: the layer then stays off whatever the rest
/// says, so a broken file of the player's is never quietly replaced by a cached one.
fn choose_hosts<'a>(env: &[String], local: Option<&Config>, cached: impl FnOnce() -> &'a Config) -> Vec<String> {
    let Some(local) = local else { return Vec::new() };
    if !env.is_empty() {
        return pick_hosts(env, &[]);
    }
    if !local.hosts.is_empty() {
        return pick_hosts(&[], &local.hosts);
    }
    pick_hosts(&[], &cached().hosts)
}

/// The hosts this run answers (settled once; empty while the layer is off).
fn hosts() -> &'static [String] {
    static HOSTS: OnceLock<Vec<String>> = OnceLock::new();
    HOSTS.get_or_init(|| {
        let c = crate::config::HookConfig::global();
        if c.rallyhere == Some(false) || !net::enabled() || net::skip("rallyhere") {
            return Vec::new();
        }
        // A refused config.json has had its one log line (config::load_from): off, quietly.
        let local = Some(config::load()).filter(|_| !config::refused());
        let hosts = choose_hosts(&c.rallyhere_hosts, local, config::load_cached);
        if local.is_some() && decide(c.rallyhere, !hosts.is_empty()) == Decision::MissingHosts {
            log!("rallyhere: PEERPARTY_RALLYHERE is on but no hosts are known (PEERPARTY_RALLYHERE_HOSTS or \"hosts\" in config.json): staying off");
        }
        hosts
    })
}

/// Whether the title's hosts are known (in any mode) and the layer isn't switched off.
pub(super) fn has_hosts() -> bool {
    !hosts().is_empty()
}

/// Whether a request's `Host` header or a looked-up name is one of the title's.
pub fn is_host(host: &str) -> bool {
    matches(hosts(), host)
}

fn matches(hosts: &[String], host: &str) -> bool {
    let h = config::normalize(host);
    !h.is_empty() && hosts.iter().any(|x| *x == h)
}

/// Whether the stand-in is on for this game (see the module comment).
pub fn wanted() -> bool {
    net::enabled()
        && !net::skip("rallyhere")
        && decide(crate::config::HookConfig::global().rallyhere, !hosts().is_empty()) == Decision::On
        && !crate::config::modes::official("rallyhere")
}

/// The address a lookup of `host` resolves to instead, or None to leave it alone.
pub fn redirect(host: &str) -> Option<String> {
    if !is_host(host) || !wanted() {
        return None;
    }
    let h = config::normalize(host);
    let ip = crate::https::server()?;
    crate::log::throttled(&format!("rallyhere redirect {h}"), 2, |n| log!("rallyhere {h} -> {ip} (PeerParty's RallyHere) n={n}"));
    Some(ip.to_string())
}

/// The key our presence goes over the LAN under.
const PRESENCE_KEY: &str = "rallyhere.presence";

/// Who is on the LAN, as one request sees them.
pub struct World {
    pub me: PeerId,
    pub name: String,
    pub peers: Vec<WorldPeer>,
    /// The LAN the sessions live on; None in tests that need none.
    pub lan: Option<Lan>,
}

pub struct WorldPeer {
    pub id: PeerId,
    pub name: String,
    /// What the peer published of its presence, when it did.
    pub published: Option<Presence>,
}

impl World {
    /// The running LAN; None when PeerParty's LAN isn't up.
    fn current() -> Option<World> {
        let lan = net::lan()?;
        let peers = lan
            .peers()
            .into_iter()
            .map(|(id, name)| WorldPeer {
                id,
                name,
                published: lan.presence(id).iter().find(|(k, _)| k == PRESENCE_KEY).and_then(|(_, v)| Presence::decode(v)),
            })
            .collect();
        Some(World { me: lan.me(), name: lan.name().to_string(), peers, lan: Some(lan.clone()) })
    }

    /// Every LAN player, us first.
    pub fn everyone(&self) -> impl Iterator<Item = (PeerId, &str)> {
        std::iter::once((self.me, self.name.as_str())).chain(self.peers.iter().map(|p| (p.id, p.name.as_str())))
    }

    pub fn name_of(&self, peer: PeerId) -> &str {
        self.everyone().find(|(p, _)| *p == peer).map(|(_, n)| n).unwrap_or_default()
    }

    /// A player's presence: ours as set, a peer's as it published it (online until it does).
    pub fn presence_of(&self, st: &State, peer: PeerId) -> Presence {
        if peer == self.me {
            return st.my_presence();
        }
        self.peers.iter().find(|p| p.id == peer).and_then(|p| p.published.clone()).unwrap_or_default()
    }

    /// The platform and the id on it a player is known by.
    pub fn identity_of(&self, st: &State, peer: PeerId) -> (Platform, String) {
        let p = self.presence_of(st, peer);
        let id = if p.portal_user_id.is_empty() { users::player_uuid(peer) } else { p.portal_user_id };
        (users::platform_of(&p.platform), id)
    }
}

/// What this copy remembers between requests.
pub struct State {
    /// Access tokens issued, oldest first.
    access: Vec<String>,
    /// Refresh tokens issued with the platform they signed in on, oldest first.
    refresh: Vec<(String, Platform)>,
    /// The platform of the last sign-in and the player's id on it.
    platform: Option<Platform>,
    portal_user_id: String,
    presence: Presence,
    /// Matches, the most recently changed last.
    matches: Vec<Json>,
    /// The config's key-values.
    kv: Vec<(String, String)>,
    /// The config's session templates, by session type.
    templates: Vec<(String, Json)>,
    /// The regions harvested from the real service; empty for the one local region.
    regions: Vec<Json>,
    /// The sessions we were last seen in and when that list changed (`me/session`).
    my_sessions: (Vec<String>, String),
    /// The game's folder for what is kept; None keeps nothing.
    dir: Option<PathBuf>,
}

/// The most a matches file may take when read back.
const MAX_MATCHES_FILE: u64 = 16 << 20;

impl State {
    pub fn new(dir: Option<PathBuf>) -> State {
        let mut st = State {
            access: Vec::new(),
            refresh: Vec::new(),
            platform: None,
            portal_user_id: String::new(),
            presence: Presence::default(),
            matches: Vec::new(),
            kv: Vec::new(),
            templates: Vec::new(),
            regions: Vec::new(),
            my_sessions: (Vec::new(), String::new()),
            dir,
        };
        st.load_matches();
        st
    }

    fn open() -> State {
        let dir = crate::config::HookConfig::global().rallyhere_dir().or_else(|| crate::util::local_store::game_dir("rallyhere"));
        let mut st = State::new(dir);
        let title = harvest::title_data();
        st.kv = title.kv.clone();
        st.templates = title.templates.clone();
        st.regions = title.regions.clone();
        st
    }

    /// The name of the platform we last signed in on (`Anon` before any sign-in).
    pub fn platform_name(&self) -> &'static str {
        self.platform.unwrap_or(users::ANON).name
    }

    /// Our presence, with who we signed in as.
    pub fn my_presence(&self) -> Presence {
        Presence { platform: self.platform.unwrap_or(users::ANON).name.to_string(), portal_user_id: self.portal_user_id.clone(), ..self.presence.clone() }
    }

    /// Tells the LAN our presence.
    pub fn publish(&self) {
        net::set_presence("rallyhere", vec![(PRESENCE_KEY.to_string(), self.my_presence().encode())]);
    }

    fn load_matches(&mut self) {
        let Some(path) = self.dir.as_ref().map(|d| d.join("matches.json")) else { return };
        let Ok(file) = std::fs::File::open(&path) else { return };
        let mut text = String::new();
        if std::io::Read::read_to_string(&mut std::io::Read::take(file, MAX_MATCHES_FILE + 1), &mut text).is_err() || text.len() as u64 > MAX_MATCHES_FILE {
            log!("rallyhere: matches.json is unreadable or too big: ignored");
            return;
        }
        match Json::parse(&text) {
            Some(Json::Arr(a)) => {
                let valid: Vec<Json> = a.into_iter().filter(|m| matches!(m, Json::Obj(_)) && m.get("match_id").as_str().is_some()).collect();
                let skip = valid.len().saturating_sub(services::MAX_MATCHES);
                self.matches = valid.into_iter().skip(skip).collect();
            }
            _ => log!("rallyhere: matches.json is not a list of matches: ignored"),
        }
    }

    fn save_matches(&self) {
        let Some(dir) = &self.dir else { return };
        let text = Json::Arr(self.matches.clone()).to_string();
        if let Err(e) = std::fs::create_dir_all(dir).and_then(|_| std::fs::write(dir.join("matches.json"), text)) {
            log!("rallyhere: the matches could not be kept: {e}");
        }
    }
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| Mutex::new(State::open()));

/// An answer before it is sent.
#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub body: String,
    /// The `ETag` header, when there is one.
    pub etag: Option<String>,
}

impl Reply {
    pub fn ok(j: Json) -> Reply {
        Reply { status: 200, body: j.to_string(), etag: None }
    }

    pub fn empty(status: u16) -> Reply {
        Reply { status, body: String::new(), etag: None }
    }

    pub fn err(status: u16, code: &str, desc: &str, auth_success: bool) -> Reply {
        Reply { status, body: error_body(auth_success, code, desc), etag: None }
    }

    /// `body` with its ETag, or an empty 304 when the caller already has it.
    pub fn cached(body: String, if_none_match: Option<&str>) -> Reply {
        let etag = etag_of(&body);
        let same = if_none_match.is_some_and(|h| h.split(',').any(|t| t.trim() == etag));
        Reply { status: if same { 304 } else { 200 }, body: if same { String::new() } else { body }, etag: Some(etag) }
    }
}

/// A weak ETag that changes with the text.
pub fn etag_of(text: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in text.bytes() {
        h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
    }
    format!("W/\"{h}\"")
}

/// Now, as RallyHere writes times: ISO 8601 UTC with microseconds.
pub fn now_iso() -> String {
    let t = crate::util::time::iso(std::time::SystemTime::now());
    format!("{}000Z", t.trim_end_matches('Z'))
}

/// `%xx` (and `+` as a space, when `plus`) decoded; a bad escape stays as it is.
fn url_decode(s: &str, plus: bool) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let (Some(h), Some(l)) = (b.get(i + 1).and_then(|c| hex(*c)), b.get(i + 2).and_then(|c| hex(*c)))
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(if plus && b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The decoded query of a request path.
pub fn query(path: &str) -> Vec<(String, String)> {
    let Some((_, q)) = path.split_once('?') else { return Vec::new() };
    q.split('&')
        .filter(|p| !p.is_empty())
        .take(32)
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (url_decode(k, true), url_decode(v, true))
        })
        .collect()
}

/// The decoded segments of a request path, without its query.
fn segments(path: &str) -> Vec<String> {
    let bare = path.split('?').next().unwrap_or_default();
    bare.split('/').filter(|s| !s.is_empty()).map(|s| url_decode(s, false)).collect()
}

/// Answers one request to a RallyHere host: (HTTP status, JSON body).
pub fn handle(req: &Request) -> (u16, String) {
    let host = config::normalize(req.header("Host").unwrap_or_default());
    let path = req.path.split('?').next().unwrap_or_default().to_string();
    crate::log::throttled(&format!("rallyhere {} {host}{path}", req.method), 3, |n| log!("rallyhere {} {host}{path} n={n}", req.method));
    let Some(world) = World::current() else {
        return (503, error_body(true, "service_unavailable", "PeerParty's LAN isn't running"));
    };
    session::start_pump();
    let reply = route(&world, &STATE, req);
    if let Some(etag) = &reply.etag {
        crate::https::server::add_header("ETag", etag);
    }
    (reply.status, reply.body)
}

/// Dispatches a request by its first path segment, then its method and path.
///
/// `state` is locked only for as long as a route reads or changes it, never while a route
/// waits: a long-poll, a join, a search on the LAN take what they need of it first (or
/// after), so every other request of the copy (health, presence, the bearer check of the
/// next long-poll) is answered meanwhile. Under it only short leaf locks are taken (net's
/// presence table, the LAN's own for presence and the lobbies we are in), never the
/// layer's (`SEEN`, the notification queues, the join waits), and nothing takes it under
/// another lock.
pub fn route(world: &World, state: &Mutex<State>, req: &Request) -> Reply {
    let st = || crate::sys::lock(state);
    if let Some(denied) = users::check_bearer(&st(), req.header("Authorization")) {
        return denied;
    }
    let bare = req.path.split('?').next().unwrap_or_default();
    let decoded = segments(&req.path);
    let segs: Vec<&str> = decoded.iter().map(String::as_str).collect();
    let json = || Json::parse(&String::from_utf8_lossy(&req.body)).unwrap_or(Json::Null);
    let inm = req.header("If-None-Match");
    let size = req.body.len();
    match (req.method.as_str(), segs.as_slice()) {
        ("POST", ["users", "v1", "login"]) => users::login(world, &mut st(), &json()),
        ("POST", ["users", "v1", "logout"]) => users::logout(&mut st(), &json()),
        ("GET", ["users", "v2", "player", uuid, "links"]) => users::links(world, &st(), uuid),
        ("GET", ["config", "v1", "time", "utc"]) => services::time(),
        ("GET", ["config", "v2", "kv"]) => services::kv(&st(), inm),
        ("POST", ["events", "v1", "events"]) => services::events(&json()),
        ("GET", ["events", "v1", "events"]) => services::time(),
        ("GET", ["friends", "v2", "player", uuid, kind @ ("friend" | "block")]) => services::friends(world, uuid, *kind == "block", &query(&req.path)),
        ("GET", ["presence", "v1", "player", "uuid", uuid, "presence"]) => services::get_presence(world, &st(), uuid, inm),
        ("PATCH", ["presence", "v1", "player", "me", "presence"]) => services::patch_presence(&mut st(), &json()),
        ("PATCH", ["match", "v1", "match", id]) => services::patch_match(&mut st(), id, &json(), size),
        ("PATCH", ["match", "v1", "player", uuid, "match", id]) => services::patch_player(&mut st(), uuid, id, &json(), size),
        ("GET", ["match", "v1", "player", uuid, "recently-played"]) => services::recently_played(&st(), uuid),
        ("POST", ["match", "v1", "pex", which @ ("host" | "client")]) => services::pex(which),
        ("PUT", ["file", "v1", "developer-file", "match", id, name]) => services::put_file(&st(), id, name, &req.body),
        ("GET", ["session", "v1", "template"]) => session::templates(&st(), inm),
        ("POST", ["session", "v1", "session"]) => session::create(world, state, &json()),
        ("GET", ["session", "v1", "session", id]) => session::get(world, id, inm),
        ("PATCH", ["session", "v1", "session", id]) => session::patch(world, id, &json()),
        ("POST", ["session", "v1", "session", id_action]) if id_action.contains(':') => session::action(world, id_action),
        ("POST", ["session", "v1", "session", id, "player", "me"]) => session::join(world, state, id, &json()),
        ("POST", ["session", "v1", "session", id, "browser"]) => session::browser_set(world, id, &json(), false),
        ("PATCH", ["session", "v1", "session", id, "browser"]) => session::browser_set(world, id, &json(), true),
        ("POST", ["session", "v1", "session", id, "instance"]) => instance::create(world, id, &json()),
        ("PATCH", ["session", "v1", "session", id, "instance"]) => instance::patch(world, id, &json()),
        ("GET", ["session", "v1", "session", id, "instance"]) => instance::get(world, id, inm),
        ("DELETE", ["session", "v1", "session", id, "instance"]) => instance::delete(world, id),
        ("POST", ["session", "v1", "session", id, "instance", "health"]) => instance::health(world, id, &json()),
        ("POST", ["session", "v1", "platform", platform, "platform-session", psid, "session", id]) => platform::link(world, platform, psid, id),
        ("DELETE", ["session", "v1", "platform", platform, "platform-session", psid, "session", id]) => platform::unlink(world, platform, psid, id),
        ("POST", ["session", "v1", "platform", platform, "platform-session", psid, "player", "me"]) => platform::join_linked(world, state, platform, psid, &json()),
        ("DELETE", ["session", "v1", "platform", platform, "platform-session", psid, "player", "me"]) => platform::leave_linked(world, platform, psid),
        ("GET", ["session", "v1", "platform", platform, "session", psid]) => platform::lookup(world, platform, psid),
        ("GET", ["session", "v1", "browser"]) => session::browser(world, &query(&req.path)),
        ("GET", ["session", "v1", "session", id, "player", "me", "voip", "epic:join"]) => {
            let q = query(&req.path);
            let kind = q.iter().find(|(k, _)| k == "voip_session_type").map(|(_, v)| v.as_str());
            voip::epic_join(world, id, kind, &config::normalize(req.header("Host").unwrap_or_default()), bare)
        }
        ("GET", ["session", "v1", "regions"]) => session::regions(&st()),
        ("GET", ["session", "v2", "queues"]) => session::queues(inm),
        ("POST", ["session", "v1", "audit"]) => session::audit(),
        ("GET", ["session", "v1", "instance", "health", "config"]) => session::health_config(),
        ("DELETE", ["session", "v1", "session", id, "player", "me"]) => session::leave(world, id),
        ("DELETE", ["session", "v1", "session", id, "player", "uuid", uuid]) => session::kick(world, id, uuid),
        ("GET", ["session", "v1", "player", "me", "session"]) => session::my_sessions(world, &mut st(), inm),
        ("GET", ["notification", "v1", "player", uuid, "stream", "notification", "lp"]) => notify::long_poll(&users::player_uuid(world.me), uuid, &query(&req.path)),
        (_, ["inventory", ..]) => {
            let (status, body) = inventory::handle(&req.method, &req.path, &json(), &users::player_uuid(world.me));
            Reply { status, body, etag: None }
        }
        _ => {
            let host = config::normalize(req.header("Host").unwrap_or_default());
            let (status, body) = not_implemented(&req.method, &host, bare);
            Reply { status, body, etag: None }
        }
    }
}

/// The answer to a route this layer doesn't answer, with the log line that names it.
pub(crate) fn not_implemented(method: &str, host: &str, path: &str) -> (u16, String) {
    crate::log::gap("rallyhere", &format!("{method} {host}{path} (not implemented, 404)"));
    (404, error_body(true, "not_implemented", "not a route this PeerParty answers"))
}

/// RallyHere's error envelope; `auth_success` is false only for authentication failures.
pub fn error_body(auth_success: bool, code: &str, desc: &str) -> String {
    Json::obj(vec![("auth_success", Json::Bool(auth_success)), ("error_code", Json::str(code)), ("desc", Json::str(desc))]).to_string()
}

/// Builders the layer's tests share.
#[cfg(test)]
pub mod tests_support {
    use super::*;

    impl World {
        /// This world with what `peer` published of its presence.
        pub fn with_published(mut self, peer: PeerId, text: &str) -> World {
            for p in &mut self.peers {
                if p.id == peer {
                    p.published = Presence::decode(text);
                }
            }
            self
        }
    }

    pub fn test_world(me: PeerId, name: &str, peers: &[(PeerId, &str)]) -> World {
        World { me, name: name.into(), peers: peers.iter().map(|(id, n)| WorldPeer { id: *id, name: n.to_string(), published: None }).collect(), lan: None }
    }

    /// A request to the test host; `headers` are extra ones.
    pub fn request(method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Request {
        let mut h: Vec<(String, String)> = vec![("Host".into(), "api.example.test".into())];
        h.extend(headers.iter().map(|(k, v)| (k.to_string(), v.to_string())));
        Request { method: method.into(), path: path.into(), headers: h, body: body.as_bytes().to_vec() }
    }

    /// Runs one request through the router, with `st` as the copy's state.
    pub fn call_with(world: &World, st: &mut State, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Reply {
        let shared = Mutex::new(std::mem::replace(st, State::new(None)));
        let r = route(world, &shared, &request(method, path, headers, body));
        *st = shared.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner);
        r
    }

    /// Runs one request, with a bearer header when `auth` is given; (status, body).
    pub fn call(world: &World, st: &mut State, method: &str, path: &str, auth: Option<&str>, body: &str) -> (u16, String) {
        let headers: Vec<(&str, &str)> = auth.map(|a| ("Authorization", a)).into_iter().collect();
        let r = call_with(world, st, method, path, &headers, body);
        (r.status, r.body)
    }

    pub fn temp_dir(tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("peerparty-rh-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_layer_is_on_only_with_hosts_and_not_switched_off() {
        // (switch, hosts known) -> decision
        assert_eq!(decide(None, true), Decision::On);
        assert_eq!(decide(Some(true), true), Decision::On);
        assert_eq!(decide(Some(false), true), Decision::Off);
        assert_eq!(decide(None, false), Decision::Off);
        assert_eq!(decide(Some(false), false), Decision::Off);
        assert_eq!(decide(Some(true), false), Decision::MissingHosts);
    }

    #[test]
    fn hosts_come_from_the_environment_or_else_the_file() {
        let file = list(&["File.Example.Test"]);
        assert_eq!(pick_hosts(&[], &file), ["file.example.test"]);
        assert_eq!(
            pick_hosts(&list(&["a.example.test", "B.Example.Test:443", "a.example.test."]), &file),
            ["a.example.test", "b.example.test"],
            "the environment replaces the file's"
        );
        assert!(pick_hosts(&[], &[]).is_empty(), "no host is built in");
        let many: Vec<String> = (0..40).map(|i| format!("h{i}.example.test")).collect();
        assert_eq!(pick_hosts(&many, &[]).len(), config::MAX_HOSTS);
    }

    #[test]
    fn a_refused_config_keeps_the_layer_off_even_with_a_cached_one() {
        let with = |hosts: &[&str]| Config { hosts: list(hosts), ..Config::default() };
        let (local, empty, cached) = (with(&["local.example.test"]), Config::default(), with(&["cached.example.test"]));
        // config.json absent (read as empty) or without hosts: the cached one supplies them.
        assert_eq!(choose_hosts(&[], Some(&empty), || &cached), ["cached.example.test"]);
        // The player's own hosts win, and the cached file isn't read for them.
        assert_eq!(choose_hosts(&[], Some(&local), || panic!("the cached config is not read")), ["local.example.test"]);
        assert_eq!(choose_hosts(&list(&["env.example.test"]), Some(&local), || &cached), ["env.example.test"]);
        // config.json there but refused: off, whatever the cache or the environment say.
        assert!(choose_hosts(&[], None, || &cached).is_empty());
        assert!(choose_hosts(&list(&["env.example.test"]), None, || &cached).is_empty());
    }

    #[test]
    fn hosts_match_without_case_port_or_trailing_dot() {
        let hosts = list(&["api.example.test"]);
        for h in ["api.example.test", "API.Example.TEST", "api.example.test:8443", "api.example.test.", "Api.Example.Test.:443"] {
            assert!(matches(&hosts, h), "{h}");
        }
        for h in ["", "example.test", "x.api.example.test", "api.example.test.evil.test"] {
            assert!(!matches(&hosts, h), "{h}");
        }
        assert!(!matches(&[], "api.example.test"));
    }

    #[test]
    fn without_hosts_nothing_is_answered() {
        // No config in the test environment: no hosts, so no lookup is redirected.
        assert!(!is_host("api.example.test"));
        assert_eq!(redirect("api.example.test"), None);
        assert!(!wanted());
    }

    #[test]
    fn query_and_path_text_are_decoded() {
        assert_eq!(url_decode("a%20b+c%2", false), "a b+c%2");
        assert_eq!(url_decode("a%20b+c", true), "a b c");
        assert_eq!(url_decode("%zz%", true), "%zz%");
        assert_eq!(query("/x?a=1&b=x%20y+z&c&d=%41"), [("a", "1"), ("b", "x y z"), ("c", ""), ("d", "A")].map(|(k, v)| (k.to_string(), v.to_string())));
        assert!(query("/x").is_empty());
    }

    #[test]
    fn an_unknown_route_gets_the_error_envelope() {
        let req = Request {
            method: "GET".into(),
            path: "/session/v1/session/abc/player/me/voip/token?x=1".into(),
            headers: vec![("Host".into(), "API.Example.Test:443".into())],
            body: Vec::new(),
        };
        let world = tests_support::test_world(PeerId([1; 16]), "Me", &[]);
        let r = route(&world, &Mutex::new(State::new(None)), &req);
        assert_eq!(r.status, 404);
        let j = Json::parse(&r.body).unwrap();
        assert_eq!(j.get("auth_success"), &Json::Bool(true));
        assert_eq!(j.get("error_code").as_str(), Some("not_implemented"));
        assert!(j.get("desc").as_str().is_some_and(|d| !d.is_empty()));
        assert_eq!(error_body(false, "error_no_auth", "x"), r#"{"auth_success":false,"error_code":"error_no_auth","desc":"x"}"#);
    }
}
