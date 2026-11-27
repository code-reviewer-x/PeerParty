//! Sessions (`API §6.1-6.3`) as PeerParty LAN lobbies.
//!
//! A RallyHere session is a lobby in namespace `NS` whose id is the session id and whose
//! owner is the session's leader. The session's own fields (type, region, creation time,
//! joinability, teams, browser info, instance, platform sessions, short code) are lobby
//! attributes; each player's own (team, status, version, client settings, joined time) are
//! its member attributes. Only a member may change its member attributes on the LAN, so
//! what the leader changes for other players (PATCH) is kept in one more lobby attribute,
//! `players`, which wins over the player's own. (No route lets a player change its own
//! team, version or settings after joining: a PATCH is the leader's, so there is no later
//! edit of a player's own to prefer. What a player gave when joining stays under what the
//! leader set until the leader's entry goes: it is cleared when the player joins, leaves,
//! drops or is removed, so a rejoin starts from the player's own.)
//!
//! Every member's copy renders the session JSON from its copy of the lobby alone, the
//! same way (`render`), so all copies answer the same JSON and the same ETag for the same
//! state. The leader is the lobby's owner: when it leaves or drops, the LAN's host
//! migration makes the next member the owner and so the leader.
//!
//! Each copy tells its player of every change to a session it is in (notify.rs): it keeps
//! the lobby as last seen and, after a change of its own (`told`) or the LAN's events
//! (`on_events`), tells what differs (`changes`), once per change.
//!
//! Lobby data comes from other players, so reading it never fails: a missing or malformed
//! attribute reads as unset, and what is read is bounded (`MAX_*`): over a bound an item is
//! dropped or cut, and the first time is logged.

use std::collections::HashMap;
use std::sync::{Condvar, LazyLock, Mutex, Once, OnceLock};
use std::time::{Duration, Instant};

use peerparty_core::{Attr, Event, Filter, JoinResult, Lan, LobbyError, Lobby, Member, MemberStatus, Op, Permission, PeerId, Query, Value, find_attr};

use super::users::{player_id, player_uuid};
use super::{Reply, State, World, etag_of, instance, notify, now_iso};
use crate::log;
use crate::net;
use crate::util::encoding;
use crate::util::json::Json;

/// The LAN namespace of RallyHere sessions.
pub const NS: &str = "rallyhere.session";

/// The most teams a session has.
const MAX_TEAMS: i64 = 16;
/// The most players a team holds.
const MAX_TEAM_SIZE: i64 = 64;
/// The longest text kept from a request (a version, a region, a platform name).
pub(super) const MAX_TEXT: usize = 128;
/// The region of a session created without one (`API §6.2`).
const DEFAULT_REGION: &str = "1";
const DEFAULT_TEAM_SIZE: i64 = 4;
/// The most players rendered from one lobby.
const MAX_PLAYERS: usize = 64;
/// The most entries of a custom data map, the longest key and the longest value.
const MAX_ENTRIES: usize = 64;
const MAX_KEY: usize = 64;
pub(super) const MAX_VALUE: usize = 1024;
/// The longest connection string of an instance.
const MAX_CONN: usize = 512;
/// The longest short code kept.
const MAX_SHORT_CODE: usize = 8;
/// The largest attribute read as JSON; a bigger one reads as unset.
pub(super) const MAX_ATTR: usize = 128 * 1024;
/// How long a join (finding the session, then the leader's answer) is waited for.
const JOIN_WAIT: Duration = Duration::from_secs(3);
/// How long a search for sessions (short codes, the browser) is waited for.
const SEARCH_WAIT: Duration = Duration::from_millis(1500);
const CODE_LEN: usize = 5;
const CODE_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

// Lobby attribute keys.
const K_TYPE: &str = "type";
const K_REGION: &str = "region";
const K_CREATED: &str = "created";
const K_JOINABILITY: &str = "joinability";
const K_TEAMS: &str = "teams";
const K_BROWSER: &str = "browser";
pub(super) const K_INSTANCE: &str = "instance";
/// What a stranger may know of the instance (its health and join status, nothing else), for
/// the browser: the leader keeps it in step with `instance` (`Session::to_attrs`).
const K_INSTANCE_STATE: &str = "instance_state";
const K_PLATFORM_SESSION: &str = "platform_session";
/// The public attribute a LAN search finds a platform-linked session by (`platform.rs`).
pub(super) const LINK: &str = "platform_link";
const K_SHORT_CODE: &str = "short_code";
const K_PLAYERS: &str = "players";
// Member attribute keys.
const M_TEAM: &str = "team";
const M_STATUS: &str = "status";
const M_VERSION: &str = "version";
const M_CLIENT_SETTINGS: &str = "client_settings";
const M_JOINED: &str = "joined";

/// Who may join (`API §6.1`): `joinable` is any of the three.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Joinability {
    pub open: bool,
    pub friends: bool,
    pub platform: bool,
}

impl Joinability {
    pub fn joinable(self) -> bool {
        self.open || self.friends || self.platform
    }

    /// The lobby's permission: open sessions are found by a LAN search, friends' by the
    /// players the LAN knows, the others by invitation only.
    pub fn permission(self) -> Permission {
        if self.open {
            Permission::Public
        } else if self.friends {
            Permission::Friends
        } else {
            Permission::InviteOnly
        }
    }

    fn to_json(self) -> Json {
        Json::obj(vec![("open", Json::Bool(self.open)), ("friends", Json::Bool(self.friends)), ("platform", Json::Bool(self.platform))])
    }

    fn from_json(j: &Json) -> Joinability {
        let flag = |k: &str| j.get(k).as_bool().unwrap_or(false);
        Joinability { open: flag("open"), friends: flag("friends"), platform: flag("platform") }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Team {
    pub id: i64,
    pub max_size: i64,
}

/// One player's fields; unset ones are absent from the JSON.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PlayerFields {
    pub team: Option<i64>,
    pub status: Option<String>,
    pub version: Option<String>,
    pub client_settings: Option<Json>,
    pub joined: Option<String>,
}

impl PlayerFields {
    /// As member attributes.
    pub fn to_attrs(&self) -> Vec<Attr> {
        let mut out = Vec::new();
        if let Some(t) = self.team {
            out.push(attr(M_TEAM, Value::Int(t)));
        }
        for (k, v) in [(M_STATUS, &self.status), (M_VERSION, &self.version), (M_JOINED, &self.joined)] {
            if let Some(v) = v {
                out.push(attr(k, Value::Str(v.clone())));
            }
        }
        if let Some(c) = &self.client_settings {
            out.push(attr(M_CLIENT_SETTINGS, Value::Str(c.to_string())));
        }
        out
    }

    pub fn from_attrs(attrs: &[Attr]) -> PlayerFields {
        PlayerFields {
            team: int_attr(attrs, M_TEAM),
            status: text_attr(attrs, M_STATUS),
            version: text_attr(attrs, M_VERSION),
            client_settings: json_attr(attrs, M_CLIENT_SETTINGS).and_then(|j| client_settings(&j)),
            joined: text_attr(attrs, M_JOINED),
        }
    }

    fn to_json(&self) -> Json {
        let mut out: Vec<(&str, Json)> = Vec::new();
        if let Some(t) = self.team {
            out.push(("team_id", Json::int(t)));
        }
        for (k, v) in [("status", &self.status), ("version", &self.version), ("joined", &self.joined)] {
            if let Some(v) = v {
                out.push((k, Json::str(v)));
            }
        }
        if let Some(c) = &self.client_settings {
            out.push(("client_settings", c.clone()));
        }
        Json::obj(out)
    }

    fn from_json(j: &Json) -> PlayerFields {
        let text = |k: &str| j.get(k).as_str().map(|s| short(s, MAX_TEXT));
        PlayerFields {
            team: j.get("team_id").as_i64(),
            status: text("status"),
            version: text("version"),
            client_settings: client_settings(j.get("client_settings")),
            joined: text("joined"),
        }
    }

    /// These fields with `over`'s set ones in their place.
    fn merged(&self, over: &PlayerFields) -> PlayerFields {
        PlayerFields {
            team: over.team.or(self.team),
            status: over.status.clone().or_else(|| self.status.clone()),
            version: over.version.clone().or_else(|| self.version.clone()),
            client_settings: over.client_settings.clone().or_else(|| self.client_settings.clone()),
            joined: over.joined.clone().or_else(|| self.joined.clone()),
        }
    }
}

/// A session's own fields, as its lobby's attributes hold them.
#[derive(Clone, Debug, PartialEq)]
pub struct Session {
    pub kind: String,
    pub region: String,
    pub created: String,
    pub joinability: Joinability,
    /// Never empty once read from a lobby.
    pub teams: Vec<Team>,
    /// Browser info (`API §6.5`), when the session is in the browser.
    pub browser: Option<Json>,
    pub instance: Option<Json>,
    pub platform_session: Option<Json>,
    pub short_code: Option<String>,
    /// What the leader set for players, by player uuid (lowercase).
    pub overrides: Vec<(String, PlayerFields)>,
}

impl Session {
    /// As lobby attributes. The instance, whose connection strings only members need, is
    /// kept from searchers; the rest is public, for searches by type, region and code.
    pub fn to_attrs(&self) -> Vec<Attr> {
        let mut out = vec![
            attr(K_TYPE, Value::Str(self.kind.clone())),
            attr(K_REGION, Value::Str(self.region.clone())),
            attr(K_CREATED, Value::Str(self.created.clone())),
            attr(K_JOINABILITY, Value::Str(self.joinability.to_json().to_string())),
            attr(K_TEAMS, Value::Str(Json::Arr(self.teams.iter().map(|t| Json::obj(vec![("team_id", Json::int(t.id)), ("max_size", Json::int(t.max_size))])).collect()).to_string())),
        ];
        if let Some(b) = &self.browser {
            out.push(attr(K_BROWSER, Value::Str(b.to_string())));
        }
        if let Some(i) = &self.instance {
            out.push(Attr { public: false, ..attr(K_INSTANCE, Value::Str(i.to_string())) });
            let field = |k: &str| Json::str(short(i.get(k).as_str().unwrap_or_default(), MAX_TEXT));
            out.push(attr(K_INSTANCE_STATE, Value::Str(Json::obj(vec![("instance_health", field("instance_health")), ("join_status", field("join_status"))]).to_string())));
        }
        if let Some(p) = &self.platform_session {
            out.push(attr(K_PLATFORM_SESSION, Value::Str(p.to_string())));
            out.extend(super::platform::link_attr(p));
        }
        if let Some(c) = &self.short_code {
            out.push(attr(K_SHORT_CODE, Value::Str(c.clone())));
        }
        if !self.overrides.is_empty() {
            let players = self.overrides.iter().map(|(u, f)| (u.clone(), f.to_json())).collect();
            out.push(attr(K_PLAYERS, Value::Str(Json::Obj(players).to_string())));
        }
        out
    }

    pub fn from_lobby(l: &Lobby) -> Session {
        let a = &l.attrs;
        let mut teams: Vec<Team> = Vec::new();
        for t in json_attr(a, K_TEAMS).as_ref().map(Json::as_arr).unwrap_or_default() {
            let (Some(id), Some(max_size)) = (t.get("team_id").as_i64(), t.get("max_size").as_i64()) else { continue };
            if teams.len() >= MAX_TEAMS as usize {
                over_bound("teams");
                break;
            }
            if !teams.iter().any(|x| x.id == id) {
                if !(0..=MAX_TEAM_SIZE).contains(&max_size) {
                    over_bound("team size");
                }
                teams.push(Team { id, max_size: max_size.clamp(0, MAX_TEAM_SIZE) });
            }
        }
        if teams.is_empty() {
            teams.push(Team { id: 0, max_size: DEFAULT_TEAM_SIZE });
        }
        let overrides = json_attr(a, K_PLAYERS)
            .map(|p| p.as_obj().iter().take(MAX_PLAYERS).map(|(u, f)| (short(&u.to_ascii_lowercase(), MAX_TEXT), PlayerFields::from_json(f))).collect())
            .unwrap_or_default();
        Session {
            kind: text_attr(a, K_TYPE).unwrap_or_default(),
            region: text_attr(a, K_REGION).unwrap_or_else(|| DEFAULT_REGION.into()),
            created: text_attr(a, K_CREATED).unwrap_or_default(),
            joinability: json_attr(a, K_JOINABILITY).map(|j| Joinability::from_json(&j)).unwrap_or_default(),
            teams,
            browser: json_attr(a, K_BROWSER).filter(|j| matches!(j, Json::Obj(_))).map(|j| bound_browser(&j)),
            instance: json_attr(a, K_INSTANCE).filter(|j| matches!(j, Json::Obj(_))).map(bound_instance),
            platform_session: json_attr(a, K_PLATFORM_SESSION).filter(|j| matches!(j, Json::Arr(_))),
            short_code: code_attr(a),
            overrides,
        }
    }

    /// A member's fields: its own, with what the leader set for it in their place.
    fn fields_of(&self, m: &Member) -> PlayerFields {
        let own = PlayerFields::from_attrs(&m.attrs);
        let uuid = player_uuid(m.id);
        match self.overrides.iter().find(|(u, _)| *u == uuid) {
            Some((_, over)) => own.merged(over),
            None => own,
        }
    }

    /// The team a player is on: its own if the session has it, else the first.
    fn team_of(&self, f: &PlayerFields) -> i64 {
        f.team.filter(|t| self.teams.iter().any(|x| x.id == *t)).unwrap_or(self.teams[0].id)
    }

    fn max_members(&self) -> u32 {
        self.teams.iter().map(|t| t.max_size.clamp(0, MAX_TEAM_SIZE)).sum::<i64>() as u32
    }
}

fn attr(key: &str, value: Value) -> Attr {
    Attr { key: key.into(), value, public: true }
}

/// Logs, the first time only, that lobby data went over a bound.
fn over_bound(what: &str) {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| log!("rallyhere: a lobby's {what} went over a bound and was cut or dropped (later ones aren't logged)"));
}

/// A text attribute, cut to `MAX_TEXT`.
fn text_attr(attrs: &[Attr], key: &str) -> Option<String> {
    find_attr(attrs, key).map(|a| {
        let s = match &a.value {
            Value::Str(s) => s.clone(),
            v => v.text(),
        };
        if s.len() > MAX_TEXT {
            over_bound("text");
        }
        short(&s, MAX_TEXT)
    })
}

/// The short code a lobby carries, cut to `MAX_SHORT_CODE`; none when empty.
fn code_attr(attrs: &[Attr]) -> Option<String> {
    let c = find_attr(attrs, K_SHORT_CODE).map(|a| a.value.text())?;
    if c.len() > MAX_SHORT_CODE {
        over_bound("short code");
    }
    Some(short(&c, MAX_SHORT_CODE)).filter(|c| !c.is_empty())
}

fn int_attr(attrs: &[Attr], key: &str) -> Option<i64> {
    match &find_attr(attrs, key)?.value {
        Value::Int(i) => Some(*i),
        Value::Str(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn json_attr(attrs: &[Attr], key: &str) -> Option<Json> {
    match &find_attr(attrs, key)?.value {
        Value::Str(s) if s.len() <= MAX_ATTR => Json::parse(s),
        Value::Str(_) => {
            over_bound("attribute");
            None
        }
        _ => None,
    }
}

/// The instance's health and join status a lobby shows everyone, when it has an instance.
fn instance_state(attrs: &[Attr]) -> Option<(String, String)> {
    let j = json_attr(attrs, K_INSTANCE_STATE).filter(|j| matches!(j, Json::Obj(_)))?;
    let text = |k: &str| short(j.get(k).as_str().unwrap_or_default(), MAX_TEXT);
    Some((text("instance_health"), text("join_status")))
}

/// A map of text, bounded: at most `MAX_ENTRIES` entries, keys of `MAX_KEY` bytes and
/// values of `MAX_VALUE`; scalar values are written out, others dropped.
pub(super) fn bounded_map(j: &Json) -> Json {
    let mut out: Vec<(String, Json)> = Vec::new();
    for (k, v) in j.as_obj() {
        if out.len() >= MAX_ENTRIES {
            over_bound("custom data");
            break;
        }
        let text = match v {
            Json::Str(s) => s.clone(),
            Json::Int(_) | Json::U64(_) | Json::Num(_) | Json::Bool(_) => v.to_string(),
            _ => {
                over_bound("custom data value");
                continue;
            }
        };
        if k.len() > MAX_KEY || text.len() > MAX_VALUE {
            over_bound("custom data entry");
        }
        let key = short(k, MAX_KEY);
        if !out.iter().any(|(x, _)| *x == key) {
            out.push((key, Json::str(short(&text, MAX_VALUE))));
        }
    }
    Json::Obj(out)
}

/// Browser info (`API §6.5`): its custom data bounded, its timestamp a short text.
fn bound_browser(j: &Json) -> Json {
    let ts = match j.get("created_timestamp") {
        Json::Str(s) => short(s, MAX_TEXT),
        Json::Int(_) | Json::U64(_) => j.get("created_timestamp").to_string(),
        _ => String::new(),
    };
    Json::obj(vec![("custom_data", bounded_map(j.get("custom_data"))), ("created_timestamp", Json::str(ts))])
}

/// An instance (`API §6.4`) read from a lobby: its connection strings and custom data
/// bounded.
pub(super) fn bound_instance(j: Json) -> Json {
    let Json::Obj(pairs) = j else { return j };
    let cut = |v: &Json| Json::str(short(v.as_str().unwrap_or_default(), MAX_CONN));
    Json::Obj(
        pairs
            .into_iter()
            .take(MAX_ENTRIES)
            .map(|(k, v)| match k.as_str() {
                "join_params" if matches!(v, Json::Obj(_)) => {
                    let mut p = Vec::new();
                    for f in ["public_conn_str", "private_conn_str"] {
                        if v.get(f).as_str().is_some() {
                            p.push((f, cut(v.get(f))));
                        }
                    }
                    if matches!(v.get("custom_data"), Json::Obj(_)) {
                        p.push(("custom_data", bounded_map(v.get("custom_data"))));
                    }
                    (k, Json::obj(p))
                }
                _ => (k, v),
            })
            .collect(),
    )
}

/// `s` cut to at most `max` bytes, on a character boundary.
pub(super) fn short(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// A text field of a request: a string, or a number written out.
pub(super) fn text_field(j: &Json) -> Option<String> {
    match j {
        Json::Str(s) => Some(short(s.trim(), MAX_TEXT)),
        Json::Int(_) | Json::U64(_) => Some(j.to_string()),
        _ => None,
    }
}

/// The client settings of a request (`{"platform", "input"}`), the known keys only.
fn client_settings(j: &Json) -> Option<Json> {
    let Json::Obj(_) = j else { return None };
    let kept: Vec<(String, Json)> = ["platform", "input"].iter().filter_map(|k| j.get(k).as_str().map(|s| (k.to_string(), Json::str(short(s, MAX_TEXT))))).collect();
    Some(Json::Obj(kept))
}

// ---- rendering ----

/// The session JSON (`API §6.1`) of a session lobby, the same on every copy that holds
/// the same lobby.
pub fn render(l: &Lobby) -> Json {
    let s = Session::from_lobby(l);
    if l.members.len() > MAX_PLAYERS {
        over_bound("player list");
    }
    let players: Vec<(PeerId, PlayerFields)> = l.members.iter().take(MAX_PLAYERS).map(|m| (m.id, s.fields_of(m))).collect();
    // A player on a team the session doesn't have is shown on the first one.
    let team_of = |f: &PlayerFields| s.team_of(f);
    let teams: Vec<Json> = s
        .teams
        .iter()
        .map(|t| {
            let on: Vec<Json> = players.iter().filter(|(_, f)| team_of(f) == t.id).map(|(p, f)| player_json(*p, f, *p == l.owner)).collect();
            Json::obj(vec![("team_id", Json::int(t.id)), ("max_size", Json::int(t.max_size)), ("players", Json::Arr(on))])
        })
        .collect();
    // Each platform's first player.
    let mut scouts: Vec<(String, Json)> = Vec::new();
    for (p, f) in &players {
        let platform = f.client_settings.as_ref().and_then(|c| c.get("platform").as_str()).unwrap_or_default();
        if !platform.is_empty() && !scouts.iter().any(|(k, _)| k == platform) {
            scouts.push((platform.to_string(), Json::obj(vec![("player_uuid", Json::str(player_uuid(*p))), ("platform", Json::str(platform))])));
        }
    }
    let mut out: Vec<(&str, Json)> = vec![("type", Json::str(&s.kind)), ("session_id", Json::str(short(&l.id, MAX_TEXT)))];
    if let Some(i) = s.instance {
        out.push(("instance", instance::visible(i)));
    }
    out.extend([
        ("joinable", Json::Bool(s.joinability.joinable())),
        ("joinability", Json::obj(vec![("open", Json::Bool(s.joinability.open)), ("friends", Json::Bool(s.joinability.friends))])),
        ("teams", Json::Arr(teams)),
    ]);
    if let Some(p) = s.platform_session {
        out.push(("platform_session", p));
    }
    out.extend([("platform_scouts", Json::Obj(scouts)), ("created", Json::str(&s.created)), ("region_id", Json::str(&s.region))]);
    if let Some(c) = s.short_code {
        out.push(("short_code", Json::str(c)));
    }
    Json::obj(out)
}

fn player_json(peer: PeerId, f: &PlayerFields, leader: bool) -> Json {
    // The leader is the lobby's owner, and only it: a status says the rest.
    let status = match f.status.as_deref() {
        _ if leader => "leader",
        Some(s @ ("member" | "invited" | "reserved")) => s,
        _ => "member",
    };
    let mut out = vec![("player_id", Json::int(player_id(peer))), ("player_uuid", Json::str(player_uuid(peer))), ("status", Json::str(status))];
    if let Some(v) = &f.version {
        out.push(("version", Json::str(v)));
    }
    if let Some(c) = &f.client_settings {
        out.push(("client_settings", c.clone()));
    }
    if let Some(j) = &f.joined {
        out.push(("joined", Json::str(j)));
    }
    Json::obj(out)
}

/// The session's ETag: of its JSON, so equal on every copy for one state and new with
/// any change the JSON shows.
#[cfg(test)]
pub fn etag(l: &Lobby) -> String {
    etag_of(&render(l).to_string())
}

/// The session JSON as `lan`'s copy answers it: `render`, with the instance's connection
/// strings rewritten for a reader other than the host (instance.rs).
pub fn render_for(lan: &Lan, l: &Lobby) -> Json {
    instance::for_viewer(lan, l, render(l))
}

/// The ETag of `render_for`.
fn etag_for(lan: &Lan, l: &Lobby) -> String {
    etag_of(&render_for(lan, l).to_string())
}

// ---- requests ----

pub(super) fn not_found() -> Reply {
    Reply::err(404, "session_not_found", "Session not found.", true)
}

pub(super) fn not_owner() -> Reply {
    Reply::err(404, "not_owner", "Only the session's leader may do this.", true)
}

pub(super) fn no_lan() -> Reply {
    Reply::err(503, "service_unavailable", "PeerParty's LAN isn't running", true)
}

/// The session a path names by id or short code, among those this copy is in.
pub(super) fn find(lan: &Lan, id: &str) -> Option<Lobby> {
    let mine = lan.my_lobbies(NS);
    let by_id = mine.iter().position(|l| l.id.eq_ignore_ascii_case(id));
    let i = by_id.or_else(|| mine.iter().position(|l| code_attr(&l.attrs).is_some_and(|c| c.eq_ignore_ascii_case(id))))?;
    mine.into_iter().nth(i)
}

/// The template of a session type: by its key, or else by its `session_type`.
fn template<'a>(st: &'a State, kind: &str) -> Option<&'a Json> {
    st.templates.iter().find(|(k, _)| k == kind).or_else(|| st.templates.iter().find(|(_, t)| t.get("session_type").as_str() == Some(kind))).map(|(_, t)| t)
}

/// `GET /session/v1/template`: the config's templates, each with its `session_type`.
pub fn templates(st: &State, if_none_match: Option<&str>) -> Reply {
    let all = st
        .templates
        .iter()
        .map(|(k, t)| {
            let mut t = t.clone();
            if let Json::Obj(p) = &mut t
                && !p.iter().any(|(f, _)| f == "session_type")
            {
                p.insert(0, ("session_type".into(), Json::str(k)));
            }
            (k.clone(), t)
        })
        .collect();
    Reply::cached(Json::obj(vec![("templates", Json::Obj(all))]).to_string(), if_none_match)
}

/// `POST /session/v1/session`: a new session of a type the config has a template for,
/// led by us. A player already in a session of that type gets that one. `state` is read
/// first and let go: creating the lobby doesn't hold it.
pub fn create(world: &World, state: &Mutex<State>, body: &Json) -> Reply {
    let kind = body.get("session_type").as_str().unwrap_or_default();
    let (template, platform) = {
        let st = crate::sys::lock(state);
        (template(&st, kind).cloned(), st.platform_name())
    };
    let Some(t) = template else {
        crate::log::gap("rallyhere", &format!("session template \"{}\" isn't in the title's data (config.json, harvested or cached) (404)", short(kind, MAX_TEXT)));
        return Reply::err(404, "session_template_not_found", "Session template not found.", true);
    };
    let Some(lan) = &world.lan else { return no_lan() };
    lan.set_join_check(NS, join_check);
    if let Some(l) = lan.my_lobbies(NS).into_iter().find(|l| text_attr(&l.attrs, K_TYPE).as_deref() == Some(kind)) {
        return Reply::ok(Json::obj(vec![("session_id", Json::str(l.id))]));
    }
    let num_teams = t.get("num_teams").as_i64().filter(|n| *n > 0).unwrap_or(1).min(MAX_TEAMS);
    let per_team = t.get("players_per_team").as_i64().filter(|n| *n > 0).unwrap_or(DEFAULT_TEAM_SIZE).min(MAX_TEAM_SIZE);
    let now = now_iso();
    let session = Session {
        kind: kind.to_string(),
        region: text_field(body.get("region_id")).filter(|r| !r.is_empty()).unwrap_or_else(|| DEFAULT_REGION.into()),
        created: now.clone(),
        // Open as the template says; LAN players are the player's friends.
        joinability: Joinability { open: t.get("default_public").as_bool().unwrap_or(false), friends: true, platform: false },
        teams: (0..num_teams).map(|id| Team { id, max_size: per_team }).collect(),
        browser: None,
        instance: None,
        platform_session: None,
        short_code: None,
        overrides: Vec::new(),
    };
    let settings = client_settings(body.get("client_settings")).unwrap_or_else(|| Json::obj(vec![("platform", Json::str(platform))]));
    let mine = PlayerFields {
        team: Some(0),
        status: None,
        version: text_field(body.get("client_version")),
        client_settings: Some(settings),
        joined: Some(now),
    };
    let mut l = Lobby::new(NS);
    l.id = encoding::uuid();
    l.max_members = session.max_members();
    l.permission = session.joinability.permission();
    l.join_by_id = true;
    l.host_migration = true;
    l.attrs = session.to_attrs();
    l.members = vec![Member { id: lan.me(), attrs: mine.to_attrs() }];
    let id = l.id.clone();
    match told(lan, &id, Why::Create, || lan.create_lobby(l)) {
        Ok(l) => {
            log!("rallyhere: created session {} ({kind}, {} players at most)", l.id, l.max_members);
            Reply::ok(Json::obj(vec![("session_id", Json::str(l.id))]))
        }
        Err(e) => Reply::err(500, "session_create_failed", &format!("{e:?}"), true),
    }
}

/// `GET /session/v1/session/{id or short code}`.
pub fn get(world: &World, id: &str, if_none_match: Option<&str>) -> Reply {
    let Some(lan) = &world.lan else { return no_lan() };
    match find(lan, id) {
        Some(l) => Reply::cached(render_for(lan, &l).to_string(), if_none_match),
        None => not_found(),
    }
}

/// The lobby with a PATCH (`API §6.2`) merged in: region, joinability, teams by
/// `team_id`, players by uuid (members only). A password is ignored.
pub fn patched(l: &Lobby, body: &Json) -> Lobby {
    let mut s = Session::from_lobby(l);
    if let Some(r) = text_field(body.get("region_id")).filter(|r| !r.is_empty()) {
        s.region = r;
    }
    // `joinable: false` closes the session; `true` opens it to friends when it was closed.
    match body.get("joinable").as_bool() {
        Some(false) => s.joinability = Joinability::default(),
        Some(true) if !s.joinability.joinable() => s.joinability.friends = true,
        _ => {}
    }
    let j = body.get("joinability");
    for (key, flag) in [("open", &mut s.joinability.open), ("friends", &mut s.joinability.friends), ("platform", &mut s.joinability.platform)] {
        if let Some(b) = j.get(key).as_bool() {
            *flag = b;
        }
    }
    for t in body.get("teams").as_arr().iter().take(MAX_TEAMS as usize) {
        let Some(id) = t.get("team_id").as_i64() else { continue };
        if !s.teams.iter().any(|x| x.id == id) {
            if s.teams.len() >= MAX_TEAMS as usize {
                continue;
            }
            s.teams.push(Team { id, max_size: DEFAULT_TEAM_SIZE });
        }
        if let (Some(n), Some(team)) = (t.get("max_size").as_i64().filter(|n| (1..=MAX_TEAM_SIZE).contains(n)), s.teams.iter_mut().find(|x| x.id == id)) {
            team.max_size = n;
        }
        for p in t.get("players").as_arr().iter().take(MAX_TEAM_SIZE as usize) {
            let Some(uuid) = p.get("player_uuid").as_str() else { continue };
            let Some(m) = l.members.iter().find(|m| player_uuid(m.id).eq_ignore_ascii_case(uuid)) else { continue };
            let uuid = player_uuid(m.id);
            let i = match s.overrides.iter().position(|(u, _)| *u == uuid) {
                Some(i) => i,
                None => {
                    s.overrides.push((uuid, PlayerFields::default()));
                    s.overrides.len() - 1
                }
            };
            let f = &mut s.overrides[i].1;
            f.team = Some(id);
            if let Some(st) = p.get("status").as_str().filter(|v| matches!(*v, "member" | "invited" | "reserved")) {
                f.status = Some(st.to_string());
            }
            if let Some(v) = text_field(p.get("version")) {
                f.version = Some(v);
            }
            if let Some(c) = client_settings(p.get("client_settings")) {
                f.client_settings = Some(c);
            }
            if let Some(v) = p.get("joined").as_str() {
                f.joined = Some(short(v, MAX_TEXT));
            }
        }
    }
    let mut out = l.clone();
    pruned(&mut s, l);
    out.max_members = s.max_members();
    out.permission = s.joinability.permission();
    out.attrs = s.to_attrs();
    out
}

/// Forgets what the leader set for players who are no longer members.
fn pruned(s: &mut Session, l: &Lobby) {
    s.overrides.retain(|(u, _)| l.members.iter().any(|m| player_uuid(m.id) == *u));
}

/// Sets a lobby we lead to `edited`. The LAN ignores an edit when the lobby is no longer
/// ours (a host migration got there first), so ownership is checked after the update:
/// then the answer is `not_owner`, not a 200 for a change that wasn't made.
pub(super) fn apply(lan: &Lan, id: &str, edited: &Lobby) -> Result<(), Reply> {
    if lan.update(id, Some(edited), &[], &[]).is_err() {
        return Err(not_found());
    }
    if !lan.is_owner(id) {
        return Err(not_owner());
    }
    Ok(())
}

/// `PATCH /session/v1/session/{id}` (the leader only).
pub fn patch(world: &World, id: &str, body: &Json) -> Reply {
    let Some(lan) = &world.lan else { return no_lan() };
    let Some(l) = find(lan, id) else { return not_found() };
    if l.owner != lan.me() {
        return not_owner();
    }
    if let Err(r) = told(lan, &l.id, Why::Patch, || apply(lan, &l.id, &patched(&l, body))) {
        return r;
    }
    match lan.lobby(&l.id) {
        Some(l) => Reply::cached(render_for(lan, &l).to_string(), None),
        None => not_found(),
    }
}

/// `DELETE /session/v1/session/{id}/player/me`: we leave; a leader hands the session on.
pub fn leave(world: &World, id: &str) -> Reply {
    let Some(lan) = &world.lan else { return no_lan() };
    let Some(l) = find(lan, id) else { return not_found() };
    match told(lan, &l.id, Why::Leave, || lan.leave(&l.id)) {
        Ok(()) => {
            log!("rallyhere: left session {}", l.id);
            Reply::empty(204)
        }
        Err(_) => not_found(),
    }
}

/// `DELETE /session/v1/session/{id}/player/uuid/{uuid}`: our own uuid leaves; the leader
/// removes another player.
pub fn kick(world: &World, id: &str, uuid: &str) -> Reply {
    let Some(lan) = &world.lan else { return no_lan() };
    if uuid.eq_ignore_ascii_case(&player_uuid(lan.me())) {
        return leave(world, id);
    }
    let Some(l) = find(lan, id) else { return not_found() };
    if l.owner != lan.me() {
        return not_owner();
    }
    let Some(target) = l.members.iter().map(|m| m.id).find(|p| player_uuid(*p).eq_ignore_ascii_case(uuid)) else {
        return Reply::err(404, "session_player_not_found", "No such player in the session.", true);
    };
    let kicked = told(lan, &l.id, Why::Other, || {
        lan.kick(&l.id, target)?;
        if let Some(mut after) = lan.lobby(&l.id) {
            let mut s = Session::from_lobby(&after);
            let before = s.overrides.len();
            pruned(&mut s, &after);
            if s.overrides.len() != before {
                after.attrs = s.to_attrs();
                let _ = lan.update(&l.id, Some(&after), &[], &[]);
            }
        }
        Ok::<(), LobbyError>(())
    });
    if kicked.is_err() {
        return not_found();
    }
    log!("rallyhere: removed {uuid} from session {}", l.id);
    Reply::empty(204)
}

/// `GET /session/v1/player/me/session`: the sessions we are in, by type; `{}` in none.
pub fn my_sessions(world: &World, st: &mut State, if_none_match: Option<&str>) -> Reply {
    let Some(lan) = &world.lan else { return no_lan() };
    let mut mine: Vec<(String, String)> = lan.my_lobbies(NS).iter().map(|l| (text_attr(&l.attrs, K_TYPE).unwrap_or_default(), l.id.clone())).collect();
    mine.sort();
    let ids: Vec<String> = mine.iter().map(|(_, id)| id.clone()).collect();
    // The time our list last changed, kept so that an unchanged list keeps its ETag.
    if st.my_sessions.0 != ids || st.my_sessions.1.is_empty() {
        st.my_sessions = (ids, now_iso());
    }
    if mine.is_empty() {
        return Reply::cached("{}".into(), if_none_match);
    }
    let body = Json::obj(vec![("sessions", Json::Obj(group_by_type(mine))), ("last_updated_timestamp", Json::str(&st.my_sessions.1))]);
    Reply::cached(body.to_string(), if_none_match)
}

/// `(type, id)` pairs as `type -> {type, session_ids}`, in the order the types first appear.
fn group_by_type(sessions: Vec<(String, String)>) -> Vec<(String, Json)> {
    let mut by_type: Vec<(String, Json)> = Vec::new();
    for (kind, id) in sessions {
        match by_type.iter_mut().find(|(k, _)| *k == kind) {
            Some((_, Json::Obj(o))) => {
                if let Some((_, Json::Arr(ids))) = o.iter_mut().find(|(k, _)| k == "session_ids") {
                    ids.push(Json::str(id));
                }
            }
            _ => by_type.push((kind.clone(), Json::obj(vec![("type", Json::str(&kind)), ("session_ids", Json::Arr(vec![Json::str(id)]))]))),
        }
    }
    by_type
}

// ---- joining ----

/// Results of the LAN's searches and joins, handed from the pump (`on_events`) to the
/// request waiting for them; by our peer id too, since one process may hold two copies.
#[derive(Default)]
struct Waits {
    searches: HashMap<(PeerId, u64), Vec<Lobby>>,
    joins: HashMap<(PeerId, String), JoinResult>,
}

/// More results than requests can be waiting for: older ones are dropped.
const MAX_WAITS: usize = 32;

static WAITS: LazyLock<(Mutex<Waits>, Condvar)> = LazyLock::new(Default::default);

/// The joins running, by our peer id and the session.
static JOINING: Mutex<Vec<(PeerId, String)>> = Mutex::new(Vec::new());

/// Forgets a join as running when dropped.
struct Joining(PeerId, String);

impl Drop for Joining {
    fn drop(&mut self) {
        crate::sys::lock(&JOINING).retain(|(p, i)| !(*p == self.0 && *i == self.1));
    }
}

/// A search on the LAN, waited for until `deadline`; empty when nobody answers.
pub(super) fn search(lan: &Lan, query: Query, deadline: Instant) -> Vec<Lobby> {
    let key = (lan.me(), lan.search(query));
    let (m, cv) = &*WAITS;
    let mut w = crate::sys::lock(m);
    loop {
        if let Some(r) = w.searches.remove(&key) {
            return r;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Vec::new();
        }
        w = cv.wait_timeout(w, left).unwrap().0;
    }
}

/// The end of a join the LAN is running, waited for until `deadline`.
fn wait_join(lan: &Lan, lobby: &str, deadline: Instant) -> JoinResult {
    let key = (lan.me(), lobby.to_string());
    let (m, cv) = &*WAITS;
    let mut w = crate::sys::lock(m);
    loop {
        if let Some(r) = w.joins.remove(&key) {
            return r;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return JoinResult::TimedOut;
        }
        w = cv.wait_timeout(w, left).unwrap().0;
    }
}

/// The leader's copy decides who joins (`Lan::set_join_check`): the session must be
/// joinable, and the team the joiner asks for (its secret, a team id; none is the first)
/// must exist and have room. The LAN refuses a full session itself.
fn join_check(l: &Lobby, joiner: PeerId, secret: &str) -> Option<JoinResult> {
    let s = Session::from_lobby(l);
    if !s.joinability.joinable() {
        return Some(JoinResult::NotAllowed);
    }
    let want = match secret.trim() {
        "" => s.teams[0].id,
        t => match t.parse::<i64>() {
            Ok(t) => t,
            Err(_) => return Some(JoinResult::WrongSecret),
        },
    };
    let Some(team) = s.teams.iter().find(|t| t.id == want) else { return Some(JoinResult::WrongSecret) };
    let on_it = l.members.iter().take(MAX_PLAYERS).filter(|m| m.id != joiner && s.team_of(&s.fields_of(m)) == team.id).count() as i64;
    (on_it >= team.max_size).then_some(JoinResult::Full)
}

/// The `400` of a join the leader's copy refused (`API §6.3`), or the `404` of one nobody
/// answered.
fn join_error(r: JoinResult) -> Reply {
    let (code, desc) = match r {
        JoinResult::Ok => return Reply::empty(200),
        JoinResult::NotFound | JoinResult::TimedOut => return not_found(),
        JoinResult::Full => ("session_full", "Join rejected by host"),
        JoinResult::WrongSecret => ("team_not_found", "Join rejected by host"),
        JoinResult::NotAllowed => ("session_not_joinable", "Join rejected by host"),
    };
    Reply::err(400, code, desc, true)
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36 && s.bytes().enumerate().all(|(i, b)| if matches!(i, 8 | 13 | 18 | 23) { b == b'-' } else { b.is_ascii_hexdigit() })
}

/// The session a short code names, by a LAN search on the short code attribute.
fn find_by_code(lan: &Lan, code: &str, deadline: Instant) -> Option<Lobby> {
    let mut q = Query::new(NS);
    q.max_results = 8;
    q.filters.push(Filter::Attr { key: K_SHORT_CODE.into(), op: Op::Eq, value: Value::Str(code.into()) });
    // What a stranger answers is checked again: only a lobby that really carries the code.
    search(lan, q, deadline).into_iter().take(8).find(|l| l.namespace == NS && code_attr(&l.attrs).is_some_and(|c| c.eq_ignore_ascii_case(code)))
}

/// `POST /session/v1/session/{id or short code}/player/me`: we join, as a member of the
/// team asked for (the first by default). The join waits on the LAN (`JOIN_WAIT`) without
/// `state`, which is locked only to read the platform once joined.
pub fn join(world: &World, state: &Mutex<State>, id: &str, body: &Json) -> Reply {
    let Some(lan) = &world.lan else { return no_lan() };
    if find(lan, id).is_some() {
        return Reply::err(400, "already_in_session", "Already in the session.", true);
    }
    let me = lan.me();
    let team = body.get("team_id").as_i64().unwrap_or(0);
    let secret = team.to_string();
    let deadline = Instant::now() + JOIN_WAIT;
    let key = id.to_ascii_lowercase();
    {
        let mut running = crate::sys::lock(&JOINING);
        if running.iter().any(|(p, i)| *p == me && *i == key) || running.len() >= MAX_WAITS {
            return Reply::err(400, "session_join_already_in_progress", "Another join of the session is running.", true);
        }
        running.push((me, key.clone()));
    }
    let _running = Joining(me, key.clone());
    lan.set_join_check(NS, join_check);
    // By id the LAN asks everyone; by short code a search finds the lobby first.
    let lobby_id = if is_uuid(id) {
        let lid = id.to_ascii_lowercase();
        crate::sys::lock(&WAITS.0).joins.remove(&(me, lid.clone()));
        match lan.join_by_id_with(NS, &lid, &secret) {
            Ok(()) => lid,
            Err(LobbyError::AlreadyIn) => return Reply::err(400, "session_join_already_in_progress", "Another join of the session is running.", true),
            Err(_) => return not_found(),
        }
    } else {
        let code = id.to_ascii_uppercase();
        if code.len() > MAX_SHORT_CODE || !code.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return not_found();
        }
        let Some(found) = find_by_code(lan, &code, deadline) else { return not_found() };
        crate::sys::lock(&WAITS.0).joins.remove(&(me, found.id.clone()));
        match lan.join_with(&found, &secret) {
            Ok(()) => found.id,
            Err(LobbyError::AlreadyIn) => return Reply::err(400, "session_join_already_in_progress", "Another join of the session is running.", true),
            Err(_) => return not_found(),
        }
    };
    let result = wait_join(lan, &lobby_id, deadline.max(Instant::now() + Duration::from_millis(500)));
    if result != JoinResult::Ok {
        // A join nobody answered is dropped, so that a retry starts afresh.
        if matches!(result, JoinResult::TimedOut | JoinResult::NotFound) {
            let _ = lan.leave(&lobby_id);
        }
        return join_error(result);
    }
    let platform = crate::sys::lock(state).platform_name();
    let mine = PlayerFields {
        team: Some(team),
        status: None,
        version: text_field(body.get("client_version")),
        client_settings: Some(client_settings(body.get("client_settings")).unwrap_or_else(|| Json::obj(vec![("platform", Json::str(platform))]))),
        joined: Some(now_iso()),
    };
    let _ = told(lan, &lobby_id, Why::Other, || lan.update(&lobby_id, None, &mine.to_attrs(), &[]));
    log!("rallyhere: joined session {lobby_id}");
    Reply::ok(Json::obj(vec![("player_uuid", Json::str(player_uuid(me))), ("status", Json::str("member")), ("team_id", Json::int(team))]))
}

// ---- short codes, browser and the small routes ----

/// `POST /session/v1/session/{id}:{action}`: `generate-short-code` is the one action.
pub fn action(world: &World, id_action: &str) -> Reply {
    let (id, name) = id_action.split_once(':').unwrap_or((id_action, ""));
    if name != "generate-short-code" {
        return Reply::err(400, "session_action_error", &format!("Session action \"{}\" not supported.", short(name, MAX_TEXT)), true);
    }
    let Some(lan) = &world.lan else { return no_lan() };
    let Some(l) = find(lan, id) else { return not_found() };
    if l.owner != lan.me() {
        return not_owner();
    }
    // A code no session the LAN shows us already has.
    let mut taken: Vec<String> = lan.my_lobbies(NS).iter().filter_map(|l| code_attr(&l.attrs)).collect();
    let mut q = Query::new(NS);
    q.max_results = 50;
    taken.extend(search(lan, q, Instant::now() + SEARCH_WAIT).iter().take(50).filter_map(|l| code_attr(&l.attrs)));
    let Some(code) = new_code(&taken) else {
        return Reply::err(500, "session_action_error", "No short code was free.", true);
    };
    let mut s = Session::from_lobby(&l);
    s.short_code = Some(code.clone());
    let mut edited = l.clone();
    edited.attrs = s.to_attrs();
    if let Err(r) = told(lan, &l.id, Why::Other, || apply(lan, &l.id, &edited)) {
        return r;
    }
    Reply::ok(Json::obj(vec![("short_code", Json::str(code))]))
}

/// A code of `CODE_LEN` characters of A-Z0-9 that isn't in `taken` (any case).
fn new_code(taken: &[String]) -> Option<String> {
    (0..64).map(|_| encoding::random_text(CODE_LEN, CODE_ALPHABET)).find(|c| !taken.iter().any(|t| t.eq_ignore_ascii_case(c)))
}

/// `POST|PATCH /session/v1/session/{id}/browser` (the leader): browser info is replaced
/// (POST) or merged into (PATCH).
pub fn browser_set(world: &World, id: &str, body: &Json, merge: bool) -> Reply {
    let Some(lan) = &world.lan else { return no_lan() };
    let Some(l) = find(lan, id) else { return not_found() };
    if l.owner != lan.me() {
        return not_owner();
    }
    let mut s = Session::from_lobby(&l);
    let old = s.browser.clone().unwrap_or(Json::Null);
    let mut custom: Vec<(String, Json)> = if merge { old.get("custom_data").as_obj().to_vec() } else { Vec::new() };
    for (k, v) in body.get("custom_data").as_obj() {
        match custom.iter_mut().find(|(x, _)| x == k) {
            Some(e) => e.1 = v.clone(),
            None => custom.push((k.clone(), v.clone())),
        }
    }
    let ts = match body.get("created_timestamp") {
        Json::Null if merge && old.get("created_timestamp").as_str().is_some_and(|t| !t.is_empty()) => old.get("created_timestamp").clone(),
        Json::Null => Json::str(now_iso()),
        t => t.clone(),
    };
    let browser = bound_browser(&Json::obj(vec![("custom_data", Json::Obj(custom)), ("created_timestamp", ts)]));
    s.browser = Some(browser.clone());
    let mut edited = l.clone();
    edited.attrs = s.to_attrs();
    if let Err(r) = told(lan, &l.id, Why::Other, || apply(lan, &l.id, &edited)) {
        return r;
    }
    Reply::ok(browser)
}

/// One session as a browser entry (`API §6.5`), read from its lobby.
pub fn browser_entry(l: &Lobby) -> Json {
    let s = Session::from_lobby(l);
    let custom = s.browser.as_ref().map(|b| bounded_map(b.get("custom_data"))).unwrap_or(Json::Obj(Vec::new()));
    // Members read the instance itself; a stranger, the health the leader publishes.
    let health = s
        .instance
        .as_ref()
        .and_then(|i| i.get("instance_health").as_str())
        .map(|h| short(h, MAX_TEXT))
        .or_else(|| instance_state(&l.attrs).map(|(h, _)| h))
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "unknown".into());
    Json::obj(vec![
        ("session_id", Json::str(short(&l.id, MAX_TEXT))),
        ("instance_health", Json::str(health)),
        ("player_count", Json::int(l.members.len().min(MAX_PLAYERS) as i64)),
        ("max_player_count", Json::int(i64::from(s.max_members()))),
        ("custom_data", custom),
    ])
}

/// `GET /session/v1/browser?session_type=&region_id=&cursor=&page_size=`: the sessions
/// that have an instance (`API §6.5`) and that we are in or the LAN shows, of the
/// type and region asked for, `page_size` (1..=50, 50 by default) from `cursor`.
pub fn browser(world: &World, query: &[(String, String)]) -> Reply {
    let Some(lan) = &world.lan else { return no_lan() };
    let get = |k: &str| query.iter().find(|(x, _)| x == k).map(|(_, v)| v.as_str()).filter(|v| !v.is_empty());
    let (kind, region) = (get("session_type"), get("region_id"));
    let cursor = get("cursor").and_then(|c| c.parse::<usize>().ok()).unwrap_or(0);
    let page = get("page_size").and_then(|c| c.parse::<i64>().ok()).unwrap_or(50).clamp(1, 50) as usize;
    let mut q = Query::new(NS);
    q.max_results = 50;
    for (key, want) in [(K_TYPE, kind), (K_REGION, region)] {
        if let Some(w) = want {
            q.filters.push(Filter::Attr { key: key.into(), op: Op::Eq, value: Value::Str(w.into()) });
        }
    }
    let mut found = lan.my_lobbies(NS);
    for l in search(lan, q, Instant::now() + SEARCH_WAIT).into_iter().take(50) {
        if l.namespace == NS && !found.iter().any(|f| f.id == l.id) {
            found.push(l);
        }
    }
    let mut listed: Vec<(String, Json)> = found
        .iter()
        .filter(|l| {
            let s = Session::from_lobby(l);
            // What a stranger answered is checked again against the filters.
            (s.instance.is_some() || instance_state(&l.attrs).is_some()) && kind.is_none_or(|k| s.kind == k) && region.is_none_or(|r| s.region == r)
        })
        .map(|l| (l.id.clone(), browser_entry(l)))
        .collect();
    listed.sort_by(|a, b| a.0.cmp(&b.0));
    let page: Vec<Json> = listed.into_iter().skip(cursor).take(page).map(|(_, j)| j).collect();
    Reply::ok(Json::obj(vec![("cursor", Json::int(cursor as i64)), ("browser_sessions", Json::Arr(page))]))
}

/// `GET /session/v1/regions`: the regions harvested from the real service, else the one
/// region, this LAN.
pub fn regions(st: &State) -> Reply {
    let regions = if st.regions.is_empty() {
        vec![Json::obj(vec![("region_id", Json::str(DEFAULT_REGION)), ("sort_order", Json::int(1)), ("custom_only", Json::Bool(false)), ("description", Json::str("PeerParty"))])]
    } else {
        st.regions.clone()
    };
    Reply::ok(Json::obj(vec![("regions", Json::Arr(regions)), ("cursor", Json::int(0))]))
}

/// `GET /session/v2/queues`: there is no matchmaking, so no queue.
pub fn queues(if_none_match: Option<&str>) -> Reply {
    Reply::cached(Json::obj(vec![("queues", Json::Arr(Vec::new()))]).to_string(), if_none_match)
}

/// `POST /session/v1/audit`: taken and forgotten.
pub fn audit() -> Reply {
    Reply::empty(200)
}

/// `GET /session/v1/instance/health/config` (`API §6.4`).
pub fn health_config() -> Reply {
    Reply::ok(Json::obj(vec![("cadence_seconds", Json::int(10)), ("unhealthy_health_check_percentage", Json::Num(0.5)), ("missed_checks_before_unknown", Json::int(3))]))
}

// ---- notifications ----

/// Why a session is looked at again (`told`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Why {
    /// We made it: nothing to tell.
    Create,
    /// We left it: nothing to tell.
    Leave,
    /// The leader's PATCH: `session_updated` even when nothing the session shows changed.
    Patch,
    /// Any other change, ours or the LAN's.
    Other,
}

/// What each copy last told its player about each session it is in, by our peer id (one
/// process may hold two copies) and session id: the lobby as it was then.
static SEEN: Mutex<Vec<((PeerId, String), Lobby)>> = Mutex::new(Vec::new());

/// Sessions seen, for every copy in the process. Over it, the ones gone from this copy
/// go first, then the oldest seen.
const MAX_SEEN: usize = 256;

/// The notifications (`API §8`) of a session going from `old` to `new` on one copy, one
/// per kind of change: a player came, a player went, the instance, the browser info, and
/// anything else the session JSON shows (joinability, teams, region, platform session,
/// short code, a remaining player's fields, a leader moving while staying).
pub fn changes(old: &Lobby, new: &Lobby) -> Vec<&'static str> {
    let mut out = Vec::new();
    if new.members.iter().any(|m| old.member(m.id).is_none()) {
        out.push(notify::PLAYER_ADDED);
    }
    if old.members.iter().any(|m| new.member(m.id).is_none()) {
        out.push(notify::PLAYER_REMOVED);
    }
    // The rest, seen through the players in both. A joiner's own fields follow its join
    // (they reach the leader just after it): part of the join, not another change.
    let stayed: Vec<PeerId> = new.members.iter().filter(|m| old.member(m.id).is_some_and(|was| !(was.attrs.is_empty() && !m.attrs.is_empty()))).map(|m| m.id).collect();
    // A leader who went: the next leading is part of that going.
    let old_owner = if new.member(old.owner).is_none() { new.owner } else { old.owner };
    let view = |l: &Lobby, owner: PeerId| {
        let mut s = Session::from_lobby(l);
        s.instance = None;
        s.browser = None;
        let mut v = l.clone();
        v.attrs = s.to_attrs();
        v.owner = owner;
        v.members.retain(|m| stayed.contains(&m.id));
        render(&v).to_string()
    };
    if view(old, old_owner) != view(new, new.owner) {
        out.push(notify::SESSION_UPDATED);
    }
    let (so, sn) = (Session::from_lobby(old), Session::from_lobby(new));
    // The health is reported every few seconds and isn't a change to tell.
    let steady = |i: &Option<Json>| i.as_ref().map(|i| Json::Obj(i.as_obj().iter().filter(|(k, _)| k != "instance_health").cloned().collect()));
    if steady(&so.instance) != steady(&sn.instance) {
        out.push(notify::INSTANCE_UPDATED);
    }
    if so.browser != sn.browser {
        out.push(notify::BROWSER_UPDATED);
    }
    out
}

/// Looks at session `id` on `lan`'s copy again: what changed since it was last seen goes
/// to the player's queue, as (message, ETag after it).
fn observe(seen: &mut Vec<((PeerId, String), Lobby)>, lan: &Lan, id: &str, why: Why) -> Vec<(&'static str, String)> {
    let me = lan.me();
    let at = seen.iter().position(|((p, i), _)| *p == me && i == id);
    let now = lan.lobby(id).filter(|l| l.namespace == NS && l.member(me).is_some());
    let old = at.map(|i| seen.remove(i).1);
    let notes = match (why, old, &now) {
        (Why::Create | Why::Leave, _, _) => Vec::new(),
        (_, None, None) => Vec::new(),
        // We joined (our own join, or the LAN's answer to it).
        (_, None, Some(l)) => vec![(notify::PLAYER_ADDED, etag_for(lan, l))],
        // Removed or the session closed, not by our leave (which says `Leave`).
        (_, Some(old), None) => vec![(notify::PLAYER_REMOVED, etag_for(lan, &old))],
        (_, Some(old), Some(l)) => {
            let mut v: Vec<_> = changes(&old, l).into_iter().map(|m| (m, etag_for(lan, l))).collect();
            if v.is_empty() && why == Why::Patch {
                v.push((notify::SESSION_UPDATED, etag_for(lan, l)));
            }
            v
        }
    };
    if let Some(l) = now
        && why != Why::Leave
    {
        if seen.len() >= MAX_SEEN {
            seen.retain(|((p, i), _)| *p != me || lan.lobby(i).is_some());
        }
        if seen.len() >= MAX_SEEN {
            seen.remove(0);
        }
        seen.push(((me, id.to_string()), l));
    }
    notes
}

/// The notifications of one change, together: a waiting poll gets all or none of them.
fn send(lan: &Lan, id: &str, notes: Vec<(&'static str, String)>) {
    notify::push(&player_uuid(lan.me()), id, &notes);
}

/// Makes a change to session `id` on `lan` (`change`), then tells our player what it
/// changed. The change and the look after it are one step for the pump, so a change is
/// told once, by whichever looks first. A failed change is looked at as `Other`.
pub fn told<T, E>(lan: &Lan, id: &str, why: Why, change: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
    let mut seen = crate::sys::lock(&SEEN);
    let out = change();
    let notes = observe(&mut seen, lan, id, if out.is_ok() { why } else { Why::Other });
    drop(seen);
    send(lan, id, notes);
    out
}

fn was_seen(lan: &Lan, id: &str) -> bool {
    crate::sys::lock(&SEEN).iter().any(|((p, i), _)| *p == lan.me() && i == id)
}

// ---- the LAN's events ----

/// Starts (once) the thread that keeps the LAN going for this layer and hands its events
/// to `on_events`: a game whose only multiplayer service is RallyHere has nothing else
/// that ticks the LAN.
pub fn start_pump() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        net::subscribe(net::Front::RallyHere);
        std::thread::spawn(|| loop {
            let events = net::take(net::Front::RallyHere);
            if let Some(lan) = net::lan_if_started() {
                on_events(lan, &events);
            }
            std::thread::sleep(Duration::from_millis(50));
        });
    });
}

/// On the leader's copy: drops what the leader set for `who` (a player who joined, left,
/// dropped or was removed) and for anyone no longer a member, so that a rejoin starts from
/// what the player says itself.
fn forget_overrides(lan: &Lan, id: &str, who: Option<PeerId>) {
    let Some(mut l) = lan.lobby(id) else { return };
    if l.owner != lan.me() || !lan.is_owner(id) {
        return;
    }
    let mut s = Session::from_lobby(&l);
    let before = s.overrides.len();
    if let Some(p) = who {
        let uuid = player_uuid(p);
        s.overrides.retain(|(u, _)| *u != uuid);
    }
    pruned(&mut s, &l);
    if s.overrides.len() != before {
        l.attrs = s.to_attrs();
        let _ = lan.update(id, Some(&l), &[], &[]);
    }
}

/// What the LAN says about the sessions `lan` holds: who joined, left or now leads goes
/// to the log, and each change to the player's notifications. Returns the sessions the
/// events touched (or that we were in and are gone), once each.
pub fn on_events(lan: &Lan, events: &[Event]) -> Vec<String> {
    let mut touched: Vec<String> = Vec::new();
    for ev in events {
        // The results of our searches and joins go to the request waiting for them.
        match ev {
            Event::SearchDone { search, results } => {
                let (m, cv) = &*WAITS;
                let mut w = crate::sys::lock(m);
                if w.searches.len() >= MAX_WAITS {
                    w.searches.clear();
                }
                w.searches.insert((lan.me(), *search), results.clone());
                cv.notify_all();
            }
            Event::JoinDone { lobby, result } => {
                let (m, cv) = &*WAITS;
                let mut w = crate::sys::lock(m);
                if w.joins.len() >= MAX_WAITS {
                    w.joins.clear();
                }
                w.joins.insert((lan.me(), lobby.clone()), *result);
                cv.notify_all();
            }
            _ => {}
        }
        let (id, status) = match ev {
            Event::LobbyUpdated { lobby } | Event::MemberUpdated { lobby, .. } | Event::JoinDone { lobby, .. } => (lobby, None),
            Event::MemberStatus { lobby, member, status } => (lobby, Some((*member, *status))),
            _ => continue,
        };
        // A session we were in may be gone (we were removed, or it closed).
        if !lan.lobby(id).is_some_and(|l| l.namespace == NS) && !was_seen(lan, id) {
            continue;
        }
        if let Some((member, status)) = status {
            let what = match status {
                MemberStatus::Joined => "joined",
                MemberStatus::Left => "left",
                MemberStatus::Disconnected => "dropped out of",
                MemberStatus::Kicked => "was removed from",
                MemberStatus::Promoted => "leads",
                MemberStatus::Closed => "closed",
            };
            log!("rallyhere: {} {what} session {id}", player_uuid(member));
            // What the leader set for a player goes when the player does (or joins afresh).
            match status {
                MemberStatus::Joined | MemberStatus::Left | MemberStatus::Disconnected | MemberStatus::Kicked => forget_overrides(lan, id, Some(member)),
                MemberStatus::Promoted => forget_overrides(lan, id, None),
                MemberStatus::Closed => {}
            }
        }
        if !touched.contains(id) {
            touched.push(id.clone());
        }
    }
    for id in &touched {
        let _ = told(lan, id, Why::Other, || Ok::<(), ()>(()));
    }
    touched
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rallyhere::tests_support::{call_with, test_world};
    use std::time::Instant;

    const A: PeerId = PeerId([1; 16]);
    const B: PeerId = PeerId([2; 16]);
    const C: PeerId = PeerId([3; 16]);
    const D: PeerId = PeerId([4; 16]);

    fn json(s: &str) -> Json {
        Json::parse(s).unwrap()
    }

    fn settings(platform: &str) -> Option<Json> {
        Some(Json::obj(vec![("platform", Json::str(platform)), ("input", Json::str("gamepad"))]))
    }

    fn session() -> Session {
        Session {
            kind: "example_match".into(),
            region: "1".into(),
            created: "2025-01-02T03:04:05.123456Z".into(),
            joinability: Joinability { open: false, friends: true, platform: false },
            teams: vec![Team { id: 0, max_size: 4 }, Team { id: 1, max_size: 2 }],
            browser: None,
            instance: None,
            platform_session: None,
            short_code: None,
            overrides: Vec::new(),
        }
    }

    fn member(id: PeerId, f: PlayerFields) -> Member {
        Member { id, attrs: f.to_attrs() }
    }

    fn lobby(s: &Session, members: Vec<Member>) -> Lobby {
        let mut l = Lobby::new(NS);
        l.id = "0b2c5e9a-1111-4222-8333-444455556666".into();
        l.owner = A;
        l.attrs = s.to_attrs();
        l.members = members;
        l
    }

    fn players(j: &Json, team: usize) -> Vec<Json> {
        j.get("teams").as_arr()[team].get("players").as_arr().to_vec()
    }

    #[test]
    fn a_lobby_renders_as_the_session_json() {
        let mut s = session();
        s.overrides = vec![(player_uuid(C), PlayerFields { status: Some("invited".into()), ..Default::default() })];
        let l = lobby(
            &s,
            vec![
                member(A, PlayerFields { team: Some(0), version: Some("1.0.0".into()), client_settings: settings("Steam"), joined: Some("t1".into()), ..Default::default() }),
                member(B, PlayerFields { team: Some(1), ..Default::default() }),
                member(C, PlayerFields { team: Some(0), client_settings: settings("Steam"), ..Default::default() }),
                // A team the session doesn't have: shown on the first.
                member(D, PlayerFields { team: Some(9), client_settings: settings("Epic"), status: Some("leader".into()), ..Default::default() }),
            ],
        );
        let j = render(&l);
        let keys: Vec<&str> = j.as_obj().iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["type", "session_id", "joinable", "joinability", "teams", "platform_scouts", "created", "region_id"], "optional fields absent when unset");
        assert_eq!(j.get("type").as_str(), Some("example_match"));
        assert_eq!(j.get("session_id").as_str(), Some(l.id.as_str()));
        assert_eq!(j.get("joinable"), &Json::Bool(true));
        assert_eq!(j.get("joinability").to_string(), r#"{"open":false,"friends":true}"#, "platform isn't echoed");
        assert_eq!((j.get("created").as_str(), j.get("region_id").as_str()), (Some("2025-01-02T03:04:05.123456Z"), Some("1")));
        let t0 = players(&j, 0);
        assert_eq!(j.get("teams").as_arr().len(), 2);
        assert_eq!((j.get("teams").as_arr()[1].get("team_id").as_i64(), j.get("teams").as_arr()[1].get("max_size").as_i64()), (Some(1), Some(2)));
        let uuids: Vec<&str> = t0.iter().map(|p| p.get("player_uuid").as_str().unwrap()).collect();
        assert_eq!(uuids, [player_uuid(A), player_uuid(C), player_uuid(D)]);
        assert_eq!(
            t0[0].to_string(),
            format!(r#"{{"player_id":{},"player_uuid":"{}","status":"leader","version":"1.0.0","client_settings":{{"platform":"Steam","input":"gamepad"}},"joined":"t1"}}"#, player_id(A), player_uuid(A))
        );
        assert_eq!(t0[1].get("status").as_str(), Some("invited"), "the leader's setting wins");
        assert_eq!(t0[2].get("status").as_str(), Some("member"), "only the owner leads");
        let b = &players(&j, 1)[0];
        assert_eq!(b.get("status").as_str(), Some("member"));
        assert!(b.get("version").is_null() && b.get("client_settings").is_null() && b.get("joined").is_null());
        // One scout per platform, its first player.
        let scouts = j.get("platform_scouts");
        assert_eq!(scouts.as_obj().len(), 2);
        assert_eq!(scouts.get("Steam").get("player_uuid").as_str(), Some(player_uuid(A).as_str()));
        assert_eq!(scouts.get("Epic").get("player_uuid").as_str(), Some(player_uuid(D).as_str()));
        assert_eq!(scouts.get("Epic").get("platform").as_str(), Some("Epic"));

        // Optional fields, once set, in their place.
        s.instance = Some(json(r#"{"instance_id":"i1"}"#));
        s.platform_session = Some(json(r#"[{"platform":"Steam"}]"#));
        s.short_code = Some("AB12C".into());
        let j = render(&lobby(&s, l.members.clone()));
        let keys: Vec<&str> = j.as_obj().iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["type", "session_id", "instance", "joinable", "joinability", "teams", "platform_session", "platform_scouts", "created", "region_id", "short_code"]);
        assert_eq!(j.get("instance").get("instance_id").as_str(), Some("i1"));
        assert_eq!(j.get("short_code").as_str(), Some("AB12C"));
    }

    #[test]
    fn joinable_is_any_of_open_friends_and_platform() {
        for (open, friends, platform) in [(false, false, false), (true, false, false), (false, true, false), (false, false, true), (true, true, true)] {
            let mut s = session();
            s.joinability = Joinability { open, friends, platform };
            let j = render(&lobby(&s, vec![]));
            assert_eq!(j.get("joinable"), &Json::Bool(open || friends || platform));
            assert_eq!((j.get("joinability").get("open").as_bool(), j.get("joinability").get("friends").as_bool()), (Some(open), Some(friends)));
        }
        let perm = |open, friends| Joinability { open, friends, platform: true }.permission();
        assert_eq!((perm(true, true), perm(false, true), perm(false, false)), (Permission::Public, Permission::Friends, Permission::InviteOnly));
    }

    #[test]
    fn session_and_player_fields_round_trip_through_attributes() {
        let s = Session {
            kind: "example_party".into(),
            region: "eu".into(),
            created: "2025-01-02T03:04:05.000000Z".into(),
            joinability: Joinability { open: true, friends: false, platform: true },
            teams: vec![Team { id: 0, max_size: 3 }, Team { id: 2, max_size: 5 }],
            browser: Some(json(r#"{"custom_data":{"k":"v"},"created_timestamp":"t"}"#)),
            instance: Some(json(r#"{"instance_id":"i","join_params":{"public_conn_str":"x"}}"#)),
            platform_session: Some(json(r#"[{"platform":"Steam","platform_session_id_base64":"AA=="}]"#)),
            short_code: Some("ZZ9Q1".into()),
            overrides: vec![(player_uuid(B), PlayerFields { team: Some(2), status: Some("reserved".into()), version: Some("2".into()), client_settings: settings("PSN"), joined: Some("t".into()) })],
        };
        let l = lobby(&s, vec![]);
        assert_eq!(Session::from_lobby(&l), s);
        assert!(!l.attr(K_INSTANCE).unwrap().public, "connection strings are for members");
        assert!(l.attr(K_TYPE).unwrap().public && l.attr(K_SHORT_CODE).unwrap().public);
        let f = PlayerFields { team: Some(1), status: Some("member".into()), version: Some("1.2".into()), client_settings: settings("Steam"), joined: Some("t2".into()) };
        assert_eq!(PlayerFields::from_attrs(&f.to_attrs()), f);
        assert_eq!(PlayerFields::from_attrs(&[]), PlayerFields::default());
        assert_eq!(PlayerFields::from_json(&f.to_json()), f);
    }

    #[test]
    fn malformed_attributes_render_as_unset() {
        let mut l = Lobby::new(NS);
        l.id = "x".into();
        l.attrs = vec![
            attr(K_TYPE, Value::Int(7)),
            attr(K_JOINABILITY, Value::Str("{not json".into())),
            attr(K_TEAMS, Value::Str(r#"[{"team_id":"a"},5,{"team_id":3}]"#.into())),
            attr(K_INSTANCE, Value::Str("[1,2]".into())),
            attr(K_PLATFORM_SESSION, Value::Bool(true)),
            attr(K_PLAYERS, Value::Str(r#"{"x":5}"#.into())),
            attr(K_SHORT_CODE, Value::Str(String::new())),
        ];
        l.members = vec![Member {
            id: A,
            attrs: vec![attr(M_TEAM, Value::Str("zz".into())), attr(M_CLIENT_SETTINGS, Value::Str("\"text\"".into())), attr(M_VERSION, Value::Double(1.5))],
        }];
        let j = render(&l);
        assert_eq!(j.get("type").as_str(), Some("7"));
        assert_eq!(j.get("joinable"), &Json::Bool(false));
        assert_eq!(j.get("teams").as_arr().len(), 1, "no usable team: one team 0");
        assert_eq!(j.get("teams").as_arr()[0].get("max_size").as_i64(), Some(4));
        assert!(j.get("instance").is_null() && j.get("platform_session").is_null() && j.get("short_code").is_null());
        assert_eq!(j.get("region_id").as_str(), Some("1"));
        let p = &players(&j, 0)[0];
        assert_eq!(p.get("version").as_str(), Some("1.5"));
        assert!(p.get("client_settings").is_null());
        // No attributes at all, and no members.
        let mut bare = Lobby::new(NS);
        bare.id = "y".into();
        assert_eq!(render(&bare).get("teams").as_arr().len(), 1);
    }

    #[test]
    fn the_etag_follows_the_session_state() {
        let s = session();
        let l = lobby(&s, vec![member(A, PlayerFields { team: Some(0), ..Default::default() })]);
        let tag = etag(&l);
        assert!(tag.starts_with("W/\"") && tag.ends_with('"'));
        assert_eq!(etag(&l.clone()), tag, "another copy of the same state");
        let mut hidden = l.clone();
        hidden.bucket = "other".into();
        assert_eq!(etag(&hidden), tag, "nothing the JSON shows changed");
        let mut changes: Vec<Lobby> = Vec::new();
        let edits: [fn(&mut Session); 5] = [
            |s: &mut Session| s.region = "2".into(),
            |s: &mut Session| s.joinability.open = true,
            |s: &mut Session| s.teams[1].max_size = 3,
            |s: &mut Session| s.short_code = Some("AAAAA".into()),
            |s: &mut Session| s.instance = Some(Json::obj(vec![])),
        ];
        for edit in edits {
            let mut s2 = s.clone();
            edit(&mut s2);
            changes.push(lobby(&s2, l.members.clone()));
        }
        let mut joined = l.clone();
        joined.members.push(member(B, PlayerFields::default()));
        changes.push(joined);
        let mut moved = l.clone();
        moved.members[0] = member(A, PlayerFields { team: Some(1), ..Default::default() });
        changes.push(moved);
        let mut led = l.clone();
        led.members.push(member(B, PlayerFields::default()));
        let before = etag(&led);
        led.owner = B;
        assert_ne!(etag(&led), before, "the leader moved");
        for c in &changes {
            assert_ne!(etag(c), tag);
        }
    }

    #[test]
    fn a_patch_merges_teams_by_id_and_players_by_uuid() {
        let mut s = session();
        s.overrides = vec![(player_uuid(B), PlayerFields { version: Some("old".into()), ..Default::default() })];
        let l = lobby(&s, vec![member(A, PlayerFields { team: Some(0), version: Some("1".into()), ..Default::default() }), member(B, PlayerFields { team: Some(0), ..Default::default() })]);
        let body = json(&format!(
            r#"{{"region_id":"7","joinability":{{"open":true}},"password":"x",
               "teams":[{{"team_id":1,"max_size":6,"players":[{{"player_uuid":"{}","status":"reserved","client_settings":{{"platform":"Epic","input":"touch","extra":1}}}}]}},
                        {{"team_id":5,"max_size":3}},
                        {{"team_id":0,"players":[{{"player_uuid":"{}","version":"2","status":"leader"}},{{"player_uuid":"{}"}}]}}]}}"#,
            player_uuid(B).to_uppercase(),
            player_uuid(A),
            player_uuid(C)
        ));
        let out = patched(&l, &body);
        let j = render(&out);
        assert_eq!(j.get("region_id").as_str(), Some("7"));
        assert_eq!(j.get("joinability").to_string(), r#"{"open":true,"friends":true}"#);
        assert_eq!(out.permission, Permission::Public);
        let teams: Vec<(i64, i64)> = j.get("teams").as_arr().iter().map(|t| (t.get("team_id").as_i64().unwrap(), t.get("max_size").as_i64().unwrap())).collect();
        assert_eq!(teams, [(0, 4), (1, 6), (5, 3)], "merged by team_id, a new one added");
        assert_eq!(out.max_members, 13);
        let a = &players(&j, 0)[0];
        assert_eq!((a.get("version").as_str(), a.get("status").as_str()), (Some("2"), Some("leader")));
        let b = &players(&j, 1)[0];
        assert_eq!(b.get("player_uuid").as_str(), Some(player_uuid(B).as_str()));
        assert_eq!((b.get("status").as_str(), b.get("version").as_str()), (Some("reserved"), Some("old")));
        assert_eq!(b.get("client_settings").to_string(), r#"{"platform":"Epic","input":"touch"}"#);
        assert_eq!(players(&j, 0).len(), 1);
        // A player who isn't a member is nobody's business.
        assert!(Session::from_lobby(&out).overrides.iter().all(|(u, _)| *u != player_uuid(C)));
        // joinable false closes it, true opens it to friends.
        let closed = patched(&out, &json(r#"{"joinable":false}"#));
        assert_eq!((render(&closed).get("joinable"), closed.permission), (&Json::Bool(false), Permission::InviteOnly));
        let reopened = patched(&closed, &json(r#"{"joinable":true}"#));
        assert_eq!((render(&reopened).get("joinable"), reopened.permission), (&Json::Bool(true), Permission::Friends));
        // An empty patch changes nothing the JSON shows.
        assert_eq!(render(&patched(&out, &json("{}"))).to_string(), j.to_string());
    }

    #[test]
    fn templates_are_the_configs_and_a_missing_one_fails_fast() {
        let world = test_world(A, "Me", &[]);
        let mut st = State::new(None);
        st.templates = vec![
            ("example_party".into(), json(r#"{"can_be_created_by_players_directly":true}"#)),
            ("example_match".into(), json(r#"{"session_type":"example_match","players_per_team":4}"#)),
        ];
        let r = call_with(&world, &mut st, "GET", "/session/v1/template", &[], "");
        assert_eq!(r.status, 200);
        let j = json(&r.body);
        assert_eq!(j.get("templates").get("example_party").to_string(), r#"{"session_type":"example_party","can_be_created_by_players_directly":true}"#);
        assert_eq!(j.get("templates").get("example_match").get("players_per_team").as_i64(), Some(4));
        let etag = r.etag.unwrap();
        let again = call_with(&world, &mut st, "GET", "/session/v1/template", &[("If-None-Match", etag.as_str())], "");
        assert_eq!((again.status, again.body.as_str()), (304, ""));
        // A type the config lacks: RallyHere's error, before the LAN is asked.
        let r = call_with(&world, &mut st, "POST", "/session/v1/session", &[], r#"{"session_type":"example_ranked"}"#);
        assert_eq!(r.status, 404);
        assert_eq!(json(&r.body).get("error_code").as_str(), Some("session_template_not_found"));
        // Known, but no LAN here.
        let r = call_with(&world, &mut st, "POST", "/session/v1/session", &[], r#"{"session_type":"example_party"}"#);
        assert_eq!(r.status, 503);
    }

    // ---- on the LAN ----

    fn start(game: &str, port: u16, name: &str) -> Lan {
        Lan::start(peerparty_core::Options {
            game: game.into(),
            identity: peerparty_core::Identity::ephemeral(name),
            discovery_port: port,
            extra_targets: Vec::new(),
            log: |_| {},
            internet: None,
            public: None,
            lan_discovery: true,
            public_voice: None,
        })
        .expect("start")
    }

    fn pump(lans: &[&Lan], what: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while !done() {
            for l in lans {
                l.tick();
                let _ = l.poll();
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The world of `lan`'s copy, with `others` as its peers.
    fn world_of(lan: &Lan, others: &[&Lan]) -> World {
        let peers: Vec<(PeerId, &str)> = others.iter().map(|o| (o.me(), "other")).collect();
        World { lan: Some(lan.clone()), ..test_world(lan.me(), "me", &peers) }
    }

    fn state() -> State {
        let mut st = State::new(None);
        st.templates = vec![
            ("example_match".into(), json(r#"{"players_per_team":3,"num_teams":2,"default_public":true}"#)),
            ("example_party".into(), json(r#"{}"#)),
        ];
        st
    }

    fn req(world: &World, st: &mut State, method: &str, path: &str, body: &str) -> Reply {
        call_with(world, st, method, path, &[], body)
    }

    #[test]
    fn one_copy_creates_gets_patches_and_leaves() {
        let port = peerparty_core::test_ports::claim(1);
        let lan = start(&format!("test:rallyhere:one:{}", std::process::id()), port, "a");
        let world = world_of(&lan, &[]);
        let mut st = state();
        let r = req(&world, &mut st, "POST", "/session/v1/session", r#"{"session_type":"example_match","client_version":"1.0.0","client_settings":{"platform":"Steam","input":"gamepad"}}"#);
        assert_eq!(r.status, 200, "{}", r.body);
        let id = json(&r.body).get("session_id").as_str().unwrap().to_string();
        assert_eq!(json(&r.body).as_obj().len(), 1);
        let l = lan.lobby(&id).unwrap();
        assert_eq!((l.namespace.as_str(), l.owner, l.max_members, l.permission), (NS, lan.me(), 6, Permission::Public));
        // The same type again: the session we are in.
        let again = req(&world, &mut st, "POST", "/session/v1/session", r#"{"session_type":"example_match"}"#);
        assert_eq!(json(&again.body).get("session_id").as_str(), Some(id.as_str()));
        // A party: no region given is "1", not public is friends.
        let party = req(&world, &mut st, "POST", "/session/v1/session", r#"{"session_type":"example_party","region_id":"unknown-region"}"#);
        let party_id = json(&party.body).get("session_id").as_str().unwrap().to_string();
        assert_eq!(lan.lobby(&party_id).unwrap().permission, Permission::Friends);

        let r = req(&world, &mut st, "GET", &format!("/session/v1/session/{}?refresh_ttl=true", id.to_uppercase()), "");
        assert_eq!(r.status, 200);
        let j = json(&r.body);
        assert_eq!((j.get("type").as_str(), j.get("region_id").as_str(), j.get("joinable")), (Some("example_match"), Some("1"), &Json::Bool(true)));
        assert_eq!(j.get("teams").as_arr().len(), 2);
        let me = &players(&j, 0)[0];
        assert_eq!((me.get("status").as_str(), me.get("version").as_str()), (Some("leader"), Some("1.0.0")));
        assert_eq!(me.get("client_settings").to_string(), r#"{"platform":"Steam","input":"gamepad"}"#);
        assert!(me.get("joined").as_str().is_some());
        assert_eq!(render(&lan.lobby(&party_id).unwrap()).get("region_id").as_str(), Some("unknown-region"));
        let etag = r.etag.clone().unwrap();
        let cached = call_with(&world, &mut st, "GET", &format!("/session/v1/session/{id}"), &[("If-None-Match", etag.as_str())], "");
        assert_eq!((cached.status, cached.body.as_str()), (304, ""));
        assert_eq!(req(&world, &mut st, "GET", "/session/v1/session/00000000-0000-4000-8000-000000000000", "").status, 404);

        let r = req(&world, &mut st, "PATCH", &format!("/session/v1/session/{id}"), r#"{"joinability":{"open":false,"friends":true},"region_id":"2"}"#);
        assert_eq!(r.status, 200);
        assert_eq!(json(&r.body).get("region_id").as_str(), Some("2"));
        assert_ne!(r.etag.as_deref(), Some(etag.as_str()));
        assert_eq!(lan.lobby(&id).unwrap().permission, Permission::Friends);
        let fresh = call_with(&world, &mut st, "GET", &format!("/session/v1/session/{id}"), &[("If-None-Match", etag.as_str())], "");
        assert_eq!((fresh.status, fresh.etag), (200, r.etag));

        // me/session, then leave and kick ourselves out of the other.
        let mine = req(&world, &mut st, "GET", "/session/v1/player/me/session", "");
        let j = json(&mine.body);
        assert_eq!(j.get("sessions").get("example_match").get("session_ids").as_arr(), [Json::str(&id)]);
        assert_eq!(j.get("sessions").get("example_party").get("type").as_str(), Some("example_party"));
        assert!(j.get("last_updated_timestamp").as_str().is_some());
        let same = call_with(&world, &mut st, "GET", "/session/v1/player/me/session", &[("If-None-Match", mine.etag.as_deref().unwrap())], "");
        assert_eq!(same.status, 304, "an unchanged list keeps its ETag");
        assert_eq!(req(&world, &mut st, "DELETE", &format!("/session/v1/session/{id}/player/me"), "").status, 204);
        assert_eq!(req(&world, &mut st, "DELETE", &format!("/session/v1/session/{id}/player/me"), "").status, 404);
        let r = req(&world, &mut st, "DELETE", &format!("/session/v1/session/{party_id}/player/uuid/{}", player_uuid(PeerId([9; 16]))), "");
        assert_eq!((r.status, json(&r.body).get("error_code").as_str()), (404, Some("session_player_not_found")));
        let r = req(&world, &mut st, "DELETE", &format!("/session/v1/session/{party_id}/player/uuid/{}", player_uuid(lan.me()).to_uppercase()), "");
        assert_eq!((r.status, r.body.as_str()), (204, ""));
        let none = req(&world, &mut st, "GET", "/session/v1/player/me/session", "");
        assert_eq!((none.status, none.body.as_str()), (200, "{}"));
        assert_eq!(req(&world, &mut st, "GET", &format!("/session/v1/session/{id}"), "").status, 404);
    }

    #[test]
    fn two_copies_share_a_session_and_its_leader_moves_on() {
        let port = peerparty_core::test_ports::claim(1);
        let game = format!("test:rallyhere:two:{}", std::process::id());
        let (a, b) = (start(&game, port, "a"), start(&game, port, "b"));
        pump(&[&a, &b], "the copies to meet", || a.peers().iter().any(|(p, _)| *p == b.me()) && b.peers().iter().any(|(p, _)| *p == a.me()));
        let (wa, wb) = (world_of(&a, &[&b]), world_of(&b, &[&a]));
        let (mut sa, mut sb) = (state(), state());

        let r = req(&wa, &mut sa, "POST", "/session/v1/session", r#"{"session_type":"example_match","client_settings":{"platform":"Steam","input":"gamepad"}}"#);
        let id = json(&r.body).get("session_id").as_str().unwrap().to_string();
        // The LAN's own join stands in for the join route here.
        b.join_by_id(NS, &id).unwrap();
        pump(&[&a, &b], "the join", || b.lobby(&id).is_some_and(|l| l.members.len() == 2) && a.lobby(&id).is_some_and(|l| l.members.len() == 2));
        // A short code set by the leader.
        let mut l = a.lobby(&id).unwrap();
        peerparty_core::set_attr(&mut l.attrs, attr(K_SHORT_CODE, Value::Str("QX7K2".into())));
        a.update(&id, Some(&l), &[], &[]).unwrap();
        pump(&[&a, &b], "the code", || b.lobby(&id).is_some_and(|l| l.attr(K_SHORT_CODE).is_some()));

        // Every copy answers the same JSON and ETag, by id and by short code.
        let ga = req(&wa, &mut sa, "GET", &format!("/session/v1/session/{id}"), "");
        for (w, s) in [(&wa, &mut sa), (&wb, &mut sb)] {
            for key in [id.as_str(), "qx7k2"] {
                let g = req(w, s, "GET", &format!("/session/v1/session/{key}"), "");
                assert_eq!((g.status, &g.body, &g.etag), (200, &ga.body, &ga.etag));
            }
        }
        let j = json(&ga.body);
        let team = players(&j, 0);
        let statuses: Vec<&str> = team.iter().map(|p| p.get("status").as_str().unwrap()).collect();
        assert_eq!(statuses, ["leader", "member"]);

        // Only the leader patches or removes others.
        let bpatch = req(&wb, &mut sb, "PATCH", &format!("/session/v1/session/{id}"), r#"{"region_id":"9"}"#);
        assert_eq!((bpatch.status, json(&bpatch.body).get("error_code").as_str()), (404, Some("not_owner")));
        let bkick = req(&wb, &mut sb, "DELETE", &format!("/session/v1/session/{id}/player/uuid/{}", player_uuid(a.me())), "");
        assert_eq!((bkick.status, json(&bkick.body).get("error_code").as_str()), (404, Some("not_owner")));
        let body = format!(r#"{{"region_id":"9","teams":[{{"team_id":1,"players":[{{"player_uuid":"{}","version":"3"}}]}}]}}"#, player_uuid(b.me()));
        let apatch = req(&wa, &mut sa, "PATCH", &format!("/session/v1/session/{id}"), &body);
        assert_eq!(apatch.status, 200);
        assert_eq!(players(&json(&apatch.body), 1)[0].get("version").as_str(), Some("3"));
        pump(&[&a, &b], "the patch", || b.lobby(&id).is_some_and(|l| etag(&l) == apatch.etag.clone().unwrap()));
        assert_eq!(req(&wb, &mut sb, "GET", &format!("/session/v1/session/{id}"), "").body, apatch.body);

        // The leader removes B: gone from B's sessions.
        assert_eq!(req(&wa, &mut sa, "DELETE", &format!("/session/v1/session/{id}/player/uuid/{}", player_uuid(b.me())), "").status, 204);
        pump(&[&a, &b], "the kick", || b.lobby(&id).is_none());
        assert_eq!(req(&wb, &mut sb, "GET", "/session/v1/player/me/session", "").body, "{}");
        assert!(Session::from_lobby(&a.lobby(&id).unwrap()).overrides.is_empty(), "what the leader set for B goes with B");

        // A second session: its leader leaves and the other copy leads it.
        let r = req(&wa, &mut sa, "POST", "/session/v1/session", r#"{"session_type":"example_party"}"#);
        let party = json(&r.body).get("session_id").as_str().unwrap().to_string();
        b.join_by_id(NS, &party).unwrap();
        pump(&[&a, &b], "the second join", || b.lobby(&party).is_some_and(|l| l.members.len() == 2));
        assert_eq!(req(&wa, &mut sa, "DELETE", &format!("/session/v1/session/{party}/player/me"), "").status, 204);
        pump(&[&a, &b], "the new leader", || b.lobby(&party).is_some_and(|l| l.owner == b.me() && l.members.len() == 1));
        let g = req(&wb, &mut sb, "GET", &format!("/session/v1/session/{party}"), "");
        let ps = players(&json(&g.body), 0);
        assert_eq!((ps.len(), ps[0].get("player_uuid").as_str(), ps[0].get("status").as_str()), (1, Some(player_uuid(b.me()).as_str()), Some("leader")));
        let mine = json(&req(&wa, &mut sa, "GET", "/session/v1/player/me/session", "").body);
        assert!(mine.get("sessions").get("example_party").is_null());
        assert_eq!(on_events(&b, &[Event::LobbyUpdated { lobby: party.clone() }, Event::LobbyUpdated { lobby: party.clone() }, Event::LobbyUpdated { lobby: "other".into() }]), [party]);
    }

    // ---- Joins, short codes, browser, the small routes, bounds ----

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Keeps a copy's LAN going and its events going to `on_events`, as the layer's pump
    /// does, until dropped.
    struct Pumped(Arc<AtomicBool>);

    impl Pumped {
        fn of(lan: &Lan) -> Pumped {
            let stop = Arc::new(AtomicBool::new(false));
            let (flag, lan) = (stop.clone(), lan.clone());
            std::thread::spawn(move || {
                while !flag.load(Ordering::Relaxed) {
                    lan.tick();
                    let events = lan.poll();
                    on_events(&lan, &events);
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
            Pumped(stop)
        }
    }

    impl Drop for Pumped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    fn wait_until(what: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(15);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn code(r: &Reply) -> Option<String> {
        json(&r.body).get("error_code").as_str().map(str::to_string)
    }

    #[test]
    fn short_codes_are_five_of_a_to_z_and_digits_and_never_taken_ones() {
        for _ in 0..200 {
            let c = new_code(&[]).unwrap();
            assert!(c.len() == CODE_LEN && c.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()), "{c}");
        }
        // Every code but one taken (any case): the free one is found, or none.
        let taken: Vec<String> = CODE_ALPHABET.iter().map(|b| format!("{0}{0}{0}{0}{0}", *b as char)).collect();
        assert!(new_code(&taken).is_some());
        assert!(is_uuid("0b2c5e9a-1111-4222-8333-444455556666") && is_uuid("0B2C5E9A-1111-4222-8333-444455556666"));
        assert!(!is_uuid("QX7K2") && !is_uuid("0b2c5e9a-1111-4222-8333-44445555666g") && !is_uuid(""));
        // The code a lobby carries is cut to 8 and found in any case.
        let mut l = lobby(&session(), vec![member(A, PlayerFields::default())]);
        l.attrs.push(attr(K_SHORT_CODE, Value::Str("ABCDEFGHIJKL".into())));
        assert_eq!(code_attr(&l.attrs).as_deref(), Some("ABCDEFGH"));
    }

    #[test]
    fn a_join_is_checked_for_team_room_and_joinability() {
        let mut s = session();
        let mut on_team_one = PlayerFields { team: Some(1), ..Default::default() };
        let l = lobby(&s, vec![member(A, PlayerFields { team: Some(0), ..Default::default() }), member(B, on_team_one.clone())]);
        assert_eq!(join_check(&l, C, "0"), None);
        assert_eq!(join_check(&l, C, ""), None, "no team asked: the first");
        assert_eq!(join_check(&l, C, "7"), Some(JoinResult::WrongSecret), "a team the session lacks");
        assert_eq!(join_check(&l, C, "x"), Some(JoinResult::WrongSecret));
        assert_eq!(join_check(&l, C, "1"), None, "team 1 holds 2, one is on it");
        let l2 = lobby(&s, vec![member(A, PlayerFields { team: Some(0), ..Default::default() }), member(B, on_team_one.clone()), member(D, on_team_one.clone())]);
        assert_eq!(join_check(&l2, C, "1"), Some(JoinResult::Full));
        assert_eq!(join_check(&l2, D, "1"), None, "a member asking again isn't counted against itself");
        on_team_one.team = Some(0);
        s.joinability = Joinability::default();
        assert_eq!(join_check(&lobby(&s, vec![]), C, "0"), Some(JoinResult::NotAllowed));
    }

    #[test]
    fn a_refused_join_answers_the_error_of_the_api() {
        for (r, status, code) in [
            (JoinResult::Full, 400, "session_full"),
            (JoinResult::WrongSecret, 400, "team_not_found"),
            (JoinResult::NotAllowed, 400, "session_not_joinable"),
            (JoinResult::NotFound, 404, "session_not_found"),
            (JoinResult::TimedOut, 404, "session_not_found"),
        ] {
            let e = join_error(r);
            assert_eq!((e.status, code_of(&e).as_str()), (status, code));
            if status == 400 {
                assert_eq!(json(&e.body).get("desc").as_str(), Some("Join rejected by host"));
            }
        }
    }

    fn code_of(r: &Reply) -> String {
        code(r).unwrap_or_default()
    }

    #[test]
    fn sessions_group_by_type_and_the_small_routes_answer() {
        let g = group_by_type(vec![("a".into(), "1".into()), ("b".into(), "2".into()), ("a".into(), "3".into())]);
        assert_eq!(g.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), ["a", "b"]);
        assert_eq!(g[0].1.to_string(), r#"{"type":"a","session_ids":["1","3"]}"#);
        let world = test_world(A, "me", &[]);
        let mut st = state();
        let r = req(&world, &mut st, "GET", "/session/v1/regions", "");
        assert_eq!(r.body, r#"{"regions":[{"region_id":"1","sort_order":1,"custom_only":false,"description":"PeerParty"}],"cursor":0}"#);
        // Harvested regions (harvest.rs) are what the route serves instead.
        let mut harvested = state();
        harvested.regions = crate::rallyhere::config::regions_value(&Json::parse(r#"[{"region_id":"eu","sort_order":2},{"region_id":"us"}]"#).unwrap()).unwrap();
        let r = req(&world, &mut harvested, "GET", "/session/v1/regions", "");
        assert_eq!(r.body, r#"{"regions":[{"region_id":"eu","sort_order":2},{"region_id":"us"}],"cursor":0}"#);
        let q = req(&world, &mut st, "GET", "/session/v2/queues?cursor=0&page_size=10", "");
        assert_eq!((q.status, q.body.as_str()), (200, r#"{"queues":[]}"#));
        let again = call_with(&world, &mut st, "GET", "/session/v2/queues", &[("If-None-Match", q.etag.as_deref().unwrap())], "");
        assert_eq!((again.status, again.body.as_str()), (304, ""));
        let a = req(&world, &mut st, "POST", "/session/v1/audit", r#"{"event_name":"x","session_id":"y"}"#);
        assert_eq!((a.status, a.body.as_str()), (200, ""));
        let h = req(&world, &mut st, "GET", "/session/v1/instance/health/config", "");
        assert_eq!(h.body, r#"{"cadence_seconds":10,"unhealthy_health_check_percentage":0.5,"missed_checks_before_unknown":3}"#);
        // No LAN: the routes that need one say so; another action is a 400.
        assert_eq!(req(&world, &mut st, "POST", "/session/v1/session/abc/player/me", "{}").status, 503);
        assert_eq!(req(&world, &mut st, "GET", "/session/v1/browser", "").status, 503);
        let bad = req(&world, &mut st, "POST", "/session/v1/session/abc:explode", "");
        assert_eq!((bad.status, code_of(&bad).as_str()), (400, "session_action_error"));
        assert_eq!(json(&bad.body).get("desc").as_str(), Some("Session action \"explode\" not supported."));
    }

    #[test]
    fn one_copy_browses_its_sessions_by_type_region_and_page() {
        let port = peerparty_core::test_ports::claim(1);
        let lan = start(&format!("test:rallyhere:browse:{}", std::process::id()), port, "a");
        let _pump = Pumped::of(&lan);
        let world = world_of(&lan, &[]);
        let mut st = state();
        let mut ids = Vec::new();
        for (kind, region) in [("example_match", "eu"), ("example_party", "eu"), ("example_party", "us")] {
            // One session of a type per player: a second type is made by another type.
            let r = req(&world, &mut st, "POST", "/session/v1/session", &format!(r#"{{"session_type":"{kind}","region_id":"{region}"}}"#));
            let id = json(&r.body).get("session_id").as_str().unwrap().to_string();
            if ids.len() == 2 {
                req(&world, &mut st, "DELETE", &format!("/session/v1/session/{}/player/me", ids[1]), "");
                let r = req(&world, &mut st, "POST", "/session/v1/session", &format!(r#"{{"session_type":"{kind}","region_id":"{region}"}}"#));
                ids.push(json(&r.body).get("session_id").as_str().unwrap().to_string());
            } else {
                ids.push(id);
            }
        }
        // None is in the browser yet.
        let none = json(&req(&world, &mut st, "GET", "/session/v1/browser", "").body);
        assert_eq!(none.get("browser_sessions").as_arr().len(), 0);
        // A leader puts two in: POST replaces, PATCH merges.
        let r = req(&world, &mut st, "POST", &format!("/session/v1/session/{}/browser", ids[0]), r#"{"custom_data":{"map":"m1","n":5,"deep":{"x":1}},"created_timestamp":"2025-01-02T03:04:05Z"}"#);
        assert_eq!(r.body, r#"{"custom_data":{"map":"m1","n":"5"},"created_timestamp":"2025-01-02T03:04:05Z"}"#, "scalars as text, objects dropped");
        let r = req(&world, &mut st, "PATCH", &format!("/session/v1/session/{}/browser", ids[0]), r#"{"custom_data":{"map":"m2","mode":"x"}}"#);
        assert_eq!(r.body, r#"{"custom_data":{"map":"m2","n":"5","mode":"x"},"created_timestamp":"2025-01-02T03:04:05Z"}"#);
        let r = req(&world, &mut st, "POST", &format!("/session/v1/session/{}/browser", ids[2]), "{}");
        assert_eq!(json(&r.body).get("custom_data").as_obj().len(), 0);
        assert!(json(&r.body).get("created_timestamp").as_str().is_some_and(|t| t.ends_with('Z')));
        assert_eq!(req(&world, &mut st, "POST", "/session/v1/session/00000000-0000-4000-8000-000000000000/browser", "{}").status, 404);

        // Only sessions with an instance are listed.
        assert_eq!(json(&req(&world, &mut st, "GET", "/session/v1/browser", "").body).get("browser_sessions").as_arr().len(), 0);
        for i in [0, 2] {
            assert_eq!(req(&world, &mut st, "POST", &format!("/session/v1/session/{}/instance", ids[i]), "{}").status, 200);
        }
        let mut list = |q: &str| json(&req(&world, &mut st, "GET", &format!("/session/v1/browser{q}"), "").body);
        let all = list("");
        assert_eq!(all.get("cursor").as_i64(), Some(0));
        assert_eq!(all.get("browser_sessions").as_arr().len(), 2);
        let e = all.get("browser_sessions").as_arr().iter().find(|e| e.get("session_id").as_str() == Some(ids[0].as_str())).unwrap().clone();
        assert_eq!(e.get("instance_health").as_str(), Some("unknown"));
        assert_eq!((e.get("player_count").as_i64(), e.get("max_player_count").as_i64()), (Some(1), Some(6)));
        assert_eq!(e.get("custom_data").get("map").as_str(), Some("m2"));
        assert_eq!(list("?session_type=example_match").get("browser_sessions").as_arr().len(), 1);
        assert_eq!(list("?session_type=example_party&region_id=us").get("browser_sessions").as_arr().len(), 1);
        assert_eq!(list("?session_type=example_party&region_id=eu").get("browser_sessions").as_arr().len(), 0);
        // The page size is 1..=50, the cursor is echoed and skips.
        assert_eq!(list("?page_size=1").get("browser_sessions").as_arr().len(), 1);
        assert_eq!(list("?page_size=0").get("browser_sessions").as_arr().len(), 1);
        assert_eq!(list("?page_size=-4").get("browser_sessions").as_arr().len(), 1);
        assert_eq!(list("?page_size=999").get("browser_sessions").as_arr().len(), 2);
        assert_eq!(list("?page_size=x").get("browser_sessions").as_arr().len(), 2);
        let second = list("?page_size=1&cursor=1");
        assert_eq!((second.get("cursor").as_i64(), second.get("browser_sessions").as_arr().len()), (Some(1), 1));
        assert_eq!(list("?cursor=9").get("browser_sessions").as_arr().len(), 0);
    }

    #[test]
    fn two_copies_join_by_id_and_short_code_and_are_refused_with_the_apis_errors() {
        let port = peerparty_core::test_ports::claim(1);
        let game = format!("test:rallyhere:join:{}", std::process::id());
        let (a, b) = (start(&game, port, "a"), start(&game, port, "b"));
        pump(&[&a, &b], "the copies to meet", || a.peers().iter().any(|(p, _)| *p == b.me()) && b.peers().iter().any(|(p, _)| *p == a.me()));
        let (_pa, _pb) = (Pumped::of(&a), Pumped::of(&b));
        let (wa, wb) = (world_of(&a, &[&b]), world_of(&b, &[&a]));
        let (mut sa, mut sb) = (state(), state());

        let r = req(&wa, &mut sa, "POST", "/session/v1/session", r#"{"session_type":"example_match","client_settings":{"platform":"Steam","input":"gamepad"}}"#);
        let id = json(&r.body).get("session_id").as_str().unwrap().to_string();
        // A short code, only by the leader.
        let denied = req(&wb, &mut sb, "POST", &format!("/session/v1/session/{id}:generate-short-code"), "");
        assert_eq!(denied.status, 404);
        let g = req(&wa, &mut sa, "POST", &format!("/session/v1/session/{id}:generate-short-code"), "");
        assert_eq!(g.status, 200, "{}", g.body);
        let short_code = json(&g.body).get("short_code").as_str().unwrap().to_string();
        assert_eq!(short_code.len(), 5);
        assert_eq!(json(&req(&wa, &mut sa, "GET", &format!("/session/v1/session/{}", short_code.to_lowercase()), "").body).get("short_code").as_str(), Some(short_code.as_str()));

        // Unknown team and unknown session.
        let r = req(&wb, &mut sb, "POST", &format!("/session/v1/session/{id}/player/me"), r#"{"team_id":9}"#);
        assert_eq!((r.status, code_of(&r).as_str()), (400, "team_not_found"));
        assert!(b.lobby(&id).is_none(), "a refused join leaves nothing behind");
        let r = req(&wb, &mut sb, "POST", "/session/v1/session/00000000-0000-4000-8000-000000000000/player/me", "{}");
        assert_eq!((r.status, code_of(&r).as_str()), (404, "session_not_found"));
        let r = req(&wb, &mut sb, "POST", "/session/v1/session/ZZZZZ/player/me", "{}");
        assert_eq!((r.status, code_of(&r).as_str()), (404, "session_not_found"));

        // B joins by code, in team 1.
        let uuid_b = player_uuid(b.me());
        let r = req(&wb, &mut sb, "POST", &format!("/session/v1/session/{}/player/me", short_code.to_lowercase()), r#"{"client_version":"2.0","team_id":1}"#);
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(r.body, format!(r#"{{"player_uuid":"{uuid_b}","status":"member","team_id":1}}"#));
        wait_until("the join to reach both copies", || {
            let seen = |l: Option<Lobby>| l.is_some_and(|l| l.members.len() == 2 && l.members.iter().any(|m| m.id == b.me() && !m.attrs.is_empty()));
            seen(a.lobby(&id)) && seen(b.lobby(&id))
        });
        let j = json(&req(&wa, &mut sa, "GET", &format!("/session/v1/session/{id}"), "").body);
        let on_one = players(&j, 1);
        assert_eq!((on_one.len(), on_one[0].get("player_uuid").as_str(), on_one[0].get("status").as_str(), on_one[0].get("version").as_str()), (1, Some(uuid_b.as_str()), Some("member"), Some("2.0")));
        assert!(on_one[0].get("client_settings").get("platform").as_str().is_some(), "the platform scouts list a joiner too");
        let r = req(&wb, &mut sb, "POST", &format!("/session/v1/session/{id}/player/me"), "{}");
        assert_eq!((r.status, code_of(&r).as_str()), (400, "already_in_session"));
        // me/session on B.
        let mine = json(&req(&wb, &mut sb, "GET", "/session/v1/player/me/session", "").body);
        assert_eq!(mine.get("sessions").get("example_match").get("session_ids").as_arr(), [Json::str(&id)]);

        // What the leader sets for B goes when B leaves, and a rejoin starts from B's own.
        let body = format!(r#"{{"teams":[{{"team_id":1,"players":[{{"player_uuid":"{uuid_b}","version":"leader-says"}}]}}]}}"#);
        let r = req(&wa, &mut sa, "PATCH", &format!("/session/v1/session/{id}"), &body);
        assert_eq!(players(&json(&r.body), 1)[0].get("version").as_str(), Some("leader-says"));
        assert_eq!(req(&wb, &mut sb, "DELETE", &format!("/session/v1/session/{id}/player/me"), "").status, 204);
        wait_until("the override to go with B", || a.lobby(&id).is_some_and(|l| l.members.len() == 1 && Session::from_lobby(&l).overrides.is_empty()));
        let r = req(&wb, &mut sb, "POST", &format!("/session/v1/session/{id}/player/me"), r#"{"client_version":"2.1","team_id":0}"#);
        assert_eq!(r.status, 200, "{}", r.body);
        wait_until("B's own fields", || a.lobby(&id).is_some_and(|l| l.members.len() == 2 && l.members.iter().any(|m| player_uuid(m.id) == uuid_b && !m.attrs.is_empty())));
        let j = json(&req(&wa, &mut sa, "GET", &format!("/session/v1/session/{id}"), "").body);
        let b_json = players(&j, 0).into_iter().find(|p| p.get("player_uuid").as_str() == Some(uuid_b.as_str())).unwrap();
        assert_eq!(b_json.get("version").as_str(), Some("2.1"));

        // A full team: team 0 shrunk to 1 holds the leader, B is refused. B leaves first.
        assert_eq!(req(&wb, &mut sb, "DELETE", &format!("/session/v1/session/{id}/player/me"), "").status, 204);
        wait_until("B gone", || a.lobby(&id).is_some_and(|l| l.members.len() == 1));
        let r = req(&wa, &mut sa, "PATCH", &format!("/session/v1/session/{id}"), r#"{"teams":[{"team_id":0,"max_size":1}]}"#);
        assert_eq!(r.status, 200);
        let r = req(&wb, &mut sb, "POST", &format!("/session/v1/session/{id}/player/me"), r#"{"team_id":0}"#);
        assert_eq!((r.status, code_of(&r).as_str()), (400, "session_full"), "{}", r.body);
        // A closed session isn't joined.
        let r = req(&wa, &mut sa, "PATCH", &format!("/session/v1/session/{id}"), r#"{"joinable":false}"#);
        assert_eq!(r.status, 200);
        let r = req(&wb, &mut sb, "POST", &format!("/session/v1/session/{id}/player/me"), r#"{"team_id":1}"#);
        assert!(matches!((r.status, code_of(&r).as_str()), (400, "session_not_joinable") | (404, "session_not_found")), "{} {}", r.status, r.body);

        // Another edit by a copy that no longer leads is refused after the update, not
        // answered as made.
        let l = a.lobby(&id).unwrap();
        assert!(apply(&b, &id, &l).is_err(), "B isn't in it: not found");
        assert!(apply(&a, &id, &l).is_ok());
    }

    #[test]
    fn a_join_already_running_is_refused() {
        let port = peerparty_core::test_ports::claim(1);
        let lan = start(&format!("test:rallyhere:running:{}", std::process::id()), port, "a");
        let world = world_of(&lan, &[]);
        let st = Mutex::new(state());
        let key = "0b2c5e9a-1111-4222-8333-444455556666".to_string();
        crate::sys::lock(&JOINING).push((lan.me(), key.clone()));
        let r = join(&world, &st, &key.to_uppercase(), &Json::Null);
        assert_eq!((r.status, code_of(&r).as_str()), (400, "session_join_already_in_progress"));
        crate::sys::lock(&JOINING).retain(|(p, _)| *p != lan.me());
    }

    /// A join waits on the LAN for seconds: the copy's state stays free meanwhile, so its
    /// other requests (a sign-in, the regions) are answered at once.
    #[test]
    fn other_requests_are_answered_while_a_join_waits() {
        use crate::rallyhere::route;
        use crate::rallyhere::tests_support::request;
        let port = peerparty_core::test_ports::claim(1);
        let lan = start(&format!("test:rallyhere:waiting:{}", std::process::id()), port, "a");
        let world = world_of(&lan, &[]);
        let shared = Mutex::new(state());
        std::thread::scope(|s| {
            // Nobody answers the search for the code (no pump hands results over): the join
            // waits until its deadline.
            let joining = s.spawn(|| {
                let t = Instant::now();
                (route(&world, &shared, &request("POST", "/session/v1/session/ZZZZZ/player/me", &[], "{}")), t.elapsed())
            });
            wait_until("the join to start", || crate::sys::lock(&JOINING).iter().any(|(p, _)| *p == lan.me()));
            let t = Instant::now();
            let login = route(&world, &shared, &request("POST", "/users/v1/login", &[], r#"{"grant_type":"steam"}"#));
            let regions = route(&world, &shared, &request("GET", "/session/v1/regions", &[], ""));
            let quick = t.elapsed();
            assert_eq!((login.status, regions.status), (200, 200), "{} {}", login.body, regions.body);
            assert!(!joining.is_finished(), "the join was still waiting when they were answered");
            assert!(quick < Duration::from_millis(500), "answered in {quick:?}");
            let (r, took) = joining.join().unwrap();
            assert_eq!((r.status, code(&r).as_deref()), (404, Some("session_not_found")));
            assert!(took >= JOIN_WAIT - Duration::from_millis(100), "the join waited: {took:?}");
        });
        assert!(crate::sys::lock(&shared).platform_name() == "Steam", "the sign-in during the join was kept");
    }

    #[test]
    fn a_patch_by_a_copy_that_no_longer_leads_is_not_owner() {
        let port = peerparty_core::test_ports::claim(1);
        let game = format!("test:rallyhere:owner:{}", std::process::id());
        let (a, b) = (start(&game, port, "a"), start(&game, port, "b"));
        pump(&[&a, &b], "the copies to meet", || a.peers().iter().any(|(p, _)| *p == b.me()) && b.peers().iter().any(|(p, _)| *p == a.me()));
        let wa = world_of(&a, &[&b]);
        let mut sa = state();
        let r = req(&wa, &mut sa, "POST", "/session/v1/session", r#"{"session_type":"example_party"}"#);
        let id = json(&r.body).get("session_id").as_str().unwrap().to_string();
        b.join_by_id(NS, &id).unwrap();
        pump(&[&a, &b], "the join", || b.lobby(&id).is_some_and(|l| l.members.len() == 2));
        // B is a member that isn't the owner: the LAN takes the edit as a no-op.
        let l = b.lobby(&id).unwrap();
        let r = apply(&b, &id, &l).unwrap_err();
        assert_eq!((r.status, code_of(&r).as_str()), (404, "not_owner"));
    }

    #[test]
    fn what_other_copies_put_in_a_lobby_is_bounded() {
        let big = "x".repeat(100_000);
        let teams: Vec<Json> = (0..40).map(|i| Json::obj(vec![("team_id", Json::int(i)), ("max_size", Json::int(1_000_000))])).collect();
        let custom: Vec<(String, Json)> = (0..90).map(|i| (format!("{i}{}", "k".repeat(100)), Json::str("v".repeat(1100)))).collect();
        let mut l = Lobby::new(NS);
        l.id = "i".repeat(500);
        l.attrs = vec![
            attr(K_TYPE, Value::Str(big.clone())),
            attr(K_TEAMS, Value::Str(Json::Arr(teams).to_string())),
            attr(K_SHORT_CODE, Value::Str(big.clone())),
            attr(K_BROWSER, Value::Str(Json::obj(vec![("custom_data", Json::Obj(custom.clone()))]).to_string())),
            attr(K_INSTANCE, Value::Str(Json::obj(vec![("join_params", Json::obj(vec![("public_conn_str", Json::str("c".repeat(2000))), ("private_conn_str", Json::str("c".repeat(2000))), ("custom_data", Json::Obj(custom))]))]).to_string())),
            attr(K_PLAYERS, Value::Str(big.clone())),
        ];
        l.members = (0..300u16)
            .map(|i| Member {
                id: PeerId([(i % 250) as u8 + 1; 16]),
                attrs: vec![
                    attr(M_VERSION, Value::Str(big.clone())),
                    attr(M_CLIENT_SETTINGS, Value::Str(Json::obj(vec![("platform", Json::str(&big)), ("input", Json::str("pad")), ("extra", Json::Arr(vec![Json::Null; 100]))]).to_string())),
                ],
            })
            .collect();
        let s = Session::from_lobby(&l);
        assert_eq!(s.teams.len(), 16);
        assert!(s.teams.iter().all(|t| t.max_size == MAX_TEAM_SIZE));
        assert_eq!(s.short_code.as_deref().map(str::len), Some(MAX_SHORT_CODE));
        assert!(s.kind.len() <= MAX_TEXT);
        let browser = s.browser.unwrap();
        let cd = browser.get("custom_data").as_obj();
        assert_eq!(cd.len(), MAX_ENTRIES);
        assert!(cd.iter().all(|(k, v)| k.len() <= MAX_KEY && v.as_str().is_some_and(|v| v.len() <= MAX_VALUE)));
        let jp = s.instance.unwrap();
        let jp = jp.get("join_params");
        assert!(jp.get("public_conn_str").as_str().unwrap().len() <= MAX_CONN && jp.get("private_conn_str").as_str().unwrap().len() <= MAX_CONN);
        assert_eq!(jp.get("custom_data").as_obj().len(), MAX_ENTRIES);
        let j = render(&l);
        let rendered: usize = j.get("teams").as_arr().iter().map(|t| t.get("players").as_arr().len()).sum();
        assert_eq!(rendered, MAX_PLAYERS);
        let p = &players(&j, 0)[0];
        assert!(p.get("version").as_str().unwrap().len() <= MAX_TEXT);
        assert_eq!(p.get("client_settings").as_obj().len(), 2, "known keys only");
        assert!(p.get("client_settings").get("platform").as_str().unwrap().len() <= MAX_TEXT);
        assert!(j.to_string().len() < MAX_ATTR, "{}", j.to_string().len());
        assert_eq!(browser_entry(&l).get("player_count").as_i64(), Some(MAX_PLAYERS as i64));
    }

    // ---- Notifications ----

    #[test]
    fn each_change_gives_its_notification() {
        use notify::{BROWSER_UPDATED, INSTANCE_UPDATED, PLAYER_ADDED, PLAYER_REMOVED, SESSION_UPDATED};
        let s = session();
        let own = |v: &str| PlayerFields { team: Some(0), version: Some(v.into()), ..Default::default() };
        let base = lobby(&s, vec![member(A, own("1")), member(B, own("2"))]);
        let edited = |f: &dyn Fn(&mut Session)| {
            let mut s = s.clone();
            f(&mut s);
            let mut l = base.clone();
            l.attrs = s.to_attrs();
            l
        };
        assert!(changes(&base, &base).is_empty(), "no change, nothing to tell");
        // What a PATCH changes, a short code, a platform session, what the leader sets for a player.
        let edits: [&dyn Fn(&mut Session); 7] = [
            &|s| s.region = "2".into(),
            &|s| s.joinability.open = true,
            &|s| s.joinability = Joinability::default(),
            &|s| s.teams[1].max_size = 3,
            &|s| s.platform_session = Some(json(r#"[{"platform":"Steam"}]"#)),
            &|s| s.short_code = Some("AB12C".into()),
            &|s| s.overrides = vec![(player_uuid(B), PlayerFields { version: Some("9".into()), ..Default::default() })],
        ];
        for (i, e) in edits.iter().enumerate() {
            assert_eq!(changes(&base, &edited(e)), [SESSION_UPDATED], "edit {i}");
        }
        // A member's own fields.
        let mut l = base.clone();
        l.members[1] = member(B, own("3"));
        assert_eq!(changes(&base, &l), [SESSION_UPDATED]);
        // The instance and the browser info have their own.
        assert_eq!(changes(&base, &edited(&|s| s.instance = Some(json(r#"{"instance_id":"i1","join_status":"pending"}"#)))), [INSTANCE_UPDATED]);
        assert_eq!(changes(&base, &edited(&|s| s.browser = Some(json(r#"{"custom_data":{"map":"x"},"created_timestamp":"t"}"#)))), [BROWSER_UPDATED]);
        // A join; the joiner's own fields arrive just after it: part of the join.
        let mut joined = base.clone();
        joined.members.push(Member { id: C, attrs: Vec::new() });
        assert_eq!(changes(&base, &joined), [PLAYER_ADDED]);
        let mut fields = joined.clone();
        fields.members[2] = member(C, own("4"));
        assert!(changes(&joined, &fields).is_empty());
        assert_eq!(changes(&base, &fields), [PLAYER_ADDED]);
        // A player leaving or removed, with what the leader set for it going too.
        let with_override = edited(&|s| s.overrides = vec![(player_uuid(B), PlayerFields { version: Some("9".into()), ..Default::default() })]);
        let mut gone = base.clone();
        gone.members.truncate(1);
        assert_eq!(changes(&with_override, &gone), [PLAYER_REMOVED]);
        // The leader leaving: the next one leading is part of it. Leading while staying isn't.
        let mut left = base.clone();
        left.members.remove(0);
        left.owner = B;
        assert_eq!(changes(&base, &left), [PLAYER_REMOVED]);
        let mut promoted = base.clone();
        promoted.owner = B;
        assert_eq!(changes(&base, &promoted), [SESSION_UPDATED]);
        // Several at once: one each.
        let mut many = edited(&|s| s.instance = Some(json(r#"{"instance_id":"i1"}"#)));
        many.members.push(Member { id: D, attrs: Vec::new() });
        assert_eq!(changes(&base, &many), [PLAYER_ADDED, INSTANCE_UPDATED]);
    }

    /// The messages `lan`'s player has been told, oldest first.
    fn messages(lan: &Lan) -> Vec<String> {
        notify::queued(&player_uuid(lan.me())).iter().map(|n| n.get("message").as_str().unwrap().to_string()).collect()
    }

    /// A long-poll cursor for now (a millisecond back, so nothing made now is skipped).
    fn cursor_now() -> String {
        format!("{}-0", crate::util::time::millis(std::time::SystemTime::now()) - 1)
    }

    /// Long-polls `lan`'s player from `cursor` (moved on) until a `want` notification comes.
    fn hear(lan: &Lan, cursor: &mut String, want: &str) -> Json {
        let me = player_uuid(lan.me());
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let r = notify::long_poll(&me, &me, &[("exclude_before".into(), cursor.clone()), ("deadline".into(), "2".into())]);
            let j = json(&r.body);
            *cursor = j.get("cursor").as_str().unwrap().to_string();
            if let Some(n) = j.get("notifications").as_arr().iter().find(|n| n.get("message").as_str() == Some(want)) {
                return n.clone();
            }
            assert!(Instant::now() < deadline, "no {want} for {me}: {:?}", messages(lan));
        }
    }

    /// An instance set by the leader (the instance routes stand in here).
    fn set_instance(lan: &Lan, id: &str, status: &str) {
        let l = lan.lobby(id).unwrap();
        let mut s = Session::from_lobby(&l);
        s.instance = Some(json(&format!(r#"{{"instance_id":"i1","join_status":"{status}"}}"#)));
        let mut edited = l.clone();
        edited.attrs = s.to_attrs();
        told(lan, id, Why::Other, || apply(lan, id, &edited)).unwrap();
    }

    #[test]
    fn one_copy_tells_its_player_of_its_own_changes() {
        let port = peerparty_core::test_ports::claim(1);
        let lan = start(&format!("test:rallyhere:told:{}", std::process::id()), port, "a");
        let world = world_of(&lan, &[]);
        let mut st = state();
        let me = player_uuid(lan.me());
        let r = req(&world, &mut st, "POST", "/session/v1/session", r#"{"session_type":"example_match"}"#);
        let id = json(&r.body).get("session_id").as_str().unwrap().to_string();
        assert!(messages(&lan).is_empty(), "making a session tells nothing");

        let r = req(&world, &mut st, "PATCH", &format!("/session/v1/session/{id}"), r#"{"region_id":"2"}"#);
        let told = notify::queued(&me);
        assert_eq!(told.len(), 1);
        assert_eq!((told[0].get("message").as_str(), told[0].get("etag").as_str()), (Some("session_updated"), r.etag.as_deref()));
        assert_eq!(told[0].get("rh_url").as_str(), Some(format!("session/v1/session/{id}").as_str()));
        // The PATCH a game sends right after making a session tells, even if nothing changed.
        let r = req(&world, &mut st, "PATCH", &format!("/session/v1/session/{id}"), "{}");
        assert_eq!(r.status, 200);
        assert_eq!(messages(&lan), ["session_updated", "session_updated"]);
        assert_eq!(req(&world, &mut st, "PATCH", &format!("/session/v1/session/{id}/browser"), r#"{"custom_data":{"map":"x"}}"#).status, 200);
        assert_eq!(req(&world, &mut st, "POST", &format!("/session/v1/session/{id}/browser"), r#"{"custom_data":{"map":"y"}}"#).status, 200);
        set_instance(&lan, &id, "pending");
        assert_eq!(req(&world, &mut st, "POST", &format!("/session/v1/session/{id}:generate-short-code"), "").status, 200);
        let all = ["session_updated", "session_updated", "session_browser_info_updated", "session_browser_info_updated", "session_instance_updated", "session_updated"];
        assert_eq!(messages(&lan), all);
        // The pump looking again finds nothing more; leaving tells nothing.
        assert_eq!(on_events(&lan, &[Event::LobbyUpdated { lobby: id.clone() }]), [id.clone()]);
        assert_eq!(req(&world, &mut st, "DELETE", &format!("/session/v1/session/{id}/player/me"), "").status, 204);
        assert_eq!(messages(&lan), all);

        // The long-poll route: what was told, oldest first; another player's stream is refused.
        let path = format!("/notification/v1/player/{}/stream/notification/lp?exclude_before=&offset_reset_strategy=latest&deadline=25", me.to_uppercase());
        let r = req(&world, &mut st, "GET", &path, "");
        assert_eq!(r.status, 200, "{}", r.body);
        let got: Vec<String> = json(&r.body).get("notifications").as_arr().iter().map(|n| n.get("message").as_str().unwrap().to_string()).collect();
        assert_eq!(got, all);
        let r = req(&world, &mut st, "GET", &format!("/notification/v1/player/{}/stream/notification/lp", player_uuid(D)), "");
        assert_eq!(r.status, 401);
    }

    #[test]
    fn each_members_copy_hears_the_others_changes() {
        use notify::{BROWSER_UPDATED, INSTANCE_UPDATED, PLAYER_ADDED, PLAYER_REMOVED, SESSION_UPDATED};
        let port = peerparty_core::test_ports::claim(1);
        let game = format!("test:rallyhere:notify:{}", std::process::id());
        let (a, b) = (start(&game, port, "a"), start(&game, port, "b"));
        pump(&[&a, &b], "the copies to meet", || a.peers().iter().any(|(p, _)| *p == b.me()) && b.peers().iter().any(|(p, _)| *p == a.me()));
        let (_pa, _pb) = (Pumped::of(&a), Pumped::of(&b));
        let (wa, wb) = (world_of(&a, &[&b]), world_of(&b, &[&a]));
        let (mut sa, mut sb) = (state(), state());
        let ub = player_uuid(b.me());
        let r = req(&wa, &mut sa, "POST", "/session/v1/session", r#"{"session_type":"example_match"}"#);
        let id = json(&r.body).get("session_id").as_str().unwrap().to_string();
        let settled = |id: &str| {
            let seen = |l: Option<Lobby>| l.is_some_and(|l| l.members.len() == 2 && l.members.iter().all(|m| !m.attrs.is_empty()));
            seen(a.lobby(id)) && seen(b.lobby(id))
        };
        let (mut ca, mut cb) = (cursor_now(), cursor_now());

        // B joins: both copies hear a player came.
        assert_eq!(req(&wb, &mut sb, "POST", &format!("/session/v1/session/{id}/player/me"), "{}").status, 200);
        let n = hear(&a, &mut ca, PLAYER_ADDED);
        assert_eq!(n.get("rh_url").as_str(), Some(format!("session/v1/session/{id}").as_str()));
        hear(&b, &mut cb, PLAYER_ADDED);
        wait_until("the join to settle", || settled(&id));

        // A changes the joinability while B's long-poll waits: B hears it within a second,
        // with the session's ETag after it.
        cb = cursor_now();
        let (b2, c2) = (b.clone(), cb.clone());
        let waiter = std::thread::spawn(move || {
            let mut c = c2;
            let n = hear(&b2, &mut c, SESSION_UPDATED);
            (n, Instant::now(), c)
        });
        wait_until("B's long-poll to wait", || notify::waiting(&ub) > 0);
        let t = Instant::now();
        let r = req(&wa, &mut sa, "PATCH", &format!("/session/v1/session/{id}"), r#"{"joinability":{"open":false,"friends":true}}"#);
        assert_eq!(r.status, 200);
        let (n, at, c) = waiter.join().unwrap();
        cb = c;
        assert!(at.duration_since(t) < Duration::from_secs(1), "{:?}", at.duration_since(t));
        assert_eq!(n.get("etag").as_str(), r.etag.as_deref());
        hear(&a, &mut ca, SESSION_UPDATED);

        // The instance and the browser info.
        set_instance(&a, &id, "joinable");
        hear(&b, &mut cb, INSTANCE_UPDATED);
        hear(&a, &mut ca, INSTANCE_UPDATED);
        assert_eq!(req(&wa, &mut sa, "PATCH", &format!("/session/v1/session/{id}/browser"), r#"{"custom_data":{"map":"x"}}"#).status, 200);
        hear(&b, &mut cb, BROWSER_UPDATED);

        // B leaves: A hears it; B, who left, is told nothing.
        let told_b = notify::queued(&ub).len();
        assert_eq!(req(&wb, &mut sb, "DELETE", &format!("/session/v1/session/{id}/player/me"), "").status, 204);
        hear(&a, &mut ca, PLAYER_REMOVED);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(notify::queued(&ub).len(), told_b, "{:?}", messages(&b));

        // B joins again and A removes B: both hear it.
        assert_eq!(req(&wb, &mut sb, "POST", &format!("/session/v1/session/{id}/player/me"), "{}").status, 200);
        hear(&a, &mut ca, PLAYER_ADDED);
        hear(&b, &mut cb, PLAYER_ADDED);
        wait_until("the second join to settle", || settled(&id));
        assert_eq!(req(&wa, &mut sa, "DELETE", &format!("/session/v1/session/{id}/player/uuid/{ub}"), "").status, 204);
        hear(&a, &mut ca, PLAYER_REMOVED);
        hear(&b, &mut cb, PLAYER_REMOVED);    }

    #[test]
    fn health_alone_is_not_an_instance_change() {
        let mut s = session();
        s.instance = Some(json(r#"{"instance_id":"i1","join_status":"joinable","instance_health":"unknown"}"#));
        let old = lobby(&s, vec![member(A, PlayerFields::default())]);
        s.instance = Some(json(r#"{"instance_id":"i1","join_status":"joinable","instance_health":"healthy"}"#));
        let healthy = lobby(&s, vec![member(A, PlayerFields::default())]);
        assert!(changes(&old, &healthy).is_empty());
        s.instance = Some(json(r#"{"instance_id":"i1","join_status":"full","instance_health":"healthy"}"#));
        let full = lobby(&s, vec![member(A, PlayerFields::default())]);
        assert_eq!(changes(&healthy, &full), [notify::INSTANCE_UPDATED]);
    }

    #[test]
    fn the_instance_routes_follow_the_api() {
        let port = peerparty_core::test_ports::claim(1);
        let lan = start(&format!("test:rallyhere:instance:{}", std::process::id()), port, "a");
        let world = world_of(&lan, &[]);
        let mut st = state();
        let r = req(&world, &mut st, "POST", "/session/v1/session", r#"{"session_type":"example_match"}"#);
        let id = json(&r.body).get("session_id").as_str().unwrap().to_string();
        let path = format!("/session/v1/session/{id}/instance");
        let err = |r: &Reply| (r.status, json(&r.body).get("error_code").as_str().map(str::to_string));

        // None yet.
        assert_eq!(err(&req(&world, &mut st, "GET", &path, "")), (404, Some("session_instance_not_found".into())));
        assert_eq!(err(&req(&world, &mut st, "DELETE", &path, "")), (404, Some("instance_not_found".into())));
        assert_eq!(err(&req(&world, &mut st, "PATCH", &path, r#"{"join_status":"pending"}"#)), (404, Some("session_instance_not_found".into())));
        assert_eq!(err(&req(&world, &mut st, "POST", &format!("{path}/health"), r#"{"instance_health":"healthy"}"#)), (404, Some("session_instance_not_found".into())));
        assert_eq!(err(&req(&world, &mut st, "POST", "/session/v1/session/nope/instance", "{}")), (404, Some("session_not_found".into())));

        // POST: the caller hosts, requested, health unknown, no version or match yet.
        let r = req(&world, &mut st, "POST", &path, r#"{"instance_id":"inst-1","host_type":"player","host_player_uuid":"someone-else","instance_startup_params":{"map":"m1","mode":"duel","misc_params":{"a":"b"},"ignored":1}}"#);
        assert_eq!(r.status, 200, "{}", r.body);
        let i = json(&r.body);
        assert_eq!(i.get("instance_id").as_str(), Some("inst-1"));
        assert_eq!(i.get("host_type").as_str(), Some("player"));
        assert_eq!(i.get("host_player_uuid").as_str(), Some(player_uuid(lan.me()).as_str()));
        assert_eq!(i.get("host_player_id").as_i64(), Some(player_id(lan.me())));
        assert_eq!((i.get("join_status").as_str(), i.get("instance_health").as_str()), (Some("requested"), Some("unknown")));
        assert_eq!(i.get("instance_startup_params").get("map").as_str(), Some("m1"));
        assert_eq!(i.get("instance_startup_params").get("misc_params").get("a").as_str(), Some("b"));
        assert!(i.get("instance_startup_params").get("ignored").is_null());
        assert!(i.get("version").is_null() && i.get("match_id").is_null() && i.get("join_params").is_null());
        assert!(!i.get("created").as_str().unwrap_or_default().is_empty());
        // A POST without anything: a fresh id and the defaults.
        let again = json(&req(&world, &mut st, "POST", &path, "{}").body);
        assert_ne!(again.get("instance_id").as_str(), Some("inst-1"));
        assert_eq!(again.get("host_type").as_str(), Some("player"));
        assert!(again.get("instance_startup_params").is_null());
        assert_eq!(messages(&lan), ["session_instance_updated", "session_instance_updated"]);

        // PATCH: pending, then joinable with join params; version and match id appear once set.
        let r = req(&world, &mut st, "PATCH", &path, r#"{"join_status":"pending"}"#);
        assert_eq!(json(&r.body).get("join_status").as_str(), Some("pending"));
        let r = req(&world, &mut st, "PATCH", &path, r#"{"join_status":"joinable","version":"1.2","match_id":"m-9","join_params":{"public_conn_str":"0.0.0.0:7777","private_conn_str":"unreal://EOS:ab:G:1","custom_data":{"k":"v"}}}"#);
        let i = json(&r.body);
        assert_eq!((i.get("join_status").as_str(), i.get("version").as_str(), i.get("match_id").as_str()), (Some("joinable"), Some("1.2"), Some("m-9")));
        // A later PATCH merges: the other string and custom data keys stay.
        let r = req(&world, &mut st, "PATCH", &path, r#"{"join_params":{"public_conn_str":"127.0.0.1:7778","custom_data":{"k2":"v2"}}}"#);
        let p = json(&r.body);
        let p = p.get("join_params");
        assert_eq!((p.get("public_conn_str").as_str(), p.get("private_conn_str").as_str()), (Some("127.0.0.1:7778"), Some("unreal://EOS:ab:G:1")));
        assert_eq!((p.get("custom_data").get("k").as_str(), p.get("custom_data").get("k2").as_str()), (Some("v"), Some("v2")));
        assert_eq!(messages(&lan).len(), 5);

        // GET (and the session's own) show it; the host reads its own strings as written.
        let g = req(&world, &mut st, "GET", &path, "");
        assert_eq!(g.status, 200);
        assert_eq!(json(&g.body).get("join_params").get("public_conn_str").as_str(), Some("127.0.0.1:7778"));
        assert_eq!(req(&world, &mut st, "GET", &path, "").etag, g.etag);
        let s = req(&world, &mut st, "GET", &format!("/session/v1/session/{id}"), "");
        assert_eq!(json(&s.body).get("instance").get("instance_id").as_str(), json(&g.body).get("instance_id").as_str());

        // Health: answered, kept, and not told.
        let told_before = messages(&lan).len();
        let h = req(&world, &mut st, "POST", &format!("{path}/health"), &format!(r#"{{"instance_id":"{}","instance_health":"healthy"}}"#, json(&g.body).get("instance_id").as_str().unwrap()));
        assert_eq!((h.status, json(&h.body).get("updated_instance_health").as_str()), (200, Some("healthy")));
        assert_eq!(json(&req(&world, &mut st, "GET", &path, "").body).get("instance_health").as_str(), Some("healthy"));
        assert_eq!(err(&req(&world, &mut st, "POST", &format!("{path}/health"), r#"{"instance_id":"other","instance_health":"healthy"}"#)), (404, Some("session_instance_not_found".into())));
        assert_eq!(req(&world, &mut st, "POST", &format!("{path}/health"), "{}").status, 400);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(messages(&lan).len(), told_before, "{:?}", messages(&lan));

        // An instance too large for a lobby attribute is refused, and the old one stays.
        let big = |p: &str| (0..64).map(|i| format!(r#""{p}{i:0>58}":"{}""#, "x".repeat(1024))).collect::<Vec<_>>().join(",");
        let huge = req(&world, &mut st, "POST", &path, &["{\"instance_startup_params\":{\"misc_params\":{", &big("m"), "}}}"].concat());
        assert_eq!(huge.status, 200, "one big map still fits");
        let before = json(&req(&world, &mut st, "GET", &path, "").body).get("instance_id").as_str().unwrap().to_string();
        let r = req(&world, &mut st, "PATCH", &path, &["{\"join_params\":{\"custom_data\":{", &big("c"), "}}}"].concat());
        assert_eq!(err(&r), (413, Some("payload_too_large".into())), "{}", r.body);
        let kept = json(&req(&world, &mut st, "GET", &path, "").body);
        assert_eq!(kept.get("instance_id").as_str(), Some(before.as_str()));
        assert!(kept.get("join_params").is_null(), "the refused patch changed nothing");
        let told_before = messages(&lan).len();

        // DELETE: gone, and told.
        assert_eq!(req(&world, &mut st, "DELETE", &path, "").status, 204);
        assert_eq!(err(&req(&world, &mut st, "GET", &path, "")), (404, Some("session_instance_not_found".into())));
        assert_eq!(err(&req(&world, &mut st, "DELETE", &path, "")), (404, Some("instance_not_found".into())));
        assert_eq!(messages(&lan).len(), told_before + 1);
        assert!(json(&req(&world, &mut st, "GET", &format!("/session/v1/session/{id}"), "").body).get("instance").is_null());
    }

    /// A public session's players read a lobby value of core's cap at most: while the copy
    /// plays public sessions, an instance that long is refused instead of reaching joiners as
    /// none; a usual one is stored, and on the LAN alone the long one still is.
    #[test]
    fn an_instance_too_long_for_a_public_session_is_refused_there() {
        struct Public;
        impl Drop for Public {
            fn drop(&mut self) {
                instance::TEST_PUBLIC.with(|p| p.set(false));
            }
        }
        let port = peerparty_core::test_ports::claim(1);
        let lan = start(&format!("test:rallyhere:public-instance:{}", std::process::id()), port, "a");
        let world = world_of(&lan, &[]);
        let mut st = state();
        let r = req(&world, &mut st, "POST", "/session/v1/session", r#"{"session_type":"example_match"}"#);
        let id = json(&r.body).get("session_id").as_str().unwrap().to_string();
        let path = format!("/session/v1/session/{id}/instance");
        let err = |r: &Reply| (r.status, json(&r.body).get("error_code").as_str().map(str::to_string), json(&r.body).get("auth_success").as_bool());
        let long = format!(r#"{{"instance_startup_params":{{"map":"m","misc_params":"{}"}}}}"#, "x".repeat(MAX_VALUE));

        let _public = Public;
        instance::TEST_PUBLIC.with(|p| p.set(true));
        // Too long for a stranger: refused with the API's envelope, and nothing stored.
        assert_eq!(err(&req(&world, &mut st, "POST", &path, &long)), (413, Some("payload_too_large".into()), Some(true)));
        assert_eq!(req(&world, &mut st, "GET", &path, "").status, 404, "no instance a joiner would read as none");
        // A usual instance is stored, patched and read back whole.
        assert_eq!(req(&world, &mut st, "POST", &path, r#"{"instance_startup_params":{"map":"m","mode":"x","misc_params":"?listen"}}"#).status, 200);
        let r = req(&world, &mut st, "PATCH", &path, r#"{"join_status":"joinable","join_params":{"public_conn_str":"0.0.0.0:7777","custom_data":{"rh.SessionSecurityToken":"0123456789abcdef0123456789abcdef"}}}"#);
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(Session::from_lobby(&lan.lobby(&id).unwrap()).instance.is_some());
        // A PATCH that would make it too long is refused and changes nothing.
        let grow = format!(r#"{{"join_params":{{"custom_data":{{"k":"{}"}}}}}}"#, "y".repeat(MAX_VALUE));
        assert_eq!(err(&req(&world, &mut st, "PATCH", &path, &grow)), (413, Some("payload_too_large".into()), Some(true)));
        let kept = json(&req(&world, &mut st, "GET", &path, "").body);
        assert_eq!(kept.get("join_status").as_str(), Some("joinable"));
        assert!(kept.get("join_params").get("custom_data").get("k").is_null());

        // On the LAN alone, the long one is stored as before.
        instance::TEST_PUBLIC.with(|p| p.set(false));
        assert_eq!(req(&world, &mut st, "POST", &path, &long).status, 200);
        let i = json(&req(&world, &mut st, "GET", &path, "").body);
        assert_eq!(i.get("instance_startup_params").get("misc_params").as_str().map(str::len), Some(MAX_VALUE));
    }

    #[test]
    fn the_title_defaults_complete_the_instance_on_every_route() {
        let d = crate::rallyhere::config::parse(
            r#"{"instance": {"instance_startup_params": {"map": "", "mode": "", "misc_params": ""},
                "join_params": {"custom_data": {}, "private_conn_str": "", "public_conn_str": ""}}}"#,
        )
        .unwrap()
        .instance;
        instance::TEST_DEFAULTS.with(|t| *t.borrow_mut() = Some(d));
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                instance::TEST_DEFAULTS.with(|t| *t.borrow_mut() = None);
            }
        }
        let _reset = Reset;
        let port = peerparty_core::test_ports::claim(1);
        let lan = start(&format!("test:rallyhere:instdefaults:{}", std::process::id()), port, "a");
        let world = world_of(&lan, &[]);
        let mut st = state();
        let r = req(&world, &mut st, "POST", "/session/v1/session", r#"{"session_type":"example_match"}"#);
        let id = json(&r.body).get("session_id").as_str().unwrap().to_string();
        let path = format!("/session/v1/session/{id}/instance");
        let startup = r#"{"map":"/Game/Maps/X","misc_params":"","mode":""}"#;
        let join_empty = r#"{"custom_data":{},"private_conn_str":"","public_conn_str":""}"#;
        let sorted = |j: &Json| {
            let mut v: Vec<String> = j.as_obj().iter().map(|(k, x)| format!("{k}={x}")).collect();
            v.sort();
            v
        };
        let expect = |j: &Json, s: &str| assert_eq!(sorted(j), sorted(&json(s)), "{j}");

        let r = req(&world, &mut st, "POST", &path, r#"{"instance_startup_params":{"map":"/Game/Maps/X","misc_params":""},"host_type":"player"}"#);
        assert_eq!(r.status, 200, "{}", r.body);
        let i = json(&r.body);
        expect(i.get("instance_startup_params"), startup);
        expect(i.get("join_params"), join_empty);

        let r = req(&world, &mut st, "PATCH", &path, r#"{"join_status":"pending","version":"1.0"}"#);
        let i = json(&r.body);
        expect(i.get("instance_startup_params"), startup);
        expect(i.get("join_params"), join_empty);

        // Once joinable the game's strings and custom data win over the defaults.
        let r = req(&world, &mut st, "PATCH", &path, r#"{"join_status":"joinable","join_params":{"public_conn_str":"127.0.0.1:7777","custom_data":{"k":"v"}}}"#);
        let p = json(&r.body);
        assert_eq!(p.get("join_params").get("public_conn_str").as_str(), Some("127.0.0.1:7777"));
        assert_eq!(p.get("join_params").get("private_conn_str").as_str(), Some(""));
        assert_eq!(p.get("join_params").get("custom_data").get("k").as_str(), Some("v"));

        let g = json(&req(&world, &mut st, "GET", &path, "").body);
        expect(g.get("instance_startup_params"), startup);
        assert_eq!(g.get("join_params").get("private_conn_str").as_str(), Some(""));
        let s = json(&req(&world, &mut st, "GET", &format!("/session/v1/session/{id}"), "").body);
        expect(s.get("instance").get("instance_startup_params"), startup);
        assert_eq!(s.get("instance").get("join_params").get("public_conn_str").as_str(), Some("127.0.0.1:7777"));

        // A new instance with nothing sent: the defaults alone, and nothing stored for them.
        assert_eq!(req(&world, &mut st, "POST", &path, "{}").status, 200);
        let g = json(&req(&world, &mut st, "GET", &path, "").body);
        expect(g.get("instance_startup_params"), r#"{"map":"","mode":"","misc_params":""}"#);
        let l = find(&lan, &id).unwrap();
        assert!(Session::from_lobby(&l).instance.unwrap().get("instance_startup_params").is_null(), "defaults belong to the config, not the lobby");
    }

    #[test]
    fn two_members_get_one_voice_room_and_each_their_own_product_user_id() {
        let port = peerparty_core::test_ports::claim(1);
        let game = format!("test:rallyhere:voip:{}", std::process::id());
        let (a, b, c) = (start(&game, port, "a"), start(&game, port, "b"), start(&game, port, "c"));
        pump(&[&a, &b, &c], "the copies to meet", || [&a, &b, &c].iter().all(|l| l.peers().len() >= 2));
        let (_pa, _pb, _pc) = (Pumped::of(&a), Pumped::of(&b), Pumped::of(&c));
        let (wa, wb, wc) = (world_of(&a, &[&b, &c]), world_of(&b, &[&a, &c]), world_of(&c, &[&a, &b]));
        let (mut sa, mut sb, mut sc) = (state(), state(), state());
        let r = req(&wa, &mut sa, "POST", "/session/v1/session", r#"{"session_type":"example_match","client_settings":{"platform":"Steam","input":"gamepad"}}"#);
        let id = json(&r.body).get("session_id").as_str().unwrap().to_string();
        let r = req(&wb, &mut sb, "POST", &format!("/session/v1/session/{id}/player/me"), "{}");
        assert_eq!(r.status, 200, "{}", r.body);
        wait_until("the join", || a.lobby(&id).is_some_and(|l| l.members.len() == 2));
        let path = format!("/session/v1/session/{id}/player/me/voip/epic:join?voip_session_type=session");

        let ra = req(&wa, &mut sa, "GET", &path, "");
        let rb = req(&wb, &mut sb, "GET", &path, "");
        assert_eq!((ra.status, rb.status), (200, 200), "{} {}", ra.body, rb.body);
        let (ja, jb) = (json(&ra.body), json(&rb.body));
        // The same room for both, the one `voip::room_name` gives; stable across calls.
        assert_eq!(ja.get("room_id").as_str(), Some(crate::rallyhere::voip::room_name(&id).as_str()));
        assert_eq!(ja.get("room_id").as_str(), jb.get("room_id").as_str());
        assert_eq!(req(&wa, &mut sa, "GET", &path, "").body, ra.body);
        // Each its own ProductUserId, as the EOS layer gives it to that copy.
        assert_eq!(ja.get("product_user_id").as_str(), Some(crate::eos::product_user_id(a.me()).as_str()));
        assert_eq!(jb.get("product_user_id").as_str(), Some(crate::eos::product_user_id(b.me()).as_str()));
        assert_ne!(ja.get("product_user_id").as_str(), jb.get("product_user_id").as_str());
        // By id in capitals: the same room. No query: the session type.
        let by_id = req(&wb, &mut sb, "GET", &format!("/session/v1/session/{}/player/me/voip/epic:join", id.to_uppercase()), "");
        assert_eq!(json(&by_id.body).get("room_id").as_str(), ja.get("room_id").as_str());
        // Placeholders: not empty, not a URL.
        for key in ["participant_token", "client_base_url"] {
            let v = ja.get(key).as_str().unwrap();
            assert!(!v.is_empty() && !v.contains("://") && !v.contains('.'), "{key}: {v}");
        }

        // A copy that is not in the session, and one that does not know it: 404 session_not_found.
        let r = req(&wc, &mut sc, "GET", &path, "");
        assert_eq!((r.status, code_of(&r).as_str()), (404, "session_not_found"));
        let unknown = "/session/v1/session/00000000-0000-4000-8000-000000000000/player/me/voip/epic:join";
        let r = req(&wa, &mut sa, "GET", unknown, "");
        assert_eq!((r.status, code_of(&r).as_str()), (404, "session_not_found"));

        // Another voice type or route is a gap (the unknown-route answer), as is a bearer this copy didn't issue.
        for p in [format!("/session/v1/session/{id}/player/me/voip/epic:join?voip_session_type=team"), format!("/session/v1/session/{id}/player/me/voip/vivox:join")] {
            let r = req(&wa, &mut sa, "GET", &p, "");
            assert_eq!((r.status, code_of(&r).as_str()), (404, "not_implemented"), "{p}");
        }
        let r = authed(&wa, &mut sa, "nope", "GET", &path, "");
        assert_eq!(r.status, 401);
        // Once the member left, the session is no longer its own.
        assert_eq!(req(&wb, &mut sb, "DELETE", &format!("/session/v1/session/{id}/player/me"), "").status, 204);
        let r = req(&wb, &mut sb, "GET", &path, "");
        assert_eq!((r.status, code_of(&r).as_str()), (404, "session_not_found"));
    }

    /// The access token of a sign-in on `world`'s copy.
    fn sign_in(world: &World, st: &mut State) -> String {
        let r = req(world, st, "POST", "/users/v1/login", r#"{"grant_type":"steam"}"#);
        assert_eq!(r.status, 200, "{}", r.body);
        json(&r.body).get("access_token").as_str().unwrap().to_string()
    }

    /// A request with the bearer token of a sign-in.
    fn authed(world: &World, st: &mut State, token: &str, method: &str, path: &str, body: &str) -> Reply {
        call_with(world, st, method, path, &[("Authorization", &format!("Bearer {token}"))], body)
    }

    /// Long-polls the route of the player of `world` from `cursor` (moved on) until a `want`
    /// notification comes.
    fn poll_for(world: &World, st: &mut State, token: &str, cursor: &mut String, want: &str) -> Json {
        let me = player_uuid(world.me);
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let path = format!("/notification/v1/player/{me}/stream/notification/lp?exclude_before={cursor}&offset_reset_strategy=latest&deadline=2");
            let j = json(&authed(world, st, token, "GET", &path, "").body);
            *cursor = j.get("cursor").as_str().unwrap().to_string();
            if let Some(n) = j.get("notifications").as_arr().iter().find(|n| n.get("message").as_str() == Some(want)) {
                return n.clone();
            }
            assert!(Instant::now() < deadline, "no {want} for {me}");
        }
    }

    #[test]
    fn two_copies_sign_in_create_join_and_notify() {
        use notify::{INSTANCE_UPDATED, PLAYER_ADDED, SESSION_UPDATED};
        let port = peerparty_core::test_ports::claim(1);
        let game = format!("test:rallyhere:integration:{}", std::process::id());
        let (a, b) = (start(&game, port, "a"), start(&game, port, "b"));
        pump(&[&a, &b], "the copies to meet", || a.peers().iter().any(|(p, _)| *p == b.me()) && b.peers().iter().any(|(p, _)| *p == a.me()));
        let (_pa, _pb) = (Pumped::of(&a), Pumped::of(&b));
        let (wa, wb) = (world_of(&a, &[&b]), world_of(&b, &[&a]));
        let (mut sa, mut sb) = (state(), state());
        let (ta, tb) = (sign_in(&wa, &mut sa), sign_in(&wb, &mut sb));
        let mut ca = cursor_now();

        // A creates a session and an instance whose strings are on A's own PC.
        let r = authed(&wa, &mut sa, &ta, "POST", "/session/v1/session", r#"{"session_type":"example_match","client_version":"1.0.0","client_settings":{"platform":"Steam","input":"gamepad"}}"#);
        assert_eq!(r.status, 200, "{}", r.body);
        let id = json(&r.body).get("session_id").as_str().unwrap().to_string();
        let ipath = format!("/session/v1/session/{id}/instance");
        assert_eq!(authed(&wa, &mut sa, &ta, "POST", &ipath, r#"{"instance_startup_params":{"map":"m1"}}"#).status, 200);
        let r = authed(&wa, &mut sa, &ta, "PATCH", &ipath, r#"{"join_status":"joinable","join_params":{"public_conn_str":"0.0.0.0:7777?team=1","private_conn_str":"unreal://EOS:0123456789abcdef0123456789abcdef:GameNetDriver:3"}}"#);
        assert_eq!(r.status, 200, "{}", r.body);
        poll_for(&wa, &mut sa, &ta, &mut ca, INSTANCE_UPDATED);

        // B joins by id: A's long-poll returns `session_player_added` for the session.
        let r = authed(&wb, &mut sb, &tb, "POST", &format!("/session/v1/session/{id}/player/me"), r#"{"client_version":"1.0.0"}"#);
        assert_eq!(r.status, 200, "{}", r.body);
        let n = poll_for(&wa, &mut sa, &ta, &mut ca, PLAYER_ADDED);
        assert_eq!(n.get("rh_url").as_str(), Some(format!("session/v1/session/{id}").as_str()));
        wait_until("both players and the instance in both copies", || {
            let seen = |l: Option<Lobby>| l.is_some_and(|l| l.members.len() == 2 && l.members.iter().all(|m| !m.attrs.is_empty()) && Session::from_lobby(&l).instance.is_some());
            seen(a.lobby(&id)) && seen(b.lobby(&id))
        });

        // A patches the joinability: B's long-poll returns `session_updated`.
        let (a2, b2, tb2, cb2) = (a.clone(), b.clone(), tb.clone(), cursor_now());
        let waiter = std::thread::spawn(move || {
            let (mut st, mut c) = (state(), cb2);
            st.access = vec![tb2.clone()];
            poll_for(&world_of(&b2, &[&a2]), &mut st, &tb2, &mut c, SESSION_UPDATED)
        });
        let r = authed(&wa, &mut sa, &ta, "PATCH", &format!("/session/v1/session/{id}"), r#"{"joinability":{"open":false,"friends":true}}"#);
        assert_eq!(r.status, 200, "{}", r.body);
        let n = waiter.join().unwrap();
        assert_eq!(n.get("message").as_str(), Some(SESSION_UPDATED));

        // B's GET shows both players and the instance, rewritten to A as B reaches it.
        let g = authed(&wb, &mut sb, &tb, "GET", &format!("/session/v1/session/{id}"), "");
        assert_eq!(g.status, 200, "{}", g.body);
        let j = json(&g.body);
        assert_eq!(players(&j, 0).len(), 2);
        let reach = match b.game_address(a.me()) {
            Some(std::net::IpAddr::V4(v)) => v,
            _ => peerparty_core::fwd::Forwarder::address_of(a.me()),
        };
        let i = j.get("instance");
        assert_eq!(i.get("join_status").as_str(), Some("joinable"));
        assert_eq!(i.get("join_params").get("public_conn_str").as_str(), Some(format!("{reach}:7777?team=1").as_str()));
        assert_ne!(i.get("join_params").get("public_conn_str").as_str(), Some("0.0.0.0:7777?team=1"), "the host's own address is no use to B");
        assert_eq!(i.get("join_params").get("private_conn_str").as_str(), Some("unreal://EOS:0123456789abcdef0123456789abcdef:GameNetDriver:3"));
        assert_eq!(json(&authed(&wb, &mut sb, &tb, "GET", &ipath, "").body).get("join_params").get("public_conn_str").as_str(), i.get("join_params").get("public_conn_str").as_str());
        // A reads its own strings as it wrote them.
        let ga = json(&authed(&wa, &mut sa, &ta, "GET", &format!("/session/v1/session/{id}"), "").body);
        assert_eq!(ga.get("instance").get("join_params").get("public_conn_str").as_str(), Some("0.0.0.0:7777?team=1"));

        // B isn't the leader: every write of the instance is refused.
        for (method, path, body) in [("POST", ipath.clone(), "{}"), ("PATCH", ipath.clone(), r#"{"join_status":"full"}"#), ("DELETE", ipath.clone(), ""), ("POST", format!("{ipath}/health"), r#"{"instance_health":"healthy"}"#)] {
            let r = authed(&wb, &mut sb, &tb, method, &path, body);
            assert_eq!((r.status, json(&r.body).get("error_code").as_str()), (404, Some("not_owner")), "{method} {path}");
        }
        // The strings are read toward the instance's host player, not the lobby's owner: with
        // B as host, A reads B's own strings rewritten and B reads them as they are; with a
        // host who isn't in the session, nobody rewrites them.
        let set_host = |uuid: &str| {
            let l = a.lobby(&id).unwrap();
            let mut s = Session::from_lobby(&l);
            let Some(Json::Obj(pairs)) = s.instance.take() else { panic!("no instance") };
            s.instance = Some(Json::Obj(pairs.into_iter().map(|(k, v)| if k == "host_player_uuid" { (k, Json::str(uuid)) } else { (k, v) }).collect()));
            let mut edited = l.clone();
            edited.attrs = s.to_attrs();
            told(&a, &id, Why::Other, || apply(&a, &id, &edited)).unwrap();
        };
        let public = |w: &World, s: &mut State, t: &str| json(&authed(w, s, t, "GET", &format!("/session/v1/session/{id}"), "").body).get("instance").get("join_params").get("public_conn_str").as_str().unwrap().to_string();
        set_host(&player_uuid(b.me()));
        wait_until("B as the host", || Session::from_lobby(&b.lobby(&id).unwrap()).instance.is_some_and(|i| i.get("host_player_uuid").as_str() == Some(player_uuid(b.me()).as_str())));
        let toward_b = match a.game_address(b.me()) {
            Some(std::net::IpAddr::V4(v)) => v,
            _ => peerparty_core::fwd::Forwarder::address_of(b.me()),
        };
        assert_eq!(public(&wa, &mut sa, &ta), format!("{toward_b}:7777?team=1"));
        assert_eq!(public(&wb, &mut sb, &tb), "0.0.0.0:7777?team=1");
        set_host("00000000-0000-4000-8000-000000000000");
        wait_until("a host that left", || Session::from_lobby(&b.lobby(&id).unwrap()).instance.is_some_and(|i| i.get("host_player_uuid").as_str() == Some("00000000-0000-4000-8000-000000000000")));
        assert_eq!(public(&wb, &mut sb, &tb), "0.0.0.0:7777?team=1");
        assert_eq!(public(&wa, &mut sa, &ta), "0.0.0.0:7777?team=1");
        assert_eq!(authed(&wa, &mut sa, &ta, "DELETE", &ipath, "").status, 204);
    }

    #[test]
    fn two_copies_link_a_platform_session_and_a_stranger_finds_it() {
        let port = peerparty_core::test_ports::claim(1);
        let game = format!("test:rallyhere:platform:{}", std::process::id());
        let (a, b) = (start(&game, port, "a"), start(&game, port, "b"));
        pump(&[&a, &b], "the copies to meet", || a.peers().iter().any(|(p, _)| *p == b.me()) && b.peers().iter().any(|(p, _)| *p == a.me()));
        let (_pa, _pb) = (Pumped::of(&a), Pumped::of(&b));
        let (wa, wb) = (world_of(&a, &[&b]), world_of(&b, &[&a]));
        let (mut sa, mut sb) = (state(), state());
        let r = req(&wa, &mut sa, "POST", "/session/v1/session", r#"{"session_type":"example_match"}"#);
        let id = json(&r.body).get("session_id").as_str().unwrap().to_string();
        let psid = encoding::base64(b"STEAM:109775244200441988");
        let link = format!("/session/v1/platform/Steam/platform-session/{psid}/session/{id}");
        let lookup = format!("/session/v1/platform/Steam/session/{psid}");

        // Nothing is linked yet: the lookup finds none, the unlink is a 404.
        assert_eq!(code(&req(&wb, &mut sb, "GET", &lookup, "")).as_deref(), Some("session_not_found"));
        let r = req(&wa, &mut sa, "DELETE", &link, "");
        assert_eq!((r.status, code(&r).as_deref()), (404, Some("platform_session_not_found")));
        // Garbage ids and a stranger's write.
        assert_eq!(code(&req(&wa, &mut sa, "POST", &format!("/session/v1/platform/Steam/platform-session/!!!/session/{id}"), "")).as_deref(), Some("invalid_request"));
        assert_eq!(req(&wa, &mut sa, "POST", &format!("/session/v1/platform/Steam/platform-session/{}/session/{id}", "QUJD".repeat(40)), "").status, 400);
        assert_eq!(req(&wa, &mut sa, "POST", &format!("/session/v1/platform/Steam/platform-session/{psid}/session/00000000-0000-4000-8000-000000000000"), "").status, 404);

        let r = req(&wa, &mut sa, "POST", &link, "");
        assert_eq!(r.status, 200, "{}", r.body);
        let j = json(&r.body);
        assert_eq!((j.get("platform").as_str(), j.get("platform_session_type").as_str(), j.get("platform_session_id_base64").as_str()), (Some("Steam"), Some("example_match"), Some(psid.as_str())));
        assert_eq!(j.get("players").as_arr().len(), 0);
        let shown = |w: &World, st: &mut State| json(&req(w, st, "GET", &format!("/session/v1/session/{id}"), "").body).get("platform_session").to_string();
        assert_eq!(shown(&wa, &mut sa), format!("[{}]", r.body));

        // A copy that isn't in the session finds it by the link, in any case of the id.
        wait_until("the link to reach b", || {
            req(&wb, &mut state(), "GET", &format!("/session/v1/platform/steam/session/{}", encoding::base64(b"steam:109775244200441988")), "").status == 200
        });
        let r = req(&wb, &mut sb, "GET", &lookup, "");
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(json(&r.body).get("session_id").as_str(), Some(id.as_str()));
        assert_eq!(json(&r.body).get("platform_session").to_string(), format!("[{}]", json(&req(&wa, &mut sa, "GET", &format!("/session/v1/session/{id}"), "").body).get("platform_session").as_arr()[0]));
        // The leader finds it too, without a search; another id finds none.
        assert_eq!(json(&req(&wa, &mut sa, "GET", &lookup, "").body).get("session_id").as_str(), Some(id.as_str()));
        assert_eq!(req(&wb, &mut sb, "GET", &format!("/session/v1/platform/Steam/session/{}", encoding::base64(b"STEAM:7")), "").status, 404);

        // Members see it in the session JSON; only the leader writes it.
        assert_eq!(req(&wb, &mut sb, "POST", &format!("/session/v1/session/{id}/player/me"), "{}").status, 200);
        wait_until("b to show the link", || shown(&wb, &mut state()).contains(&psid));
        assert_eq!(req(&wb, &mut sb, "DELETE", &link, "").status, 404);
        let r = req(&wb, &mut sb, "POST", &link, "");
        assert_eq!(code(&r).as_deref(), Some("not_owner"));

        // Unlinking: another psid is a 404, the right one a 204, then it is gone.
        let other = encoding::base64(b"STEAM:7");
        let r = req(&wa, &mut sa, "DELETE", &format!("/session/v1/platform/Steam/platform-session/{other}/session/{id}"), "");
        assert_eq!(code(&r).as_deref(), Some("platform_session_not_found"));
        let r = req(&wa, &mut sa, "DELETE", &link, "");
        assert_eq!((r.status, r.body.as_str()), (204, ""));
        assert_eq!(shown(&wa, &mut sa), "null");
        assert_eq!(req(&wa, &mut sa, "GET", &lookup, "").status, 404);
        assert_eq!(req(&wa, &mut sa, "DELETE", &link, "").status, 404);

        // Any other platform route is the unknown-route answer.
        let r = req(&wa, &mut sa, "GET", &format!("/session/v1/platform/Steam/platform-session/{psid}"), "");
        assert_eq!((r.status, code(&r).as_deref()), (404, Some("not_implemented")));
        let r = req(&wa, &mut sa, "PUT", &format!("/session/v1/platform/Steam/session/{psid}"), "");
        assert_eq!((r.status, code(&r).as_deref()), (404, Some("not_implemented")));
    }

    #[test]
    fn a_player_accepting_a_platform_invite_joins_the_linked_session() {
        use notify::{INSTANCE_UPDATED, PLAYER_ADDED, PLAYER_REMOVED};
        let port = peerparty_core::test_ports::claim(1);
        let game = format!("test:rallyhere:platjoin:{}", std::process::id());
        let (a, b) = (start(&game, port, "a"), start(&game, port, "b"));
        pump(&[&a, &b], "the copies to meet", || a.peers().iter().any(|(p, _)| *p == b.me()) && b.peers().iter().any(|(p, _)| *p == a.me()));
        let (_pa, _pb) = (Pumped::of(&a), Pumped::of(&b));
        let (wa, wb) = (world_of(&a, &[&b]), world_of(&b, &[&a]));
        let (mut sa, mut sb) = (state(), state());
        let (ta, tb) = (sign_in(&wa, &mut sa), sign_in(&wb, &mut sb));
        let mut ca = cursor_now();
        let r = authed(&wa, &mut sa, &ta, "POST", "/session/v1/session", r#"{"session_type":"example_match","client_version":"1.0.0","client_settings":{"platform":"Steam","input":"gamepad"}}"#);
        let id = json(&r.body).get("session_id").as_str().unwrap().to_string();
        let ipath = format!("/session/v1/session/{id}/instance");
        assert_eq!(authed(&wa, &mut sa, &ta, "POST", &ipath, r#"{}"#).status, 200);
        assert_eq!(authed(&wa, &mut sa, &ta, "PATCH", &ipath, r#"{"join_status":"joinable","join_params":{"public_conn_str":"0.0.0.0:7777"}}"#).status, 200);
        poll_for(&wa, &mut sa, &ta, &mut ca, INSTANCE_UPDATED);
        let psid = encoding::base64(b"STEAM:109775244200441988");
        assert_eq!(authed(&wa, &mut sa, &ta, "POST", &format!("/session/v1/platform/Steam/platform-session/{psid}/session/{id}"), "").status, 200);

        // Unknown and garbage ids.
        let join = |w: &World, st: &mut State, t: &str, p: &str| authed(w, st, t, "POST", &format!("/session/v1/platform/Steam/platform-session/{p}/player/me"), r#"{"client_version":"1.0.0","client_settings":{"platform":"Steam","input":"keyboardandmouse"},"team_id":0}"#);
        let r = join(&wb, &mut sb, &tb, &encoding::base64(b"STEAM:7"));
        assert_eq!((r.status, code(&r).as_deref()), (404, Some("session_not_found")));
        assert!(b.lobby(&id).is_none());
        let r = join(&wb, &mut sb, &tb, "!!!");
        assert_eq!((r.status, code(&r).as_deref()), (400, Some("invalid_request")));

        // B accepts the invite: it joins, A hears it and the answer is the session as B reads it.
        let r = join(&wb, &mut sb, &tb, &psid);
        assert_eq!(r.status, 200, "{}", r.body);
        let n = poll_for(&wa, &mut sa, &ta, &mut ca, PLAYER_ADDED);
        assert_eq!(n.get("rh_url").as_str(), Some(format!("session/v1/session/{id}").as_str()));
        let j = json(&r.body);
        assert_eq!(j.get("session_id").as_str(), Some(id.as_str()));
        assert_eq!(players(&j, 0).len(), 2);
        assert_eq!(j.get("instance").get("join_status").as_str(), Some("joinable"));
        wait_until("both players in both copies", || [a.lobby(&id), b.lobby(&id)].iter().all(|l| l.as_ref().is_some_and(|l| l.members.len() == 2 && l.members.iter().all(|m| !m.attrs.is_empty()))));
        let g = json(&authed(&wb, &mut sb, &tb, "GET", &format!("/session/v1/session/{id}"), "").body);
        assert_eq!(players(&g, 0).len(), 2);
        assert!(g.get("instance").get("join_params").get("public_conn_str").as_str().is_some());
        // Joining again is the join's own error.
        assert_eq!(join(&wb, &mut sb, &tb, &psid).status, 400);

        // B leaves through the platform session.
        let leave_path = format!("/session/v1/platform/Steam/platform-session/{psid}/player/me");
        let r = authed(&wb, &mut sb, &tb, "DELETE", &leave_path, "");
        assert_eq!((r.status, r.body.as_str()), (204, ""));
        poll_for(&wa, &mut sa, &ta, &mut ca, PLAYER_REMOVED);
        assert_eq!(authed(&wb, &mut sb, &tb, "DELETE", &leave_path, "").status, 404);
    }

    #[test]
    fn a_stranger_browses_a_session_with_the_health_its_leader_reports() {
        let port = peerparty_core::test_ports::claim(1);
        let game = format!("test:rallyhere:health:{}", std::process::id());
        let (a, b) = (start(&game, port, "a"), start(&game, port, "b"));
        pump(&[&a, &b], "the copies to meet", || a.peers().iter().any(|(p, _)| *p == b.me()) && b.peers().iter().any(|(p, _)| *p == a.me()));
        let (_pa, _pb) = (Pumped::of(&a), Pumped::of(&b));
        let (wa, wb) = (world_of(&a, &[&b]), world_of(&b, &[&a]));
        let (mut sa, mut sb) = (state(), state());
        let r = req(&wa, &mut sa, "POST", "/session/v1/session", r#"{"session_type":"example_match"}"#);
        let id = json(&r.body).get("session_id").as_str().unwrap().to_string();
        let browse = |w: &World, s: &mut State| json(&req(w, s, "GET", "/session/v1/browser?session_type=example_match&cursor=0&region_id=1", "").body).get("browser_sessions").as_arr().to_vec();
        req(&wa, &mut sa, "POST", &format!("/session/v1/session/{id}/browser"), r#"{"custom_data":{"leader_name":"x"}}"#);
        assert!(browse(&wb, &mut sb).is_empty(), "no instance yet: not listed");
        assert_eq!(req(&wa, &mut sa, "POST", &format!("/session/v1/session/{id}/instance"), "{}").status, 200);
        let secret = r#"{"join_params":{"public_conn_str":"unreal://EOS:SECRETCONN:GameNetDriver:1","custom_data":{"rh.SessionSecurityToken":"SECRETTOKEN"}}}"#;
        assert_eq!(req(&wa, &mut sa, "PATCH", &format!("/session/v1/session/{id}/instance"), secret).status, 200);
        let seen = browse(&wb, &mut sb);
        assert_eq!((seen.len(), seen[0].get("instance_health").as_str()), (1, Some("unknown")), "the instance's own state, until it reports");
        let h = req(&wa, &mut sa, "POST", &format!("/session/v1/session/{id}/instance/health"), r#"{"instance_health":"healthy"}"#);
        assert_eq!(h.status, 200, "{}", h.body);
        let raw = req(&wb, &mut sb, "GET", "/session/v1/browser?session_type=example_match", "").body;
        let seen = json(&raw).get("browser_sessions").as_arr().to_vec();
        assert_eq!((seen.len(), seen[0].get("instance_health").as_str(), seen[0].get("session_id").as_str()), (1, Some("healthy"), Some(id.as_str())));
        assert_eq!(seen[0].get("custom_data").get("leader_name").as_str(), Some("x"));
        assert!(!raw.contains("SECRET"), "nothing of the join parameters reaches a stranger: {raw}");
        // What a stranger's search gets holds the state and not the instance.
        let found = search_all(&b);
        let public = found.iter().find(|l| l.id == id).unwrap();
        assert!(public.attr(K_INSTANCE).is_none() && public.attr(K_INSTANCE_STATE).is_some());
        assert!(!public.attr(K_INSTANCE_STATE).unwrap().value.text().contains("SECRET"));
        // The instance goes: the session isn't listed any more.
        assert_eq!(req(&wa, &mut sa, "DELETE", &format!("/session/v1/session/{id}/instance"), "").status, 204);
        assert!(browse(&wb, &mut sb).is_empty());
        assert!(a.lobby(&id).unwrap().attr(K_INSTANCE_STATE).is_none());
    }

    fn search_all(lan: &Lan) -> Vec<Lobby> {
        search(lan, Query::new(NS), Instant::now() + Duration::from_secs(5))
    }

    #[test]
    fn the_published_instance_state_is_bounded_and_never_the_instance() {
        let mut s = session();
        s.instance = Some(json(&format!(r#"{{"instance_health":"{0}","join_status":"{0}","join_params":{{"public_conn_str":"unreal://SECRET"}},"host_player_uuid":"u"}}"#, "h".repeat(5000))));
        let l = lobby(&s, vec![]);
        let published = l.attr(K_INSTANCE_STATE).expect("published").value.text();
        assert!(l.attr(K_INSTANCE_STATE).unwrap().public && !published.contains("SECRET") && !published.contains("host_player"), "{published}");
        let (health, status) = instance_state(&l.attrs).unwrap();
        assert_eq!((health.len(), status.len()), (MAX_TEXT, MAX_TEXT));
        // Wrong types and oversize read as nothing.
        for v in [Value::Int(3), Value::Str("[1]".into()), Value::Str("x".repeat(MAX_ATTR + 1))] {
            assert_eq!(instance_state(&[attr(K_INSTANCE_STATE, v)]), None);
        }
    }
}
