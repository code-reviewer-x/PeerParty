//! The simple services (`API §4`): time, key-values, events, friends, presence, matches,
//! recently played, performance stats and developer files.
//!
//! A match's data is kept under the game's folder (`matches.json`, the last `MAX_MATCHES`),
//! the files a game uploads under `files/`. What the game sends is bounded here: sizes,
//! counts, and the fields that are kept.

use std::fs;

use super::users::{self, ANON, player_uuid};
use super::{Reply, State, World, etag_of, now_iso};
use crate::log;
use crate::util::json::Json;
use crate::util::local_store;

/// The matches kept (the least recently changed are dropped).
pub const MAX_MATCHES: usize = 50;
/// The most one match, with its players, may take once serialized.
const MAX_MATCH_BYTES: usize = 256 * 1024;
/// The most one PATCH body may take.
const MAX_PATCH_BYTES: usize = 64 * 1024;
const MAX_ENTRIES: usize = 64;
/// The most a developer file may take.
pub const MAX_FILE: usize = 1 << 20;
const MAX_FILE_NAME: usize = 128;

// ---- time, kv, events ----

pub fn time() -> Reply {
    Reply::ok(Json::str(now_iso()))
}

/// `GET /config/v2/kv`.
pub fn kv(st: &State, if_none_match: Option<&str>) -> Reply {
    let kvs = Json::Obj(st.kv.iter().map(|(k, v)| (k.clone(), Json::str(v))).collect());
    let body = Json::obj(vec![("kvs", kvs), ("kick_before_hint", Json::str("2020-01-01T00:00:00.000000Z"))]).to_string();
    Reply::cached(body, if_none_match)
}

/// `POST /events/v1/events`: accepted and dropped.
pub fn events(body: &Json) -> Reply {
    let n = body.get("event_list").as_arr().len();
    Reply::ok(Json::obj(vec![("posted_events", Json::int(n as i64)), ("errors", Json::Arr(Vec::new()))]))
}

// ---- friends ----

/// `GET /friends/v2/player/{uuid}/friend` and `.../block`: the LAN's players, and nobody blocked.
pub fn friends(world: &World, uuid: &str, blocked: bool, query: &[(String, String)]) -> Reply {
    if !uuid.eq_ignore_ascii_case(&player_uuid(world.me)) {
        return Reply::err(400, "error_wrong_user", "not the signed-in player", true);
    }
    let num = |k: &str, d: usize| query.iter().find(|(n, _)| n == k).and_then(|(_, v)| v.parse::<usize>().ok()).unwrap_or(d);
    let (page, limit) = (num("page", 0), num("limit", 10000).clamp(1, 10000));
    let list: Vec<Json> = if blocked {
        Vec::new()
    } else {
        let now = now_iso();
        world
            .peers
            .iter()
            .map(|p| {
                let u = player_uuid(p.id);
                Json::obj(vec![
                    ("friend_player_uuid", Json::str(&u)),
                    ("status", Json::str("mutual")),
                    ("notes", Json::str("")),
                    ("etag", Json::str(etag_of(&u))),
                    ("last_modified_on", Json::str(&now)),
                ])
            })
            .collect()
    };
    let total = list.len();
    let shown: Vec<Json> = list.into_iter().skip(page.saturating_mul(limit)).take(limit).collect();
    Reply::ok(Json::obj(vec![
        ("player_uuid", Json::str(uuid.to_ascii_lowercase())),
        (if blocked { "blocked" } else { "friends" }, Json::Arr(shown)),
        ("page", Json::obj(vec![("page", Json::int(page as i64)), ("limit", Json::int(limit as i64)), ("total", Json::int(total as i64))])),
    ]))
}

// ---- presence ----

/// What a player's presence says; ours is shared with the LAN (`State::publish`).
#[derive(Clone, Debug, PartialEq)]
pub struct Presence {
    pub status: String,
    pub message: String,
    pub do_not_disturb: bool,
    pub custom_data: Json,
    /// Who the player is on a platform, for their links.
    pub platform: String,
    pub portal_user_id: String,
}

impl Default for Presence {
    fn default() -> Self {
        Presence {
            status: "online".into(),
            message: String::new(),
            do_not_disturb: false,
            custom_data: Json::Obj(Vec::new()),
            platform: ANON.name.into(),
            portal_user_id: String::new(),
        }
    }
}

const MAX_PUBLISHED: usize = 4096;
const MAX_STATUS: usize = 64;
const MAX_MESSAGE: usize = 256;
const MAX_CUSTOM: usize = 2048;

impl Presence {
    /// The text this presence goes over the LAN as.
    pub fn encode(&self) -> String {
        Json::obj(vec![
            ("status", Json::str(&self.status)),
            ("message", Json::str(&self.message)),
            ("do_not_disturb", Json::Bool(self.do_not_disturb)),
            ("custom_data", self.custom_data.clone()),
            ("platform", Json::str(&self.platform)),
            ("portal_user_id", Json::str(&self.portal_user_id)),
        ])
        .to_string()
    }

    /// A presence another copy published: untrusted, bounded and rebuilt field by field.
    pub fn decode(text: &str) -> Option<Presence> {
        if text.len() > MAX_PUBLISHED {
            return None;
        }
        let j = Json::parse(text)?;
        let s = |k: &str, max: usize, d: &str| j.get(k).as_str().filter(|v| v.len() <= max).unwrap_or(d).to_string();
        let custom = j.get("custom_data");
        let d = Presence::default();
        Some(Presence {
            status: s("status", MAX_STATUS, &d.status),
            message: s("message", MAX_MESSAGE, ""),
            do_not_disturb: j.get("do_not_disturb").as_bool().unwrap_or(false),
            custom_data: if matches!(custom, Json::Obj(_)) && custom.to_string().len() <= MAX_CUSTOM { custom.clone() } else { d.custom_data },
            platform: users::platform_of(j.get("platform").as_str().unwrap_or_default()).name.to_string(),
            portal_user_id: s("portal_user_id", 64, ""),
        })
    }
}

/// `PATCH /presence/v1/player/me/presence`: merges the fields given and tells the LAN.
pub fn patch_presence(st: &mut State, body: &Json) -> Reply {
    if !matches!(body, Json::Obj(_)) {
        return Reply::err(400, "error_invalid_data", "a JSON object is expected", true);
    }
    let mut p = st.presence.clone();
    for (key, max, slot) in [("status", MAX_STATUS, &mut p.status), ("message", MAX_MESSAGE, &mut p.message)] {
        match body.get(key) {
            Json::Null => {}
            Json::Str(s) if s.len() <= max => *slot = s.clone(),
            _ => return Reply::err(400, "error_invalid_data", &format!("{key} is too long or not text"), true),
        }
    }
    match body.get("do_not_disturb") {
        Json::Null => {}
        Json::Bool(b) => p.do_not_disturb = *b,
        _ => return Reply::err(400, "error_invalid_data", "do_not_disturb is not a boolean", true),
    }
    match body.get("custom_data") {
        Json::Null => {}
        c @ Json::Obj(_) if c.to_string().len() <= MAX_CUSTOM => p.custom_data = c.clone(),
        _ => return Reply::err(400, "error_invalid_data", "custom_data is too big or not an object", true),
    }
    st.presence = p;
    st.publish();
    Reply::empty(200)
}

/// `GET /presence/v1/player/uuid/{uuid}/presence`: ours, or a LAN player's.
pub fn get_presence(world: &World, st: &State, uuid: &str, if_none_match: Option<&str>) -> Reply {
    let Some(peer) = users::peer_of(world, uuid) else {
        return Reply::err(404, "player_not_found", "no such player", true);
    };
    let p = world.presence_of(st, peer);
    let body = Json::obj(vec![
        ("status", Json::str(&p.status)),
        ("message", Json::str(&p.message)),
        ("platform", Json::str(&p.platform)),
        ("display_name", Json::str(world.name_of(peer))),
        ("custom_data", p.custom_data.clone()),
        ("player_uuid", Json::str(player_uuid(peer))),
        ("do_not_disturb", Json::Bool(p.do_not_disturb)),
    ])
    .to_string();
    Reply::cached(body, if_none_match)
}

// ---- matches ----

const MATCH_FIELDS: [&str; 11] = [
    "type", "state", "start_timestamp", "end_timestamp", "duration_seconds", "custom_data", "correlation_id", "sessions", "instances",
    "allocations", "segments",
];
const MATCH_LISTS: [&str; 4] = ["sessions", "instances", "allocations", "segments"];
const PLAYER_FIELDS: [&str; 10] = [
    "team_id", "party_session_id", "placement", "joined_match_timestamp", "left_match_timestamp", "duration_seconds", "starting_rank",
    "finishing_rank", "custom_data", "player_uuid",
];

fn set(o: &mut Vec<(String, Json)>, key: &str, v: Json) {
    match o.iter_mut().find(|(k, _)| k == key) {
        Some(slot) => slot.1 = v,
        None => o.push((key.to_string(), v)),
    }
}

fn field<'a>(o: &'a [(String, Json)], key: &str) -> Option<&'a Json> {
    o.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

/// An id or uuid from a path: short, letters, digits and `-`.
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn bad(what: &str) -> Reply {
    Reply::err(400, "error_invalid_data", what, true)
}

fn same_id(o: &[(String, Json)], key: &str, id: &str) -> bool {
    field(o, key).and_then(Json::as_str).is_some_and(|v| v.eq_ignore_ascii_case(id))
}

fn find(st: &State, id: &str) -> Option<usize> {
    st.matches.iter().position(|m| same_id(m.as_obj(), "match_id", id))
}

/// Puts the match at `i` last (the most recently changed) and keeps only the newest ones.
fn keep(st: &mut State, i: usize) -> usize {
    let m = st.matches.remove(i);
    st.matches.push(m);
    while st.matches.len() > MAX_MATCHES {
        st.matches.remove(0);
    }
    st.matches.len() - 1
}

/// Merges a player's fields given in `body` into `player` (an object).
fn merge_player(player: &mut Vec<(String, Json)>, body: &Json, now: &str) {
    for f in PLAYER_FIELDS {
        if !body.get(f).is_null() {
            set(player, f, body.get(f).clone());
        }
    }
    set(player, "last_modified_timestamp", Json::str(now));
}

fn player_slot<'a>(players: &'a mut Vec<Json>, uuid: &str, now: &str) -> &'a mut Vec<(String, Json)> {
    let i = players.iter().position(|p| same_id(p.as_obj(), "player_uuid", uuid)).unwrap_or_else(|| {
        players.push(Json::obj(vec![("player_uuid", Json::str(uuid.to_ascii_lowercase())), ("created_timestamp", Json::str(now))]));
        players.len() - 1
    });
    match &mut players[i] {
        Json::Obj(o) => o,
        _ => unreachable!("a player is built as an object"),
    }
}

/// Checks one array of a PATCH body: an array of at most `MAX_ENTRIES` objects.
fn entries<'a>(body: &'a Json, key: &str) -> Result<&'a [Json], Reply> {
    match body.get(key) {
        Json::Null => Ok(&[]),
        Json::Arr(a) if a.len() <= MAX_ENTRIES && a.iter().all(|e| matches!(e, Json::Obj(_))) => Ok(a),
        _ => Err(bad(&format!("{key} must be a short list of objects"))),
    }
}

/// `PATCH /match/v1/match/{id}`: creates the match or merges into it.
pub fn patch_match(st: &mut State, id: &str, body: &Json, size: usize) -> Reply {
    if !valid_id(id) {
        return bad("not a match id");
    }
    if !matches!(body, Json::Obj(_)) || size > MAX_PATCH_BYTES {
        return bad("a small JSON object is expected");
    }
    if !body.get("state").is_null() && !matches!(body.get("state").as_str(), Some("pending" | "closed")) {
        return bad("state is pending or closed");
    }
    for l in MATCH_LISTS {
        if let Err(r) = entries(body, l) {
            return r;
        }
    }
    let players = match entries(body, "players") {
        Ok(p) => p,
        Err(r) => return r,
    };
    if players.iter().any(|p| !p.get("player_uuid").as_str().is_some_and(valid_id)) {
        return bad("a player needs a player_uuid");
    }
    let now = now_iso();
    let (mut m, existing) = match find(st, id) {
        Some(i) => (st.matches[i].as_obj().to_vec(), Some(i)),
        None => (vec![("match_id".to_string(), Json::str(id)), ("created_timestamp".to_string(), Json::str(&now))], None),
    };
    for f in MATCH_FIELDS {
        if !body.get(f).is_null() {
            set(&mut m, f, body.get(f).clone());
        }
    }
    if !players.is_empty() {
        let mut all: Vec<Json> = field(&m, "players").map(|p| p.as_arr().to_vec()).unwrap_or_default();
        for p in players {
            let uuid = p.get("player_uuid").as_str().unwrap_or_default();
            if all.len() >= MAX_ENTRIES && !all.iter().any(|x| same_id(x.as_obj(), "player_uuid", uuid)) {
                return bad("too many players");
            }
            merge_player(player_slot(&mut all, uuid, &now), p, &now);
        }
        set(&mut m, "players", Json::Arr(all));
    }
    set(&mut m, "last_modified_timestamp", Json::str(&now));
    let m = Json::Obj(m);
    if m.to_string().len() > MAX_MATCH_BYTES {
        return bad("the match is too big");
    }
    let reply = Reply::ok(m.clone());
    match existing {
        Some(i) => {
            st.matches[i] = m;
            keep(st, i);
        }
        None => {
            st.matches.push(m);
            let last = st.matches.len() - 1;
            keep(st, last);
        }
    }
    st.save_matches();
    reply
}

/// `PATCH /match/v1/player/{uuid}/match/{id}`: a player's part of a match (404 when the
/// match is unknown).
pub fn patch_player(st: &mut State, uuid: &str, id: &str, body: &Json, size: usize) -> Reply {
    if !valid_id(id) || !valid_id(uuid) {
        return bad("not an id");
    }
    if !matches!(body, Json::Obj(_)) || size > MAX_PATCH_BYTES {
        return bad("a small JSON object is expected");
    }
    let Some(i) = find(st, id) else {
        return Reply::err(404, "match_not_found", "no such match", true);
    };
    let now = now_iso();
    let mut m = st.matches[i].as_obj().to_vec();
    let mut all: Vec<Json> = field(&m, "players").map(|p| p.as_arr().to_vec()).unwrap_or_default();
    if all.len() >= MAX_ENTRIES && !all.iter().any(|x| same_id(x.as_obj(), "player_uuid", uuid)) {
        return bad("too many players");
    }
    let mut player = {
        let slot = player_slot(&mut all, uuid, &now);
        merge_player(slot, body, &now);
        // The path names the player, whatever the body says.
        set(slot, "player_uuid", Json::str(uuid.to_ascii_lowercase()));
        slot.clone()
    };
    set(&mut m, "players", Json::Arr(all));
    set(&mut m, "last_modified_timestamp", Json::str(&now));
    if Json::Obj(m.clone()).to_string().len() > MAX_MATCH_BYTES {
        return bad("the match is too big");
    }
    let mut without = m.clone();
    without.retain(|(k, _)| k != "players");
    player.push(("match".to_string(), Json::Obj(without)));
    st.matches[i] = Json::Obj(m);
    keep(st, i);
    st.save_matches();
    Reply::ok(Json::Obj(player))
}

/// `GET /match/v1/player/{uuid}/recently-played`: the players met in the kept matches, the
/// most recent match first.
pub fn recently_played(st: &State, uuid: &str) -> Reply {
    let mut met: Vec<Json> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for m in st.matches.iter().rev() {
        let players = field(m.as_obj(), "players").map(Json::as_arr).unwrap_or_default();
        if !players.iter().any(|p| same_id(p.as_obj(), "player_uuid", uuid)) {
            continue;
        }
        for p in players {
            let Some(u) = field(p.as_obj(), "player_uuid").and_then(Json::as_str) else { continue };
            if u.eq_ignore_ascii_case(uuid) || seen.iter().any(|s| s.eq_ignore_ascii_case(u)) || met.len() >= 200 {
                continue;
            }
            seen.push(u.to_string());
            met.push(Json::obj(vec![
                ("player_uuid", Json::str(u)),
                ("match_id", field(m.as_obj(), "match_id").cloned().unwrap_or(Json::Null)),
                ("last_modified_timestamp", field(m.as_obj(), "last_modified_timestamp").cloned().unwrap_or(Json::Null)),
            ]));
        }
    }
    Reply::ok(Json::obj(vec![("players", Json::Arr(met))]))
}

/// `POST /match/v1/pex/{host|client}`: performance stats, dropped.
pub fn pex(which: &str) -> Reply {
    if which == "host" { Reply::err(403, "insufficient_permissions", "no permission", true) } else { Reply::empty(204) }
}

// ---- developer files ----

/// `PUT /file/v1/developer-file/match/{match_id}/{file_name}`: kept under the game's folder.
pub fn put_file(st: &State, match_id: &str, name: &str, body: &[u8]) -> Reply {
    if !valid_id(match_id) {
        return bad("not a match id");
    }
    let Some(file) = local_store::file_name(name).filter(|f| f.len() <= MAX_FILE_NAME) else {
        return bad("not a file name");
    };
    if body.len() > MAX_FILE {
        return Reply::err(413, "error_file_too_large", "the file is over 1 MiB", true);
    }
    if let Some(dir) = &st.dir {
        let folder = dir.join("files").join(local_store::component(match_id));
        if let Err(e) = fs::create_dir_all(&folder).and_then(|_| fs::write(folder.join(&file), body)) {
            log!("rallyhere: a developer file could not be kept: {e}");
            return Reply::err(500, "error_storage", "the file could not be kept", true);
        }
    }
    Reply::ok(Json::Obj(Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rallyhere::tests_support::{call, call_with, test_world};
    use peerparty_core::PeerId;

    const ME: PeerId = PeerId([1; 16]);
    const OTHER: PeerId = PeerId([2; 16]);

    fn json(s: &str) -> Json {
        Json::parse(s).unwrap()
    }

    #[test]
    fn time_kv_and_events() {
        let world = test_world(ME, "Me", &[]);
        let mut st = State::new(None);
        let (s, b) = call(&world, &mut st, "GET", "/config/v1/time/utc", None, "");
        assert_eq!(s, 200);
        assert!(json(&b).as_str().is_some_and(|t| t.ends_with('Z') && t.contains('T')));
        // kv is empty without config, then answers the config's; ETag and 304.
        let (s, b) = call(&world, &mut st, "GET", "/config/v2/kv", None, "");
        assert_eq!(s, 200);
        assert!(json(&b).get("kvs").as_obj().is_empty());
        assert!(json(&b).get("kick_before_hint").as_str().is_some());
        st.kv = vec![("k".into(), "v".into())];
        let r = call_with(&world, &mut st, "GET", "/config/v2/kv", &[], "");
        assert_eq!(json(&r.body).get("kvs").get("k").as_str(), Some("v"));
        let etag = r.etag.clone().unwrap();
        assert!(etag.starts_with("W/\"") && etag.ends_with('"'));
        let again = call_with(&world, &mut st, "GET", "/config/v2/kv", &[("If-None-Match", etag.as_str())], "");
        assert_eq!((again.status, again.body.as_str(), again.etag.as_deref()), (304, "", Some(etag.as_str())));
        st.kv = vec![("k".into(), "other".into())];
        let changed = call_with(&world, &mut st, "GET", "/config/v2/kv", &[("If-None-Match", etag.as_str())], "");
        assert_eq!(changed.status, 200, "a changed kv is sent again");
        let (s, b) = call(&world, &mut st, "POST", "/events/v1/events", None, r#"{"event_list":[{"event_name":"a"},{"event_name":"b"}]}"#);
        assert_eq!((s, json(&b).get("posted_events").as_i64(), json(&b).get("errors").as_arr().len()), (200, Some(2), 0));
        let (s, _) = call(&world, &mut st, "GET", "/events/v1/events", None, "");
        assert_eq!(s, 200);
    }

    #[test]
    fn friends_are_the_lan_players() {
        let world = test_world(ME, "Me", &[(OTHER, "Other")]);
        let mut st = State::new(None);
        let me = player_uuid(ME);
        let (s, b) = call(&world, &mut st, "GET", &format!("/friends/v2/player/{me}/friend?page=0&limit=10000"), None, "");
        let j = json(&b);
        assert_eq!(s, 200);
        assert_eq!(j.get("friends").as_arr().len(), 1);
        let f = &j.get("friends").as_arr()[0];
        assert_eq!((f.get("friend_player_uuid").as_str(), f.get("status").as_str()), (Some(player_uuid(OTHER).as_str()), Some("mutual")));
        assert_eq!(j.get("page").get("total").as_i64(), Some(1));
        let (_, b) = call(&world, &mut st, "GET", &format!("/friends/v2/player/{}/block", me.to_ascii_uppercase()), None, "");
        assert!(json(&b).get("blocked").as_arr().is_empty());
        assert!(json(&b).get("friends").is_null());
        let (s, b) = call(&world, &mut st, "GET", &format!("/friends/v2/player/{}/friend", player_uuid(OTHER)), None, "");
        assert_eq!((s, json(&b).get("error_code").as_str()), (400, Some("error_wrong_user")));
        // Paging past the list gives an empty page and the same total.
        let (_, b) = call(&world, &mut st, "GET", &format!("/friends/v2/player/{me}/friend?page=3&limit=10"), None, "");
        assert_eq!((json(&b).get("friends").as_arr().len(), json(&b).get("page").get("total").as_i64()), (0, Some(1)));
    }

    #[test]
    fn presence_patch_then_get_and_peers_see_it() {
        let world = test_world(ME, "Me", &[(OTHER, "Other")]);
        let mut st = State::new(None);
        let me = player_uuid(ME);
        let get = |st: &mut State, u: &str| call(&world, st, "GET", &format!("/presence/v1/player/uuid/{u}/presence"), None, "");
        let (s, b) = get(&mut st, &me);
        assert_eq!((s, json(&b).get("status").as_str(), json(&b).get("display_name").as_str()), (200, Some("online"), Some("Me")));
        let (s, b) = call(&world, &mut st, "PATCH", "/presence/v1/player/me/presence", None, r#"{"status":"busy","message":"in a match","custom_data":{"a":"b"},"do_not_disturb":true}"#);
        assert_eq!((s, b.as_str()), (200, ""));
        let (_, b) = get(&mut st, &me);
        let j = json(&b);
        assert_eq!((j.get("status").as_str(), j.get("message").as_str(), j.get("do_not_disturb").as_bool()), (Some("busy"), Some("in a match"), Some(true)));
        assert_eq!(j.get("custom_data").get("a").as_str(), Some("b"));
        // A second patch merges: only the field it names changes.
        call(&world, &mut st, "PATCH", "/presence/v1/player/me/presence", None, r#"{"message":"lobby"}"#);
        let j = json(&get(&mut st, &me).1);
        assert_eq!((j.get("status").as_str(), j.get("message").as_str()), (Some("busy"), Some("lobby")));
        // What a peer published is what its GET says; one that published nothing is online.
        let mut peer = Presence { status: "away".into(), message: "brb".into(), ..Presence::default() };
        peer.platform = "Steam".into();
        let world2 = test_world(ME, "Me", &[(OTHER, "Other")]).with_published(OTHER, &peer.encode());
        let j = json(&call(&world2, &mut st, "GET", &format!("/presence/v1/player/uuid/{}/presence", player_uuid(OTHER)), None, "").1);
        assert_eq!((j.get("status").as_str(), j.get("message").as_str(), j.get("platform").as_str()), (Some("away"), Some("brb"), Some("Steam")));
        assert_eq!(j.get("display_name").as_str(), Some("Other"));
        let j = json(&get(&mut st, &player_uuid(OTHER)).1);
        assert_eq!(j.get("status").as_str(), Some("online"));
        // ETag and 304.
        let path = format!("/presence/v1/player/uuid/{me}/presence");
        let etag = call_with(&world, &mut st, "GET", &path, &[], "").etag.unwrap();
        assert_eq!(call_with(&world, &mut st, "GET", &path, &[("If-None-Match", etag.as_str())], "").status, 304);
        // Unknown player, and bad patches.
        let (s, b) = get(&mut st, "00000000-0000-4000-8000-000000000000");
        assert_eq!((s, json(&b).get("error_code").as_str()), (404, Some("player_not_found")));
        for bad in ["[1]", r#"{"status":5}"#, r#"{"do_not_disturb":"yes"}"#, r#"{"custom_data":[1]}"#] {
            assert_eq!(call(&world, &mut st, "PATCH", "/presence/v1/player/me/presence", None, bad).0, 400, "{bad}");
        }
        let long = format!(r#"{{"message":"{}"}}"#, "x".repeat(300));
        assert_eq!(call(&world, &mut st, "PATCH", "/presence/v1/player/me/presence", None, &long).0, 400);
    }

    #[test]
    fn a_stranger_s_published_presence_is_bounded() {
        assert_eq!(Presence::decode(&"x".repeat(MAX_PUBLISHED + 1)), None);
        assert_eq!(Presence::decode("not json"), None);
        let p = Presence::decode(&format!(r#"{{"status":"{}","message":5,"custom_data":[1],"platform":"Nope"}}"#, "s".repeat(100))).unwrap();
        assert_eq!(p, Presence::default(), "every wrong field falls back");
        let own = Presence { status: "a".into(), message: "b".into(), do_not_disturb: true, custom_data: json(r#"{"k":1}"#), platform: "Epic".into(), portal_user_id: "42".into() };
        assert_eq!(Presence::decode(&own.encode()), Some(own));
    }

    #[test]
    fn match_patch_creates_then_merges() {
        let world = test_world(ME, "Me", &[]);
        let mut st = State::new(None);
        let path = "/match/v1/match/AAAA1111-0000-4000-8000-000000000001";
        let (s, b) = call(&world, &mut st, "PATCH", path, None, r#"{"type":"example","state":"pending","custom_data":{"a":1},"sessions":[{"session_id":"s1"}],"unknown":1}"#);
        let j = json(&b);
        assert_eq!(s, 200);
        assert_eq!(j.get("match_id").as_str(), Some("AAAA1111-0000-4000-8000-000000000001"));
        assert_eq!((j.get("type").as_str(), j.get("state").as_str()), (Some("example"), Some("pending")));
        assert!(j.get("created_timestamp").as_str().is_some() && j.get("last_modified_timestamp").as_str().is_some());
        assert!(j.get("unknown").is_null(), "only the known fields are kept");
        let created = j.get("created_timestamp").as_str().unwrap().to_string();
        // Merge, by a lower case id: the match is the same one.
        let (_, b) = call(&world, &mut st, "PATCH", &path.to_ascii_lowercase(), None, r#"{"state":"closed","players":[{"player_uuid":"p1","team_id":1}]}"#);
        let j = json(&b);
        assert_eq!((j.get("type").as_str(), j.get("state").as_str()), (Some("example"), Some("closed")), "merged");
        assert_eq!(j.get("created_timestamp").as_str(), Some(created.as_str()));
        assert_eq!(j.get("players").as_arr().len(), 1);
        assert_eq!(st.matches.len(), 1);
        for (body, why) in [(r#"{"state":"weird"}"#, "state"), (r#"{"sessions":5}"#, "list"), (r#"{"players":[{"team_id":1}]}"#, "player without uuid"), ("[]", "not an object")] {
            assert_eq!(call(&world, &mut st, "PATCH", path, None, body).0, 400, "{why}");
        }
        assert_eq!(call(&world, &mut st, "PATCH", "/match/v1/match/a%20b", None, "{}").0, 400, "bad id");
    }

    #[test]
    fn player_match_patch_merges_and_an_unknown_match_is_404() {
        let world = test_world(ME, "Me", &[]);
        let mut st = State::new(None);
        let (s, b) = call(&world, &mut st, "PATCH", "/match/v1/player/p1/match/m1", None, r#"{"team_id":1}"#);
        assert_eq!((s, json(&b).get("error_code").as_str()), (404, Some("match_not_found")));
        call(&world, &mut st, "PATCH", "/match/v1/match/m1", None, r#"{"type":"t","players":[{"player_uuid":"p2"}]}"#);
        let (s, b) = call(&world, &mut st, "PATCH", "/match/v1/player/P1/match/M1", None, r#"{"team_id":1,"player_uuid":"evil","placement":2}"#);
        let j = json(&b);
        assert_eq!(s, 200);
        assert_eq!((j.get("player_uuid").as_str(), j.get("team_id").as_i64(), j.get("placement").as_i64()), (Some("p1"), Some(1), Some(2)));
        assert!(j.get("created_timestamp").as_str().is_some() && j.get("last_modified_timestamp").as_str().is_some());
        assert_eq!(j.get("match").get("type").as_str(), Some("t"));
        assert!(j.get("match").get("players").is_null(), "the match is without its players");
        let (_, b) = call(&world, &mut st, "PATCH", "/match/v1/player/p1/match/m1", None, r#"{"placement":3}"#);
        let j = json(&b);
        assert_eq!((j.get("team_id").as_i64(), j.get("placement").as_i64()), (Some(1), Some(3)), "merged");
        assert_eq!(st.matches[0].get("players").as_arr().len(), 2);
    }

    #[test]
    fn only_the_last_matches_are_kept() {
        let world = test_world(ME, "Me", &[]);
        let mut st = State::new(None);
        for i in 0..(MAX_MATCHES + 5) {
            call(&world, &mut st, "PATCH", &format!("/match/v1/match/m{i}"), None, "{}");
        }
        assert_eq!(st.matches.len(), MAX_MATCHES);
        assert_eq!(find(&st, "m0"), None, "the oldest are dropped");
        assert!(find(&st, &format!("m{}", MAX_MATCHES + 4)).is_some());
        // Touching a match makes it the newest.
        call(&world, &mut st, "PATCH", "/match/v1/match/m5", None, "{}");
        call(&world, &mut st, "PATCH", "/match/v1/match/new", None, "{}");
        assert!(find(&st, "m5").is_some() && find(&st, "m6").is_none());
    }

    #[test]
    fn matches_are_kept_across_runs() {
        let dir = crate::rallyhere::tests_support::temp_dir("matches");
        let world = test_world(ME, "Me", &[]);
        let mut st = State::new(Some(dir.clone()));
        call(&world, &mut st, "PATCH", "/match/v1/match/m1", None, r#"{"type":"kept"}"#);
        let again = State::new(Some(dir.clone()));
        assert_eq!(again.matches.len(), 1);
        assert_eq!(again.matches[0].get("type").as_str(), Some("kept"));
        // A damaged file is ignored.
        fs::write(dir.join("matches.json"), "{ not json").unwrap();
        assert!(State::new(Some(dir.clone())).matches.is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn recently_played_lists_the_players_met() {
        let world = test_world(ME, "Me", &[]);
        let mut st = State::new(None);
        call(&world, &mut st, "PATCH", "/match/v1/match/m1", None, r#"{"players":[{"player_uuid":"a"},{"player_uuid":"b"}]}"#);
        call(&world, &mut st, "PATCH", "/match/v1/match/m2", None, r#"{"players":[{"player_uuid":"a"},{"player_uuid":"c"},{"player_uuid":"b"}]}"#);
        call(&world, &mut st, "PATCH", "/match/v1/match/m3", None, r#"{"players":[{"player_uuid":"x"},{"player_uuid":"y"}]}"#);
        let (s, b) = call(&world, &mut st, "GET", "/match/v1/player/A/recently-played", None, "");
        assert_eq!(s, 200);
        let j = json(&b);
        let ids: Vec<String> = j.get("players").as_arr().iter().map(|p| p.get("player_uuid").as_str().unwrap().to_string()).collect();
        assert_eq!(ids, ["c", "b"], "the newest match first, each once, not the player");
        let (_, b) = call(&world, &mut st, "GET", "/match/v1/player/nobody/recently-played", None, "");
        assert!(json(&b).get("players").as_arr().is_empty());
    }

    #[test]
    fn pex_host_is_refused_and_client_is_dropped() {
        let world = test_world(ME, "Me", &[]);
        let mut st = State::new(None);
        let (s, b) = call(&world, &mut st, "POST", "/match/v1/pex/host", None, "{}");
        assert_eq!((s, json(&b).get("error_code").as_str()), (403, Some("insufficient_permissions")));
        assert_eq!(call(&world, &mut st, "POST", "/match/v1/pex/client", None, "{}"), (204, String::new()));
    }

    #[test]
    fn developer_files_are_kept_under_a_sanitised_name_and_capped() {
        let dir = crate::rallyhere::tests_support::temp_dir("files");
        let world = test_world(ME, "Me", &[]);
        let mut st = State::new(Some(dir.clone()));
        let (s, b) = call(&world, &mut st, "PUT", "/file/v1/developer-file/match/m1/log.json", None, r#"{"a":1}"#);
        assert_eq!((s, b.as_str()), (200, "{}"));
        assert_eq!(fs::read_to_string(dir.join("files").join("m1").join("log.json")).unwrap(), r#"{"a":1}"#);
        // Separators in the name never leave the folder.
        let (s, _) = call(&world, &mut st, "PUT", "/file/v1/developer-file/match/m1/..%2F..%2Fescape.json", None, "{}");
        assert_eq!(s, 200);
        assert!(!dir.join("escape.json").exists() && !dir.join("files").join("escape.json").exists());
        assert!(dir.join("files").join("m1").join(".._.._escape.json").exists());
        assert_eq!(call(&world, &mut st, "PUT", "/file/v1/developer-file/match/m1/..", None, "{}").0, 400);
        assert_eq!(call(&world, &mut st, "PUT", "/file/v1/developer-file/match/..%2Fx/f.json", None, "{}").0, 400, "match id");
        let long = "n".repeat(MAX_FILE_NAME + 1);
        assert_eq!(call(&world, &mut st, "PUT", &format!("/file/v1/developer-file/match/m1/{long}"), None, "{}").0, 400);
        // The cap: exactly 1 MiB passes, one byte more does not.
        let big = "x".repeat(MAX_FILE);
        assert_eq!(call(&world, &mut st, "PUT", "/file/v1/developer-file/match/m1/big.json", None, &big).0, 200);
        let (s, b) = call(&world, &mut st, "PUT", "/file/v1/developer-file/match/m1/big2.json", None, &format!("{big}x"));
        assert_eq!((s, json(&b).get("error_code").as_str()), (413, Some("error_file_too_large")));
        assert!(!dir.join("files").join("m1").join("big2.json").exists());
        let _ = fs::remove_dir_all(dir);
    }
}
