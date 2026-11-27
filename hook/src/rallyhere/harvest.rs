//! Official mode's harvest. When the RallyHere layer runs in `official` mode (the game talks
//! to the real service), the title data the service answers is kept, so that a later LAN or
//! offline run has it. curl/mod.rs sees the game's calls to the title's hosts: `watches`
//! says which ones to keep the answer of, and each finished one comes to `observed`.
//!
//! Only title data, each answer reduced to an allowed list of fields (an unknown field is
//! dropped), one file per resource in `<rallyhere folder>\harvested\`, each with the shape
//! of the matching config.json key so that config.rs's validators read both:
//!
//! - `template.json`: the templates of `GET /session/v1/template` (config.json `templates`).
//! - `kv.json`: the key-values of `GET /config/v2/kv` (config.json `kv`).
//! - `regions.json`: the regions of `GET /session/v1/regions`, first page, as a list.
//! - `instance.json`: the instance's shape (config.json `instance`), from the instance
//!   routes and a session's `instance`: its keys, every value blanked to its type's empty
//!   value (ids, connection strings and custom data are the session's, and a startup value
//!   the host sent can't be told from a title default), merged with the keys seen before.
//!
//! Sign-in, tokens, inventory, friends, presence, ids and addresses are never kept: the
//! answers of other routes aren't even held (`watches`). curl's status code isn't seen,
//! so an answer is kept only when it has its resource's shape: an error envelope, or a
//! 304's empty body, never replaces a file. The service is not trusted: an answer is
//! bounded (`MAX_BODY`), counts and strings by config.rs's bounds, and a file is validated
//! before it is written and when it is read, written atomically (a temporary file, then a
//! rename) and not rewritten when unchanged.
//!
//! The stand-in reads title data per resource from config.json first, then from these
//! files (`title_data`).

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use super::config::{self, Config, InstanceDefaults};
use crate::log;
use crate::util::json::Json;

/// The largest answer kept, and the largest harvested file.
pub const MAX_BODY: usize = config::MAX_FILE as usize;

/// The harvested folder's name inside the game's RallyHere folder.
const FOLDER: &str = "harvested";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resource {
    Templates,
    Kv,
    Regions,
    Instance,
}

impl Resource {
    pub fn file(self) -> &'static str {
        match self {
            Resource::Templates => "template.json",
            Resource::Kv => "kv.json",
            Resource::Regions => "regions.json",
            Resource::Instance => "instance.json",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Resource::Templates => "templates",
            Resource::Kv => "kv",
            Resource::Regions => "regions",
            Resource::Instance => "instance",
        }
    }
}

/// The routes whose answers hold title data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Templates,
    Kv,
    Regions,
    /// `.../session/{id}/instance`: the answer is the instance.
    Instance,
    /// A session's create, read, change or join: the answer's `instance`.
    Session,
}

impl Route {
    fn resource(self) -> Resource {
        match self {
            Route::Templates => Resource::Templates,
            Route::Kv => Resource::Kv,
            Route::Regions => Resource::Regions,
            Route::Instance | Route::Session => Resource::Instance,
        }
    }

    fn takes(self, method: &str) -> bool {
        match self {
            Route::Templates | Route::Kv | Route::Regions => method == "GET",
            Route::Instance | Route::Session => matches!(method, "GET" | "POST" | "PATCH" | "PUT"),
        }
    }
}

/// The route of a path (with its query), from the path alone: curl may learn the method
/// after the URL.
fn route(path: &str) -> Option<Route> {
    let (bare, query) = path.split_once('?').unwrap_or((path, ""));
    let segs: Vec<&str> = bare.split('/').filter(|s| !s.is_empty()).collect();
    match segs.as_slice() {
        ["session", "v1", "template"] => Some(Route::Templates),
        ["config", "v2", "kv"] => Some(Route::Kv),
        // A later page alone would replace the whole list.
        ["session", "v1", "regions"] if first_page(query) => Some(Route::Regions),
        ["session", "v1", "session", _, "instance"] => Some(Route::Instance),
        ["session", "v1", "session"] | ["session", "v1", "session", _] | ["session", "v1", "session", _, "player", "me"] => Some(Route::Session),
        _ => None,
    }
}

fn first_page(query: &str) -> bool {
    query.split('&').filter_map(|p| p.split_once('=')).all(|(k, v)| k != "cursor" || v.is_empty() || v == "0")
}

#[cfg(test)]
thread_local! {
    /// For a test on this thread: the one host watched, in official mode, and the folder
    /// harvested into.
    pub(crate) static TEST: std::cell::RefCell<Option<(String, PathBuf)>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn test_setup() -> Option<(String, PathBuf)> {
    TEST.with(|t| t.borrow().clone())
}

/// Whether this run harvests: the title's hosts are known and the layer's mode is
/// `official` (its `auto` has no check, so it is LAN). Cheap, as curl asks it for every
/// body option it is given.
pub fn active() -> bool {
    #[cfg(test)]
    if test_setup().is_some() {
        return true;
    }
    crate::config::modes::mode("rallyhere") == crate::config::modes::Mode::Official && super::has_hosts()
}

/// Whether the answer of a call to `host`'s `path` is held for the harvest.
pub fn watches(host: &str, path: &str) -> bool {
    #[cfg(test)]
    if let Some((h, _)) = test_setup() {
        return h == host && route(path).is_some();
    }
    active() && super::is_host(host) && route(path).is_some()
}

/// The folder harvested into.
fn folder() -> Option<PathBuf> {
    #[cfg(test)]
    if let Some((_, dir)) = test_setup() {
        return Some(dir);
    }
    Some(config::folder()?.join(FOLDER))
}

fn official() -> bool {
    #[cfg(test)]
    if test_setup().is_some() {
        return true;
    }
    crate::config::modes::official("rallyhere")
}

/// A finished call to one of the title's hosts that `watches` held the answer of.
pub fn observed(method: &str, path: &str, answer: &[u8]) {
    observe(official(), folder().as_deref(), method, path, answer);
}

/// `observed`, with the mode and the folder given.
fn observe(official: bool, dir: Option<&Path>, method: &str, path: &str, answer: &[u8]) {
    let Some(dir) = dir.filter(|_| official) else { return };
    match filter(method, path, answer) {
        Ok(None) => {}
        Ok(Some((r, v))) => match keep(dir, r, v) {
            Ok(true) => log!("rallyhere: harvested the service's {} into {}\\{}", r.name(), FOLDER, r.file()),
            Ok(false) => {}
            Err(e) => crate::log::throttled(&format!("rallyhere harvest write {}", r.name()), 1, |_| log!("rallyhere: harvested {} not written: {e}", r.name())),
        },
        Err((r, why)) => crate::log::throttled(&format!("rallyhere harvest drop {}", r.name()), 2, |n| {
            log!("rallyhere: a {} answer was not harvested: {why} n={n}", r.name());
        }),
    }
}

/// What an answer holds of its resource, reduced and validated: None when the call is no
/// harvested route or method or has no body (a 304), Err (why) when its body doesn't have
/// the resource's shape (an error envelope) or breaks a bound.
pub fn filter(method: &str, path: &str, body: &[u8]) -> Result<Option<(Resource, Json)>, (Resource, String)> {
    let Some(route) = route(path).filter(|r| r.takes(method)) else { return Ok(None) };
    let r = route.resource();
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    let fail = |why: String| (r, why);
    if body.len() > MAX_BODY {
        return Err(fail(format!("larger than {} KiB", MAX_BODY / 1024)));
    }
    let text = std::str::from_utf8(body).map_err(|_| fail("not UTF-8".into()))?;
    let root = Json::parse(text.trim_start_matches('\u{feff}')).ok_or_else(|| fail("not JSON".into()))?;
    if !matches!(root, Json::Obj(_)) {
        return Err(fail("not an object".into()));
    }
    let value = match route {
        Route::Templates => templates(&root),
        Route::Kv => kv(&root),
        Route::Regions => regions(&root),
        Route::Instance => instance(&root).map(Some),
        // A session without an instance has nothing to give.
        Route::Session => match root.get("instance") {
            Json::Obj(_) => instance(root.get("instance")).map(Some),
            _ => Ok(None),
        },
    };
    value.map(|v| v.map(|v| (r, v))).map_err(fail)
}

/// `v` without its null fields, `depth` objects down: an absent field, to the validators.
fn without_nulls(v: &Json, depth: usize) -> Json {
    match v {
        Json::Obj(pairs) if depth > 0 => Json::Obj(pairs.iter().filter(|(_, x)| !x.is_null()).map(|(k, x)| (k.clone(), without_nulls(x, depth - 1))).collect()),
        _ => v.clone(),
    }
}

/// A key worth keeping: no note, within the bound.
fn usable_key(k: &str) -> bool {
    !k.is_empty() && !k.starts_with('_') && k.len() <= config::MAX_STR
}

/// `{"templates": {"<type>": {...}}}`: each template reduced to its known fields; one that
/// doesn't validate is left out.
fn templates(root: &Json) -> Result<Option<Json>, String> {
    let Json::Obj(all) = root.get("templates") else { return Err("no templates object".into()) };
    if all.len() > config::MAX_TEMPLATES {
        return Err(format!("more than {} templates", config::MAX_TEMPLATES));
    }
    let mut kept: Vec<(String, Json)> = Vec::new();
    for (name, t) in all.iter().filter(|(k, _)| usable_key(k)) {
        if !kept.iter().any(|(n, _)| n == name)
            && let Ok(t) = config::template(name, &without_nulls(t, 4))
        {
            kept.push((name.clone(), t));
        }
    }
    if kept.is_empty() {
        return if all.is_empty() { Ok(None) } else { Err("no template validates".into()) };
    }
    let v = Json::Obj(kept);
    config::templates_value(&v)?;
    Ok(Some(v))
}

/// `{"kvs": {...}, "kick_before_hint": ...}`: the string entries of `kvs`
/// within the bounds. A flat object is not taken: an error body (`{"detail": "Not Found"}`)
/// has that shape too.
fn kv(root: &Json) -> Result<Option<Json>, String> {
    let Json::Obj(pairs) = root.get("kvs") else { return Err("no kvs object".into()) };
    let mut kept: Vec<(String, Json)> = Vec::new();
    for (k, v) in pairs.iter().filter(|(k, _)| usable_key(k)) {
        if let Json::Str(s) = v
            && s.len() <= config::MAX_STR
            && !kept.iter().any(|(n, _)| n == k)
        {
            kept.push((k.clone(), Json::str(s)));
            if kept.len() > config::MAX_KV {
                return Err(format!("more than {} entries", config::MAX_KV));
            }
        }
    }
    if kept.is_empty() {
        return Ok(None);
    }
    let v = Json::Obj(kept);
    config::kv_value(&v)?;
    Ok(Some(v))
}

/// `{"regions": [...], "cursor": ...}`: each region reduced to its known fields; one that
/// doesn't validate is left out.
fn regions(root: &Json) -> Result<Option<Json>, String> {
    let Json::Arr(all) = root.get("regions") else { return Err("no regions list".into()) };
    if all.len() > config::MAX_REGIONS {
        return Err(format!("more than {} regions", config::MAX_REGIONS));
    }
    let kept: Vec<Json> = all.iter().filter_map(|r| config::region(&without_nulls(r, 1)).ok()).collect();
    if kept.is_empty() {
        return if all.is_empty() { Ok(None) } else { Err("no region validates".into()) };
    }
    let v = Json::Arr(kept);
    config::regions_value(&v)?;
    Ok(Some(v))
}

/// A key that names a player, a session or an address rather than a field: it holds a
/// UUID or another hex id (16 hex digits or more, dashes aside), an IPv4 address (with
/// or without a port) or an IPv6 one. Such a key would carry one player's data to disk,
/// and keys accumulate across sessions (`merged`).
fn personal_key(k: &str) -> bool {
    let hex_id = k.split(|c: char| !(c.is_ascii_hexdigit() || c == '-')).any(|t| t.chars().filter(char::is_ascii_hexdigit).count() >= 16);
    let v4 = k.split(|c: char| !(c.is_ascii_digit() || c == '.')).any(|t| t.parse::<std::net::Ipv4Addr>().is_ok());
    let v6 = k.split(|c: char| !(c.is_ascii_hexdigit() || c == ':' || c == '.')).any(|t| {
        t.matches(':').count() >= 2 && (t.parse::<std::net::Ipv6Addr>().is_ok() || t.rsplit_once(':').is_some_and(|(a, _)| a.parse::<std::net::Ipv6Addr>().is_ok()))
    });
    hex_id || v4 || v6
}

/// A key of an instance map worth keeping: `usable_key`, and not `personal_key`.
fn shape_key(k: &str) -> bool {
    usable_key(k) && !personal_key(k)
}

/// An object's keys, each value blanked (`""`), at most `config::MAX_KV`.
fn blank_map(m: &[(String, Json)]) -> Result<Json, String> {
    if m.len() > config::MAX_KV {
        return Err(format!("more than {} entries", config::MAX_KV));
    }
    let mut out: Vec<(String, Json)> = Vec::new();
    for (k, _) in m.iter().filter(|(k, _)| shape_key(k)) {
        if !out.iter().any(|(n, _)| n == k) {
            out.push((k.clone(), Json::str("")));
        }
    }
    Ok(Json::Obj(out))
}

/// An instance's shape: the keys of `instance_startup_params` (a string or a map of
/// strings each) and of `join_params` (its three known fields), every value blanked.
fn instance(inst: &Json) -> Result<Json, String> {
    let mut d = InstanceDefaults::default();
    let startup = inst.get("instance_startup_params");
    let join = inst.get("join_params");
    if !matches!(startup, Json::Obj(_)) && !matches!(join, Json::Obj(_)) {
        return Err("no instance_startup_params or join_params object".into());
    }
    if let Json::Obj(p) = startup {
        if p.len() > config::MAX_KV {
            return Err(format!("more than {} startup params", config::MAX_KV));
        }
        for (k, v) in p.iter().filter(|(k, _)| shape_key(k)) {
            if d.startup.iter().any(|(n, _)| n == k) {
                continue;
            }
            match v {
                Json::Str(_) => d.startup.push((k.clone(), Json::str(""))),
                Json::Obj(m) => d.startup.push((k.clone(), blank_map(m)?)),
                // A config default is a string or a map of strings: no other type is kept.
                _ => {}
            }
        }
    }
    if let Json::Obj(_) = join {
        for key in ["custom_data", "private_conn_str", "public_conn_str"] {
            match (key, join.get(key)) {
                ("custom_data", Json::Obj(m)) => d.join.push((key.to_string(), blank_map(m)?)),
                (_, Json::Str(_)) if key != "custom_data" => d.join.push((key.to_string(), Json::str(""))),
                _ => {}
            }
        }
    }
    let v = d.to_json();
    config::instance_value(&v)?;
    Ok(v)
}

/// `new` added to `old`: the keys of both, `old`'s first; a map in both gets the keys of both.
fn merged(old: Vec<(String, Json)>, new: Vec<(String, Json)>) -> Vec<(String, Json)> {
    let mut out = old;
    for (k, v) in new {
        match out.iter_mut().find(|(n, _)| *n == k) {
            Some((_, Json::Obj(have))) => {
                if let Json::Obj(more) = v {
                    for (mk, mv) in more {
                        if !have.iter().any(|(n, _)| *n == mk) {
                            have.push((mk, mv));
                        }
                    }
                }
            }
            Some(_) => {}
            None => out.push((k, v)),
        }
    }
    out
}

/// Writes `v` (from `filter`) as `r`'s file in `dir`; an instance shape is merged with the
/// file's. True when the file changed.
pub fn keep(dir: &Path, r: Resource, v: Json) -> Result<bool, String> {
    // Two calls finishing at once on two threads of the game write one after the other.
    static WRITING: Mutex<()> = Mutex::new(());
    let _one = crate::sys::lock(&WRITING);
    let v = if r == Resource::Instance {
        let new = config::instance_value(&v)?;
        let old = match read(dir, r) {
            Ok(Some(old)) => config::instance_value(&old).unwrap_or_default(),
            _ => InstanceDefaults::default(),
        };
        InstanceDefaults { startup: merged(old.startup, new.startup), join: merged(old.join, new.join) }.to_json()
    } else {
        v
    };
    validate(r, &v)?;
    let text = v.to_string();
    if text.len() > MAX_BODY {
        return Err(format!("larger than {} KiB", MAX_BODY / 1024));
    }
    write_file(dir, r.file(), &text)
}

fn validate(r: Resource, v: &Json) -> Result<(), String> {
    match r {
        Resource::Templates => config::templates_value(v).map(drop),
        Resource::Kv => config::kv_value(v).map(drop),
        Resource::Regions => config::regions_value(v).map(drop),
        Resource::Instance => config::instance_value(v).map(drop),
    }
}

/// `text` as `dir\name`, through a temporary file renamed over it, unless the file holds
/// it already. True when written.
fn write_file(dir: &Path, name: &str, text: &str) -> Result<bool, String> {
    let path = dir.join(name);
    if matches!(config::read_text(&path), Ok(Some(have)) if have == text) {
        return Ok(false);
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("no folder ({:?})", e.kind()))?;
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    if let Err(e) = std::fs::write(&tmp, text).and_then(|_| std::fs::rename(&tmp, &path)) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("can't be written ({:?})", e.kind()));
    }
    Ok(true)
}

/// `r`'s file in `dir`, as JSON: None when there is none, Err when it can't be used.
/// The caller validates it.
fn read(dir: &Path, r: Resource) -> Result<Option<Json>, String> {
    let Some(text) = config::read_text(&dir.join(r.file()))? else { return Ok(None) };
    Json::parse(text.trim_start_matches('\u{feff}')).map(Some).ok_or_else(|| "isn't valid JSON (or nests too deeply)".into())
}

/// The title data the stand-in serves.
#[derive(Debug, Default, PartialEq)]
pub struct TitleData {
    pub templates: Vec<(String, Json)>,
    pub kv: Vec<(String, String)>,
    /// Empty: the stand-in's own one region.
    pub regions: Vec<Json>,
    pub instance: InstanceDefaults,
}

/// Per resource, `cfg`'s when it has any, else the harvested file's in `harvested` when
/// there is a valid one, else nothing. The log names the file each comes from.
pub fn resolve(cfg: &Config, harvested: Option<&Path>) -> TitleData {
    resolve_all(cfg, harvested, None, None)
}

/// `resolve`, then the launcher's cache for what is still missing: per resource the first of
/// the player's config.json (`cfg`), the player's `harvested` folder, the cached config.json
/// (`cached_cfg`), the cached `harvested` folder that has a valid one. A file that is refused
/// (too big, not valid) counts as absent, whichever of the four it is (a refused config.json
/// of the player's also keeps the layer off, so its title data is then never asked for).
pub fn resolve_all(cfg: &Config, harvested: Option<&Path>, cached_cfg: Option<&Config>, cached_harvested: Option<&Path>) -> TitleData {
    fn pick<T>(
        r: Resource,
        layers: [(Option<&Config>, Option<&Path>, &str); 2],
        configured: impl Fn(&Config) -> (T, bool),
        typed: impl Fn(&Json) -> Result<T, String>,
        nothing: T,
    ) -> T {
        for (cfg, dir, from) in layers {
            if let Some(c) = cfg {
                let (t, has) = configured(c);
                if has {
                    log!("rallyhere: {} from {from}config.json", r.name());
                    return t;
                }
            }
            let Some(dir) = dir else { continue };
            match read(dir, r).and_then(|v| v.map(|v| typed(&v)).transpose()) {
                Ok(Some(t)) => {
                    log!("rallyhere: {} from {from}{}\\{}", r.name(), FOLDER, r.file());
                    return t;
                }
                Ok(None) => {}
                Err(e) => log!("rallyhere: {from}{}\\{} ignored: {e}", FOLDER, r.file()),
            }
        }
        nothing
    }
    let layers = [(Some(cfg), harvested, ""), (cached_cfg, cached_harvested, "cached ")];
    TitleData {
        templates: pick(Resource::Templates, layers, |c| (c.templates.clone(), !c.templates.is_empty()), config::templates_value, Vec::new()),
        kv: pick(Resource::Kv, layers, |c| (c.kv.clone(), !c.kv.is_empty()), config::kv_value, Vec::new()),
        // config.json has no regions.
        regions: pick(Resource::Regions, layers, |_| (Vec::new(), false), config::regions_value, Vec::new()),
        instance: pick(Resource::Instance, layers, |c| (c.instance.clone(), !c.instance.is_empty()), config::instance_value, InstanceDefaults::default()),
    }
}

/// The title data of this run, settled at first use.
pub fn title_data() -> &'static TitleData {
    static DATA: OnceLock<TitleData> = OnceLock::new();
    DATA.get_or_init(|| {
        let local = config::folder().map(|d| d.join(FOLDER));
        // No cache when the player named the folder to read (`cached_folder`).
        match config::cached_folder() {
            Some(cached) => resolve_all(config::load(), local.as_deref(), Some(config::load_cached()), Some(&cached.join(FOLDER))),
            None => resolve(config::load(), local.as_deref()),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rallyhere::tests_support::temp_dir;

    fn take(method: &str, path: &str, body: &str) -> Option<(Resource, Json)> {
        filter(method, path, body.as_bytes()).unwrap_or_else(|(r, e)| panic!("{r:?} dropped: {e}"))
    }

    fn dropped(method: &str, path: &str, body: &str) -> String {
        match filter(method, path, body.as_bytes()) {
            Err((_, why)) => why,
            Ok(v) => panic!("kept {v:?}"),
        }
    }

    /// A made-up service's template list, with fields nobody asked for.
    const TEMPLATES: &str = r#"{"templates": {
        "example_party": {"session_type": "example_party", "engine_session_type": "example_party",
          "can_be_created_by_players_directly": true, "players_per_team": 4, "custom_data": null,
          "owner_player_uuid": "11111111-2222-3333-4444-555555555555", "internal_note": "x",
          "platform_templates": {"Steam": {"platform": "Steam", "platform_id": 5, "platform_session_type": "p", "secret": "s"}}},
        "example_broken": {"num_teams": "two"},
        "_note": {"joinable": true}}}"#;

    #[test]
    fn templates_keep_their_known_fields_only() {
        let (r, v) = take("GET", "/session/v1/template", TEMPLATES).unwrap();
        assert_eq!(r, Resource::Templates);
        let t = v.get("example_party");
        assert_eq!(t.get("players_per_team").as_i64(), Some(4));
        assert_eq!(t.get("platform_templates").get("Steam").get("platform_id").as_i64(), Some(5));
        for gone in ["owner_player_uuid", "internal_note", "custom_data"] {
            assert!(t.get(gone).is_null(), "{gone} kept");
        }
        assert!(t.get("platform_templates").get("Steam").get("secret").is_null());
        assert!(v.get("example_broken").is_null(), "a template that doesn't validate is left out");
        assert!(v.get("_note").is_null());
        assert!(!v.to_string().contains("1111"), "no id");
        // What is written reads back as config.json's templates.
        assert_eq!(config::templates_value(&v).unwrap().len(), 1);
        // The ETag's 304 has no body: nothing to keep.
        assert_eq!(take("GET", "/session/v1/template", ""), None);
        assert_eq!(take("POST", "/session/v1/template", TEMPLATES), None, "only a read");
    }

    #[test]
    fn kv_comes_from_kvs_and_a_flat_object_is_dropped() {
        let (r, v) = take("GET", "/config/v2/kv?x=1", r#"{"kvs": {"motd": "hello", "n": 5, "_c": "note"}, "kick_before_hint": "2020-01-01T00:00:00Z"}"#).unwrap();
        assert_eq!(r, Resource::Kv);
        assert_eq!(v.to_string(), r#"{"motd":"hello"}"#, "strings only; the hint is no kv");
        assert!(dropped("GET", "/config/v2/kv", r#"{"motd": "hello", "feature": "on"}"#).contains("no kvs"), "a flat object can't be told from an error body");
        assert_eq!(take("GET", "/config/v2/kv", r#"{"kvs": {}}"#), None, "nothing to keep");
        let long = "x".repeat(config::MAX_STR + 1);
        let (_, v) = take("GET", "/config/v2/kv", &format!(r#"{{"kvs": {{"a": "{long}", "b": "v"}}}}"#)).unwrap();
        assert_eq!(v.to_string(), r#"{"b":"v"}"#, "an entry over the bound is left out");
    }

    #[test]
    fn regions_keep_their_known_fields_and_the_first_page_only() {
        let body = r#"{"regions": [{"region_id": "eu", "sort_order": 2, "custom_only": false, "description": "Europe", "ip": "203.0.113.9", "ping_host": "x.example.test"},
            {"sort_order": 3}, {"region_id": "us", "description": null}], "cursor": 2}"#;
        let (r, v) = take("GET", "/session/v1/regions", body).unwrap();
        assert_eq!(r, Resource::Regions);
        assert_eq!(v.to_string(), r#"[{"region_id":"eu","sort_order":2,"custom_only":false,"description":"Europe"},{"region_id":"us"}]"#);
        assert_eq!(take("GET", "/session/v1/regions?cursor=0", body).map(|(r, _)| r), Some(Resource::Regions));
        assert_eq!(take("GET", "/session/v1/regions?cursor=2&page_size=10", body), None, "a later page would replace the list");
    }

    /// A made-up instance as the service answers it, every value the session's own.
    const INSTANCE: &str = r#"{"instance_id": "a1b2c3", "host_type": "player", "host_player_uuid": "11111111-2222-3333-4444-555555555555",
        "join_status": "joinable", "version": "1.2.3", "match_id": "m-77", "created": "2026-11-27T10:00:00Z",
        "instance_startup_params": {"map": "/Game/Maps/Example", "mode": "example", "misc_params": "?Name=Player1", "extra": {"seed": "42"}, "count": 3},
        "join_params": {"public_conn_str": "203.0.113.9:7777", "private_conn_str": "192.168.1.20:7777",
          "custom_data": {"rh.SessionSecurityToken": "0123456789abcdef0123456789abcdef"}, "other": "x"}}"#;

    #[test]
    fn an_instance_keeps_its_keys_with_every_value_blanked() {
        let (r, v) = take("POST", "/session/v1/session/s-1/instance", INSTANCE).unwrap();
        assert_eq!(r, Resource::Instance);
        assert_eq!(
            v.to_string(),
            r#"{"instance_startup_params":{"map":"","mode":"","misc_params":"","extra":{"seed":""}},"join_params":{"custom_data":{"rh.SessionSecurityToken":""},"private_conn_str":"","public_conn_str":""}}"#
        );
        for secret in ["a1b2", "1111", "203.0", "192.168", "0123", "Player1", "m-77", "1.2.3", "2026", "Example"] {
            assert!(!v.to_string().contains(secret), "{secret} kept");
        }
        // A session's instance, on the session routes.
        let session = format!(r#"{{"session_id": "s-1", "type": "example_party", "instance": {INSTANCE}, "teams": []}}"#);
        for (m, p) in [("GET", "/session/v1/session/s-1"), ("PATCH", "/session/v1/session/s-1"), ("POST", "/session/v1/session"), ("POST", "/session/v1/session/s-1/player/me")] {
            assert_eq!(take(m, p, &session), Some((Resource::Instance, v.clone())), "{m} {p}");
        }
        assert_eq!(take("GET", "/session/v1/session/s-1", r#"{"session_id": "s-1"}"#), None, "no instance yet");
        assert_eq!(take("DELETE", "/session/v1/session/s-1/instance", INSTANCE), None);
        assert_eq!(take("POST", "/session/v1/session/s-1/instance/health", r#"{"updated_instance_health": "healthy"}"#), None);
    }

    #[test]
    fn keys_that_name_a_player_or_an_address_are_dropped() {
        for personal in [
            "11111111-2222-3333-4444-555555555555",
            "{11111111-2222-3333-4444-555555555555}",
            "player.11111111-2222-3333-4444-555555555555.team",
            "0123456789abcdef",
            "76561190000000001",
            "eos:0123456789abcdef0123456789abcdef",
            "203.0.113.9",
            "203.0.113.9:7777",
            "host_198.51.100.20",
            "2001:db8::1",
            "[2001:db8::1]:7777",
            "fe80::1%4",
        ] {
            assert!(personal_key(personal), "{personal}");
        }
        for field in ["rh.SessionSecurityToken", "map", "misc_params", "deadbeef", "team-1", "version.1.2.3", "v1.2", "a:b:c", "ab:cd", "max_players_16"] {
            assert!(!personal_key(field), "{field}");
        }
        let body = r#"{"instance_startup_params": {"map": "", "203.0.113.9": "x", "extra": {"seed": "1", "11111111-2222-3333-4444-555555555555": "ready"}},
            "join_params": {"custom_data": {"rh.SessionSecurityToken": "t", "0123456789abcdef0123": "p", "[2001:db8::1]:7777": "a"}}}"#;
        let (_, v) = take("PATCH", "/session/v1/session/s/instance", body).unwrap();
        assert_eq!(v.to_string(), r#"{"instance_startup_params":{"map":"","extra":{"seed":""}},"join_params":{"custom_data":{"rh.SessionSecurityToken":""}}}"#);
    }

    #[test]
    fn personal_routes_are_never_watched_or_kept() {
        let tokens = r#"{"access_token": "eyJ.x.y", "refresh_token": "r", "kvs": {"a": "b"}, "templates": {"t": {}}}"#;
        for path in ["/users/v1/login", "/users/v2/player/x/links", "/inventory/v1/player/me/inventory", "/friends/v2/player/x/friend", "/presence/v1/player/me/presence", "/session/v1/player/me/session", "/notification/v1/player/x/stream/notification/lp"] {
            assert_eq!(route(path), None, "{path}");
            assert_eq!(take("GET", path, tokens), None, "{path}");
        }
    }

    #[test]
    fn an_error_or_a_wrong_shape_is_dropped() {
        let error = r#"{"auth_success": true, "error_code": "session_not_found", "desc": "Session not found."}"#;
        for path in ["/session/v1/template", "/config/v2/kv", "/session/v1/regions", "/session/v1/session/s/instance"] {
            assert!(!dropped("GET", path, error).is_empty(), "{path}");
        }
        for all_strings in [r#"{"error_code": "x", "desc": "y"}"#, r#"{"detail": "Not Found"}"#, r#"{"message": "Forbidden"}"#] {
            for path in ["/session/v1/template", "/config/v2/kv", "/session/v1/regions", "/session/v1/session/s/instance"] {
                assert!(!dropped("GET", path, all_strings).is_empty(), "{path} {all_strings}");
            }
        }
        assert!(!dropped("GET", "/session/v1/template", r#"{"templates": []}"#).is_empty());
        assert!(!dropped("GET", "/session/v1/template", r#"{"templates": {"t": {"num_teams": -1}}}"#).is_empty());
        assert!(!dropped("GET", "/session/v1/regions", r#"{"regions": [{"region_id": 5}]}"#).is_empty());
        assert!(!dropped("GET", "/session/v1/template", "[1]").is_empty());
        assert!(!dropped("GET", "/session/v1/template", "<html>").is_empty());
        assert!(dropped("GET", "/session/v1/template", "\u{fffd}").contains("not JSON"));
        assert!(filter("GET", "/session/v1/template", &[0xff, 0xfe]).is_err());
    }

    #[test]
    fn bounds_refuse_an_answer() {
        let big = format!(r#"{{"kvs": {{"a": "{}"}}}}"#, " ".repeat(MAX_BODY));
        assert!(dropped("GET", "/config/v2/kv", &big).contains("larger"));
        let kv = |n: usize| format!(r#"{{"kvs": {{{}}}}}"#, (0..n).map(|i| format!("\"k{i}\": \"v\"")).collect::<Vec<_>>().join(","));
        assert!(take("GET", "/config/v2/kv", &kv(config::MAX_KV)).is_some());
        assert!(dropped("GET", "/config/v2/kv", &kv(config::MAX_KV + 1)).contains("more than"));
        let templates = |n: usize| format!(r#"{{"templates": {{{}}}}}"#, (0..n).map(|i| format!("\"t{i}\": {{}}")).collect::<Vec<_>>().join(","));
        assert!(take("GET", "/session/v1/template", &templates(config::MAX_TEMPLATES)).is_some());
        assert!(dropped("GET", "/session/v1/template", &templates(config::MAX_TEMPLATES + 1)).contains("more than"));
        let regions = |n: usize| format!(r#"{{"regions": [{}]}}"#, (0..n).map(|i| format!("{{\"region_id\": \"r{i}\"}}")).collect::<Vec<_>>().join(","));
        assert!(take("GET", "/session/v1/regions", &regions(config::MAX_REGIONS)).is_some());
        assert!(dropped("GET", "/session/v1/regions", &regions(config::MAX_REGIONS + 1)).contains("more than"));
        let params = |n: usize| format!(r#"{{"instance_startup_params": {{{}}}}}"#, (0..n).map(|i| format!("\"k{i}\": \"v\"")).collect::<Vec<_>>().join(","));
        assert!(take("GET", "/session/v1/session/s/instance", &params(config::MAX_KV)).is_some());
        assert!(dropped("GET", "/session/v1/session/s/instance", &params(config::MAX_KV + 1)).contains("more than"));
    }

    #[test]
    fn files_are_written_atomically_once_and_validated() {
        let dir = temp_dir("harvest-write");
        let (r, v) = take("GET", "/config/v2/kv", r#"{"kvs": {"motd": "hello"}}"#).unwrap();
        assert_eq!(keep(&dir, r, v.clone()), Ok(true));
        let path = dir.join("kv.json");
        let stamp = std::fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), r#"{"motd":"hello"}"#);
        assert_eq!(keep(&dir, r, v), Ok(false), "an identical file isn't rewritten");
        assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), stamp);
        let names: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(names, ["kv.json"], "no temporary file left");
        // Never written without validating.
        assert!(keep(&dir, Resource::Kv, Json::parse(r#"{"a": 1}"#).unwrap()).is_err());
        assert!(keep(&dir, Resource::Regions, Json::parse(r#"[{"description": "x"}]"#).unwrap()).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), r#"{"motd":"hello"}"#);
        // The instance shape grows with what is seen, and keeps what it had.
        let first = take("POST", "/session/v1/session/s/instance", r#"{"instance_startup_params": {"map": "m", "extra": {"a": "1"}}}"#).unwrap().1;
        let then = take("PATCH", "/session/v1/session/s/instance", r#"{"instance_startup_params": {"mode": "x", "extra": {"b": "2"}}, "join_params": {"public_conn_str": "198.51.100.1:1"}}"#).unwrap().1;
        assert_eq!(keep(&dir, Resource::Instance, first), Ok(true));
        assert_eq!(keep(&dir, Resource::Instance, then.clone()), Ok(true));
        assert_eq!(
            std::fs::read_to_string(dir.join("instance.json")).unwrap(),
            r#"{"instance_startup_params":{"map":"","extra":{"a":"","b":""},"mode":""},"join_params":{"public_conn_str":""}}"#
        );
        assert_eq!(keep(&dir, Resource::Instance, then), Ok(false), "nothing new");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nothing_is_written_outside_official_mode() {
        let dir = temp_dir("harvest-lan");
        observe(false, Some(&dir), "GET", "/config/v2/kv", br#"{"kvs": {"motd": "hello"}}"#);
        assert!(!dir.join("kv.json").exists());
        observe(true, Some(&dir), "GET", "/config/v2/kv", br#"{"kvs": {"motd": "hello"}}"#);
        assert!(dir.join("kv.json").exists());
        // A later error answer leaves the file as it was.
        observe(true, Some(&dir), "GET", "/config/v2/kv", br#"{"auth_success": false, "error_code": "unauthorized"}"#);
        observe(true, Some(&dir), "GET", "/config/v2/kv", b"");
        assert_eq!(std::fs::read_to_string(dir.join("kv.json")).unwrap(), r#"{"motd":"hello"}"#);
        // This thread has no test setup and the run's mode is LAN: nothing is watched.
        assert!(!active());
        assert!(!watches("api.example.test", "/config/v2/kv"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn title_data_comes_from_config_then_harvested_then_nothing() {
        let dir = temp_dir("harvest-read");
        let none = resolve(&Config::default(), Some(&dir));
        assert_eq!(none, TitleData::default(), "no file, no config");
        for (r, text) in [
            (Resource::Templates, r#"{"example_party":{"joinable":true}}"#),
            (Resource::Kv, r#"{"motd":"harvested"}"#),
            (Resource::Regions, r#"[{"region_id":"eu"}]"#),
            (Resource::Instance, r#"{"instance_startup_params":{"map":""}}"#),
        ] {
            std::fs::write(dir.join(r.file()), text).unwrap();
        }
        let h = resolve(&Config::default(), Some(&dir));
        assert_eq!(h.templates[0].0, "example_party");
        assert_eq!(h.kv, [("motd".to_string(), "harvested".to_string())]);
        assert_eq!(h.regions.len(), 1);
        assert_eq!(h.instance.startup[0].0, "map");
        let cfg = config::parse(r#"{"templates": {"example_match": {}}, "kv": {"motd": "mine"}, "instance": {"join_params": {"public_conn_str": ""}}}"#).unwrap();
        let c = resolve(&cfg, Some(&dir));
        assert_eq!(c.templates[0].0, "example_match", "config.json first");
        assert_eq!(c.kv, [("motd".to_string(), "mine".to_string())]);
        assert_eq!(c.instance.join[0].0, "public_conn_str");
        assert!(c.instance.startup.is_empty(), "config.json's instance replaces the harvested one");
        assert_eq!(c.regions.len(), 1, "config.json has no regions");
        // A harvested file that doesn't validate is ignored.
        std::fs::write(dir.join("kv.json"), r#"{"motd": 1}"#).unwrap();
        std::fs::write(dir.join("regions.json"), "[").unwrap();
        let bad = resolve(&Config::default(), Some(&dir));
        assert!(bad.kv.is_empty() && bad.regions.is_empty());
        assert_eq!(bad.templates.len(), 1, "the others still read");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn title_data_reads_the_player_then_the_cache_per_resource() {
        let (local, cache) = (temp_dir("rd-local"), temp_dir("rd-cache"));
        let (cached_h, local_h) = (cache.join("harvested"), local.join("harvested"));
        std::fs::create_dir_all(&cached_h).unwrap();
        std::fs::create_dir_all(&local_h).unwrap();
        let none = Config::default();
        let local_cfg = config::parse(r#"{"kv": {"motd": "local config"}}"#).unwrap();
        let cached_cfg = config::parse(r#"{"templates": {"cached_party": {}}, "kv": {"motd": "cached config"}, "instance": {"join_params": {"public_conn_str": ""}}}"#).unwrap();
        let all = |l: &Config, c: &Config| resolve_all(l, Some(&local_h), Some(c), Some(&cached_h));
        assert_eq!(all(&none, &none), TitleData::default(), "nothing anywhere");
        // Only the cache: its config.json, then its harvested files.
        let d = all(&none, &cached_cfg);
        assert_eq!((d.templates[0].0.as_str(), d.kv[0].1.as_str(), d.instance.join[0].0.as_str()), ("cached_party", "cached config", "public_conn_str"));
        std::fs::write(cached_h.join("kv.json"), r#"{"motd":"cached harvested"}"#).unwrap();
        std::fs::write(cached_h.join("regions.json"), r#"[{"region_id":"eu"}]"#).unwrap();
        assert_eq!(all(&none, &cached_cfg).kv[0].1, "cached config", "the cached config.json is before the cached harvested");
        let d = all(&none, &none);
        assert_eq!((d.kv[0].1.as_str(), d.regions.len()), ("cached harvested", 1));
        // The player's harvested files are before the cached config.json.
        std::fs::write(local_h.join("kv.json"), r#"{"motd":"local harvested"}"#).unwrap();
        assert_eq!(all(&none, &cached_cfg).kv[0].1, "local harvested");
        // The player's config.json is before everything.
        let d = all(&local_cfg, &cached_cfg);
        assert_eq!(d.kv[0].1, "local config");
        assert_eq!(d.templates[0].0, "cached_party", "per resource: the player has no templates");
        assert_eq!(d.regions.len(), 1);
        // A cached file that is refused counts as absent; an oversized one too.
        std::fs::write(cached_h.join("kv.json"), r#"{"motd": 1}"#).unwrap();
        std::fs::write(cached_h.join("regions.json"), vec![b' '; config::MAX_FILE as usize + 1]).unwrap();
        std::fs::remove_file(local_h.join("kv.json")).unwrap();
        let d = all(&none, &none);
        assert!(d.kv.is_empty() && d.regions.is_empty());
        // Without a cache (a folder named by the player) the resolution is `resolve`'s.
        assert_eq!(resolve(&none, Some(&local_h)), resolve_all(&none, Some(&local_h), None, None));
        let _ = std::fs::remove_dir_all(&local);
        let _ = std::fs::remove_dir_all(&cache);
    }
}
