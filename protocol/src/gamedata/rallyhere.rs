//! A game's RallyHere data files (hook/src/rallyhere/): its `config.json` and the files
//! official mode harvests (`harvested\template.json`, `kv.json`, `regions.json`,
//! `instance.json`), each with the shape of the matching config.json key. The hook reads
//! them with these checks, and the launcher checks a file it fetched for the hook's cache
//! (launcher/src/sources.rs) with the same ones, so that it never keeps a file the hook
//! would refuse.
//!
//! The files are untrusted: at most `MAX_FILE` bytes, bounded counts and strings, and any
//! wrong type refuses the whole file. Unknown keys and keys starting with `_` (notes) are
//! ignored.

use crate::json::Json;

pub const MAX_FILE: u64 = 256 * 1024;
pub const MAX_HOSTS: usize = 16;
pub const MAX_TEMPLATES: usize = 64;
pub const MAX_KV: usize = 256;
/// The most platforms one template names.
pub const MAX_PLATFORMS: usize = 16;
/// The longest string anywhere in the file, keys included.
pub const MAX_STR: usize = 1024;
/// The most regions a region list holds.
pub const MAX_REGIONS: usize = 64;
/// The largest `sort_order` of a region, either way.
const MAX_SORT: i64 = 1_000_000;

#[derive(Debug, Default, PartialEq)]
pub struct Config {
    /// Normalized (`normalize`), without duplicates.
    pub hosts: Vec<String>,
    /// Session type to its template, as validated JSON (only the known fields are kept).
    pub templates: Vec<(String, Json)>,
    pub kv: Vec<(String, String)>,
    /// The instance's default fields (empty without an `instance` section).
    pub instance: InstanceDefaults,
}

/// The defaults of an instance's `instance_startup_params` and `join_params`, as validated
/// JSON values (a string, or an object of strings).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct InstanceDefaults {
    pub startup: Vec<(String, Json)>,
    pub join: Vec<(String, Json)>,
}

impl InstanceDefaults {
    pub fn is_empty(&self) -> bool {
        self.startup.is_empty() && self.join.is_empty()
    }

    /// As config.json's `instance` section writes it (an object left out when it has nothing).
    pub fn to_json(&self) -> Json {
        let mut out = Vec::new();
        if !self.startup.is_empty() {
            out.push(("instance_startup_params".to_string(), Json::Obj(self.startup.clone())));
        }
        if !self.join.is_empty() {
            out.push(("join_params".to_string(), Json::Obj(self.join.clone())));
        }
        Json::Obj(out)
    }
}

/// A host as compared: no port, no trailing dot, lowercase.
pub fn normalize(host: &str) -> String {
    host.trim().split(':').next().unwrap_or_default().trim_end_matches('.').to_ascii_lowercase()
}

pub fn parse(text: &str) -> Result<Config, String> {
    let root = Json::parse(text.trim_start_matches('\u{feff}')).ok_or("isn't valid JSON (or nests too deeply)")?;
    if !matches!(root, Json::Obj(_)) {
        return Err("isn't a JSON object".into());
    }
    let mut c = Config::default();
    if let Some(v) = field(&root, "hosts") {
        let Json::Arr(items) = v else { return Err("hosts: expected a list of strings".into()) };
        if items.len() > MAX_HOSTS {
            return Err(format!("hosts: more than {MAX_HOSTS} entries"));
        }
        for h in items {
            let h = string(h, "hosts")?;
            let h = normalize(h);
            if !h.is_empty() && !c.hosts.contains(&h) {
                c.hosts.push(h);
            }
        }
    }
    if let Some(v) = field(&root, "templates") {
        c.templates = templates_value(v)?;
    }
    if let Some(v) = field(&root, "kv") {
        c.kv = kv_value(v)?;
    }
    if let Some(v) = field(&root, "instance") {
        c.instance = instance_value(v)?;
    }
    Ok(c)
}

/// The `templates` section: session type to its template, each validated.
pub fn templates_value(v: &Json) -> Result<Vec<(String, Json)>, String> {
    let Json::Obj(pairs) = v else { return Err("templates: expected an object".into()) };
    let mut out: Vec<(String, Json)> = Vec::new();
    for (name, t) in pairs.iter().filter(|(k, _)| !k.starts_with('_')) {
        if out.len() >= MAX_TEMPLATES {
            return Err(format!("templates: more than {MAX_TEMPLATES} entries"));
        }
        bounded(name, "templates")?;
        if out.iter().any(|(n, _)| n == name) {
            continue;
        }
        out.push((name.clone(), template(name, t)?));
    }
    Ok(out)
}

/// The `kv` section: an object of strings.
pub fn kv_value(v: &Json) -> Result<Vec<(String, String)>, String> {
    string_map(v, "kv", MAX_KV)
}

/// A region list, as `GET /session/v1/regions` answers it: at most `MAX_REGIONS`, each
/// checked by `region`.
pub fn regions_value(v: &Json) -> Result<Vec<Json>, String> {
    let Json::Arr(items) = v else { return Err("regions: expected a list".into()) };
    if items.len() > MAX_REGIONS {
        return Err(format!("regions: more than {MAX_REGIONS} entries"));
    }
    items.iter().map(region).collect()
}

/// One region: `region_id` (a string, required), `sort_order` (a whole number),
/// `custom_only` (true or false) and `description` (a string); only these fields are kept.
pub fn region(v: &Json) -> Result<Json, String> {
    let Json::Obj(_) = v else { return Err("regions: expected objects".into()) };
    let id = field(v, "region_id").ok_or("regions: a region has no region_id")?;
    let id = string(id, "regions.region_id")?;
    if id.is_empty() {
        return Err("regions.region_id: empty".into());
    }
    let mut out = vec![("region_id".to_string(), Json::str(id))];
    if let Some(n) = field(v, "sort_order") {
        let n = n.as_i64().filter(|n| (-MAX_SORT..=MAX_SORT).contains(n)).ok_or_else(|| format!("regions.sort_order: expected a whole number from -{MAX_SORT} to {MAX_SORT}"))?;
        out.push(("sort_order".to_string(), Json::int(n)));
    }
    if let Some(b) = field(v, "custom_only") {
        out.push(("custom_only".to_string(), Json::Bool(b.as_bool().ok_or("regions.custom_only: expected true or false")?)));
    }
    if let Some(d) = field(v, "description") {
        out.push(("description".to_string(), Json::str(string(d, "regions.description")?)));
    }
    Ok(Json::Obj(out))
}

/// The `instance` section: each field's default, validated.
pub fn instance_value(v: &Json) -> Result<InstanceDefaults, String> {
    let Json::Obj(_) = v else { return Err("instance: expected an object".into()) };
    let mut d = InstanceDefaults::default();
    if let Some(p) = field(v, "instance_startup_params") {
        const WHAT: &str = "instance.instance_startup_params";
        let Json::Obj(pairs) = p else { return Err(format!("{WHAT}: expected an object")) };
        for (k, x) in pairs.iter().filter(|(k, _)| !k.starts_with('_')) {
            if d.startup.len() >= MAX_KV {
                return Err(format!("{WHAT}: more than {MAX_KV} entries"));
            }
            bounded(k, WHAT)?;
            if d.startup.iter().any(|(n, _)| n == k) {
                continue;
            }
            let value = match x {
                Json::Str(_) => Json::str(string(x, WHAT)?),
                _ => string_map_json(x, WHAT)?,
            };
            d.startup.push((k.clone(), value));
        }
    }
    if let Some(p) = field(v, "join_params") {
        let Json::Obj(_) = p else { return Err("instance.join_params: expected an object".into()) };
        for key in ["custom_data", "private_conn_str", "public_conn_str"] {
            let what = format!("instance.join_params.{key}");
            match field(p, key) {
                None => {}
                Some(x) if key == "custom_data" => d.join.push((key.to_string(), string_map_json(x, &what)?)),
                Some(x) => d.join.push((key.to_string(), Json::str(string(x, &what)?))),
            }
        }
    }
    Ok(d)
}

/// A key of an object, when present (a null is present: a type error for its reader).
fn field<'a>(o: &'a Json, key: &str) -> Option<&'a Json> {
    o.as_obj().iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn bounded(s: &str, what: &str) -> Result<(), String> {
    if s.len() > MAX_STR {
        return Err(format!("{what}: a string is longer than {MAX_STR} bytes"));
    }
    Ok(())
}

fn string<'a>(v: &'a Json, what: &str) -> Result<&'a str, String> {
    let s = v.as_str().ok_or_else(|| format!("{what}: expected a string"))?;
    bounded(s, what)?;
    Ok(s)
}

/// An object whose values are all strings, without its notes, at most `max` entries.
fn string_map(v: &Json, what: &str, max: usize) -> Result<Vec<(String, String)>, String> {
    let Json::Obj(pairs) = v else { return Err(format!("{what}: expected an object of strings")) };
    let mut out: Vec<(String, String)> = Vec::new();
    for (k, s) in pairs.iter().filter(|(k, _)| !k.starts_with('_')) {
        if out.len() >= max {
            return Err(format!("{what}: more than {max} entries"));
        }
        bounded(k, what)?;
        let s = string(s, what)?;
        if !out.iter().any(|(n, _)| n == k) {
            out.push((k.clone(), s.to_string()));
        }
    }
    Ok(out)
}

fn string_map_json(v: &Json, what: &str) -> Result<Json, String> {
    Ok(Json::Obj(string_map(v, what, MAX_KV)?.into_iter().map(|(k, s)| (k, Json::Str(s))).collect()))
}

const BOOLS: &[&str] = &[
    "can_join_matchmaking",
    "can_be_created_by_players_directly",
    "joinable",
    "attempt_auto_join",
    "default_public",
    "auto_add_to_browser",
    "can_be_added_to_server_browser",
    "keep_alive_on_empty",
    "can_change_own_team",
    "notify_on_reservation",
];
const STRINGS: &[&str] = &["session_type", "engine_session_type", "auto_startup_instance_template_id"];
const INTS: &[&str] = &["min_session_count", "num_teams", "players_per_team"];
const STRING_MAPS: &[&str] = &["auto_browser_params", "custom_data"];
const VISIBILITY: &[&str] = &["player_visibility", "admin_player_visibility", "player_notification_frequency", "admin_player_notification_frequency"];
const VISIBILITY_VALUES: &[&str] = &["ALL", "TEAM", "SELF", "NONE"];
const MAX_INT: i64 = 1_000_000;

/// One template checked field by field; only its known fields are kept.
pub fn template(name: &str, t: &Json) -> Result<Json, String> {
    let what = format!("templates.{name}");
    let Json::Obj(_) = t else { return Err(format!("{what}: expected an object")) };
    let mut out: Vec<(String, Json)> = Vec::new();
    for key in BOOLS {
        if let Some(v) = field(t, key) {
            out.push((key.to_string(), Json::Bool(v.as_bool().ok_or_else(|| format!("{what}.{key}: expected true or false"))?)));
        }
    }
    for key in STRINGS {
        if let Some(v) = field(t, key) {
            out.push((key.to_string(), Json::str(string(v, &format!("{what}.{key}"))?)));
        }
    }
    for key in INTS {
        if let Some(v) = field(t, key) {
            let n = v.as_i64().filter(|n| (0..=MAX_INT).contains(n)).ok_or_else(|| format!("{what}.{key}: expected a whole number from 0 to {MAX_INT}"))?;
            out.push((key.to_string(), Json::int(n)));
        }
    }
    for key in STRING_MAPS {
        if let Some(v) = field(t, key) {
            out.push((key.to_string(), string_map_json(v, &format!("{what}.{key}"))?));
        }
    }
    for key in VISIBILITY {
        if let Some(v) = field(t, key) {
            let s = string(v, &format!("{what}.{key}"))?;
            if !VISIBILITY_VALUES.contains(&s) {
                return Err(format!("{what}.{key}: expected ALL, TEAM, SELF or NONE"));
            }
            out.push((key.to_string(), Json::str(s)));
        }
    }
    if let Some(v) = field(t, "platform_templates") {
        let Json::Obj(pairs) = v else { return Err(format!("{what}.platform_templates: expected an object")) };
        let pairs: Vec<&(String, Json)> = pairs.iter().filter(|(k, _)| !k.starts_with('_')).collect();
        if pairs.len() > MAX_PLATFORMS {
            return Err(format!("{what}.platform_templates: more than {MAX_PLATFORMS} entries"));
        }
        let mut platforms = Vec::new();
        for (p, pt) in pairs {
            bounded(p, &what)?;
            platforms.push((p.clone(), platform_template(&format!("{what}.platform_templates.{p}"), pt)?));
        }
        out.push(("platform_templates".into(), Json::Obj(platforms)));
    }
    if let Some(v) = field(t, "auto_startup_params") {
        let at = format!("{what}.auto_startup_params");
        let Json::Obj(_) = v else { return Err(format!("{at}: expected an object")) };
        let mut params = Vec::new();
        for key in ["map", "mode", "misc_params"] {
            if let Some(s) = field(v, key) {
                params.push((key.to_string(), Json::str(string(s, &format!("{at}.{key}"))?)));
            }
        }
        if let Some(m) = field(v, "custom_data") {
            params.push(("custom_data".to_string(), string_map_json(m, &format!("{at}.custom_data"))?));
        }
        out.push(("auto_startup_params".into(), Json::Obj(params)));
    }
    Ok(Json::Obj(out))
}

fn platform_template(what: &str, v: &Json) -> Result<Json, String> {
    let Json::Obj(_) = v else { return Err(format!("{what}: expected an object")) };
    let mut out = Vec::new();
    for key in ["platform", "platform_session_type"] {
        if let Some(s) = field(v, key) {
            out.push((key.to_string(), Json::str(string(s, &format!("{what}.{key}"))?)));
        }
    }
    for key in ["platform_id", "max_players"] {
        if let Some(n) = field(v, key) {
            let n = n.as_i64().filter(|n| (0..=MAX_INT).contains(n)).ok_or_else(|| format!("{what}.{key}: expected a whole number from 0 to {MAX_INT}"))?;
            out.push((key.to_string(), Json::int(n)));
        }
    }
    if let Some(m) = field(v, "custom_data") {
        out.push(("custom_data".to_string(), string_map_json(m, &format!("{what}.custom_data"))?));
    }
    Ok(Json::Obj(out))
}

/// Checks a harvested file's text, by its file name: `template.json` (`templates_value`),
/// `kv.json` (`kv_value`), `regions.json` (`regions_value`) or `instance.json`
/// (`instance_value`). Err says why it can't be used.
pub fn check_harvested(file: &str, text: &str) -> Result<(), String> {
    let v = Json::parse(text.trim_start_matches('\u{feff}')).ok_or("isn't valid JSON (or nests too deeply)")?;
    match file {
        "template.json" => templates_value(&v).map(drop),
        "kv.json" => kv_value(&v).map(drop),
        "regions.json" => regions_value(&v).map(drop),
        "instance.json" => instance_value(&v).map(drop),
        _ => Err(format!("{file} isn't a harvested file")),
    }
}
