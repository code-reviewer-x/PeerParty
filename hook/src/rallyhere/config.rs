//! The game's RallyHere config file: `%LOCALAPPDATA%\peerparty\rallyhere\<exe stem, lowercase>\config.json`
//! (`PEERPARTY_RALLYHERE_DIR` names the folder instead).
//!
//! ```json
//! { "hosts": ["api.example.test"],
//!   "templates": { "example_party": { "can_be_created_by_players_directly": true } },
//!   "kv": { "example_key": "example value" },
//!   "instance": {
//!     "instance_startup_params": { "map": "", "misc_params": "", "mode": "" },
//!     "join_params": { "custom_data": {}, "private_conn_str": "", "public_conn_str": "" } } }
//! ```
//!
//! - `hosts`: the title's RallyHere API hosts (`PEERPARTY_RALLYHERE_HOSTS` replaces them).
//! - `templates`: session templates by session type, RallyHere's template fields.
//! - `kv`: the key-value pairs the config service answers.
//! - `instance`: the title's defaults for the player-hosted instance (`API §6.4`), both
//!   objects optional. `instance_startup_params`: each value a string or a map of strings.
//!   `join_params`: `public_conn_str` and `private_conn_str` strings, `custom_data` a map of
//!   strings (other keys ignored). The instance is rendered with these keys always present:
//!   the game's own values win, a default fills in what it did not send.
//!
//! The file is a player's, so it is untrusted: read once, at most `MAX_FILE` bytes, with
//! bounded counts and strings, and any wrong type refuses the whole file (one log line says
//! why; the layer then stays off, `refused`). Unknown keys and keys starting with `_`
//! (notes) are ignored.
//!
//! The validators of `templates`, `kv` and `instance` (and of a region list, which the file
//! has no key for) also read and check the files harvest.rs keeps from the real service.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::log;
use crate::util::local_store;

// The file's shape and checks are shared with the launcher, which checks the files it
// fetches for the cache with them (protocol/src/gamedata/rallyhere.rs).
pub use peerparty_protocol::gamedata::rallyhere::*;
#[cfg(test)]
use crate::util::json::Json;

/// The game's RallyHere folder: `PEERPARTY_RALLYHERE_DIR`, else
/// `%LOCALAPPDATA%\peerparty\rallyhere\<exe stem, lowercase>`.
pub fn folder() -> Option<PathBuf> {
    crate::config::HookConfig::global().rallyhere_dir().or_else(|| local_store::game_dir("rallyhere"))
}

/// The launcher's cache of the game's files, fetched from the player's sources:
/// `%LOCALAPPDATA%\peerparty\remote\rallyhere\<exe stem, lowercase>`. None when
/// `PEERPARTY_RALLYHERE_DIR` names the folder (then only that folder is read). The hook only
/// reads it, and only after the player's own folder (`config.json`, then `harvested\`).
pub fn cached_folder() -> Option<PathBuf> {
    if crate::config::HookConfig::global().rallyhere_dir().is_some() {
        return None;
    }
    Some(local_store::peerparty_dir()?.join("remote").join("rallyhere").join(local_store::game_name()?))
}

/// The player's config.json as the process reads it: once, at first use, with whether it
/// was refused. Missing or refused gives an empty one.
fn load_local() -> &'static (Config, bool) {
    static CONFIG: OnceLock<(Config, bool)> = OnceLock::new();
    CONFIG.get_or_init(|| match folder().map(|dir| load_from(&dir, "config.json")) {
        Some(Ok(c)) => (c, false),
        Some(Err(())) => (Config::default(), true),
        None => (Config::default(), false),
    })
}

/// The player's config.json (`load_local`): empty when it is missing or refused.
pub fn load() -> &'static Config {
    &load_local().0
}

/// Whether the player's config.json is there but was refused: the layer then stays off,
/// whatever else would give it hosts (mod.rs `hosts`).
pub fn refused() -> bool {
    load_local().1
}

/// The cached config.json (`cached_folder`), read like the player's own, once. It counts
/// only where the player's config.json and harvested files have nothing.
pub fn load_cached() -> &'static Config {
    static CONFIG: OnceLock<Config> = OnceLock::new();
    CONFIG.get_or_init(|| cached_folder().and_then(|dir| load_from(&dir, "cached config.json").ok()).unwrap_or_default())
}

/// `dir`'s config.json; `what` names it in the log. Missing gives an empty config; a file
/// that is there but unreadable or refused is `Err`, after one log line saying why.
pub fn load_from(dir: &Path, what: &str) -> Result<Config, ()> {
    match read(&dir.join("config.json")) {
        Ok(Some(c)) => {
            log!("rallyhere: {what} read: {} hosts, {} templates, {} kv entries", c.hosts.len(), c.templates.len(), c.kv.len());
            Ok(c)
        }
        Ok(None) => Ok(Config::default()),
        Err(e) => {
            log!("rallyhere: {what} refused: {e}");
            Err(())
        }
    }
}

/// The file at `path`: None when it doesn't exist, Err (what is wrong) when it can't be used.
pub fn read(path: &Path) -> Result<Option<Config>, String> {
    Ok(match read_text(path)? {
        Some(text) => Some(parse(&text)?),
        None => None,
    })
}

/// The text of the file at `path`, at most `MAX_FILE` bytes of UTF-8: None when it doesn't
/// exist, Err (what is wrong) when it can't be used.
pub fn read_text(path: &Path) -> Result<Option<String>, String> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("can't be opened ({:?})", e.kind())),
    };
    let mut bytes = Vec::new();
    file.take(MAX_FILE + 1).read_to_end(&mut bytes).map_err(|e| format!("can't be read ({:?})", e.kind()))?;
    if bytes.len() as u64 > MAX_FILE {
        return Err(format!("is larger than {} KiB", MAX_FILE / 1024));
    }
    String::from_utf8(bytes).map(Some).map_err(|_| "isn't UTF-8 text".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"{
      "_note": "made-up data",
      "hosts": ["Api.Example.Test:443", "api.example.test.", "other.example.test"],
      "unknown": [1, 2],
      "templates": {
        "_note": "ignored",
        "example_party": { "engine_session_type": "example_party", "can_join_matchmaking": true,
          "can_be_created_by_players_directly": true, "notify_on_reservation": false, "mystery": 1 },
        "example_match": { "engine_session_type": "example_match", "players_per_team": 4, "num_teams": 2,
          "player_visibility": "TEAM", "custom_data": { "k": "v" },
          "platform_templates": { "Steam": { "platform_id": 5, "platform": "Steam", "platform_session_type": "example_match" } },
          "auto_startup_params": { "map": "m", "mode": "x", "misc_params": "", "custom_data": {} } }
      },
      "kv": { "_c": "note", "example_key": "example value" }
    }"#;

    #[test]
    fn a_valid_file_is_read() {
        let c = parse(EXAMPLE).unwrap();
        assert_eq!(c.hosts, ["api.example.test", "other.example.test"], "normalized, once each");
        assert_eq!(c.templates.len(), 2, "the note is no template");
        let party = &c.templates[0];
        assert_eq!(party.0, "example_party");
        assert_eq!(party.1.get("can_join_matchmaking"), &Json::Bool(true));
        assert!(party.1.get("mystery").is_null(), "unknown template fields are dropped");
        let m = &c.templates[1].1;
        assert_eq!(m.get("players_per_team").as_i64(), Some(4));
        assert_eq!(m.get("platform_templates").get("Steam").get("platform_id").as_i64(), Some(5));
        assert_eq!(m.get("custom_data").get("k").as_str(), Some("v"));
        assert_eq!(c.kv, [("example_key".to_string(), "example value".to_string())]);
    }

    #[test]
    fn the_example_config_loads() {
        let c = parse(include_str!("../../../docs/examples/rallyhere/config.json")).expect("the example loads");
        assert_eq!(c.hosts, ["api.example-game.invalid"]);
        assert_eq!(c.templates.len(), 2, "the _note is no template");
        assert_eq!(c.templates[0].0, "example_party");
        assert_eq!(c.kv, [("example_motd".to_string(), "Welcome to the example title".to_string())]);
        assert_eq!(c.instance.startup.len(), 3, "map, mode and misc_params");
        assert_eq!(c.instance.join.len(), 3, "custom_data and both connection strings");
    }

    #[test]
    fn instance_defaults_are_read_validated_and_bounded() {
        assert_eq!(parse("{}").unwrap().instance, InstanceDefaults::default(), "absent section = empty");
        assert_eq!(parse(r#"{"instance": {}}"#).unwrap().instance, InstanceDefaults::default());
        let c = parse(
            r#"{"instance": {"_note": "n", "unknown": 1,
              "instance_startup_params": {"_c": 1, "map": "", "misc_params": "", "mode": "", "extra": {"a": "b"}},
              "join_params": {"_c": 1, "custom_data": {"k": "v"}, "private_conn_str": "", "public_conn_str": "", "other": 5}}}"#,
        )
        .unwrap();
        assert_eq!(c.instance.startup.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), ["map", "misc_params", "mode", "extra"]);
        assert_eq!(c.instance.startup[0].1, Json::str(""));
        assert_eq!(c.instance.startup[3].1.get("a").as_str(), Some("b"));
        assert_eq!(c.instance.join.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(), ["custom_data", "private_conn_str", "public_conn_str"]);
        assert_eq!(c.instance.join[0].1.get("k").as_str(), Some("v"));
        assert!(parse(r#"{"instance": {"join_params": {}}}"#).unwrap().instance.join.is_empty(), "one object alone is fine");
    }

    #[test]
    fn instance_defaults_wrong_types_and_bounds_refuse_the_file() {
        assert!(refused(r#"{"instance": []}"#).starts_with("instance:"));
        assert!(refused(r#"{"instance": {"instance_startup_params": []}}"#).starts_with("instance.instance_startup_params:"));
        assert!(refused(r#"{"instance": {"instance_startup_params": {"map": 1}}}"#).starts_with("instance.instance_startup_params:"));
        assert!(refused(r#"{"instance": {"instance_startup_params": {"map": {"a": 1}}}}"#).starts_with("instance.instance_startup_params:"));
        assert!(refused(r#"{"instance": {"instance_startup_params": {"map": null}}}"#).starts_with("instance.instance_startup_params:"));
        assert!(refused(r#"{"instance": {"join_params": 1}}"#).starts_with("instance.join_params:"));
        assert!(refused(r#"{"instance": {"join_params": {"public_conn_str": 1}}}"#).starts_with("instance.join_params.public_conn_str:"));
        assert!(refused(r#"{"instance": {"join_params": {"private_conn_str": {}}}}"#).starts_with("instance.join_params.private_conn_str:"));
        assert!(refused(r#"{"instance": {"join_params": {"custom_data": "x"}}}"#).starts_with("instance.join_params.custom_data:"));
        assert!(refused(r#"{"instance": {"join_params": {"custom_data": {"a": 1}}}}"#).starts_with("instance.join_params.custom_data:"));

        let startup = |n: usize| format!("{{\"instance\": {{\"instance_startup_params\": {{{}}}}}}}", (0..n).map(|i| format!("\"k{i}\": \"v\"")).collect::<Vec<_>>().join(","));
        assert_eq!(parse(&startup(MAX_KV)).unwrap().instance.startup.len(), MAX_KV);
        assert!(refused(&startup(MAX_KV + 1)).contains("more than"));
        let custom = |n: usize| format!("{{\"instance\": {{\"join_params\": {{\"custom_data\": {{{}}}}}}}}}", (0..n).map(|i| format!("\"k{i}\": \"v\"")).collect::<Vec<_>>().join(","));
        assert_eq!(parse(&custom(MAX_KV)).unwrap().instance.join[0].1.as_obj().len(), MAX_KV);
        assert!(refused(&custom(MAX_KV + 1)).contains("more than"));

        let (long, max) = ("x".repeat(MAX_STR + 1), "x".repeat(MAX_STR));
        for field in [r#""instance_startup_params": {"map": "L"}"#, r#""instance_startup_params": {"L": "v"}"#, r#""instance_startup_params": {"m": {"a": "L"}}"#, r#""join_params": {"public_conn_str": "L"}"#, r#""join_params": {"custom_data": {"L": "v"}}"#] {
            assert!(refused(&format!("{{\"instance\": {{{}}}}}", field.replace('L', &long))).contains("longer"), "{field}");
            assert!(parse(&format!("{{\"instance\": {{{}}}}}", field.replace('L', &max))).is_ok(), "{field}");
        }
    }

    #[test]
    fn a_folders_config_loads_empty_when_missing_and_is_refused_when_wrong() {
        let dir = crate::rallyhere::tests_support::temp_dir("cfg-from");
        assert_eq!(load_from(&dir, "cached config.json"), Ok(Config::default()), "no file");
        std::fs::write(dir.join("config.json"), r#"{"hosts": ["api.example.test"]}"#).unwrap();
        assert_eq!(load_from(&dir, "cached config.json").unwrap().hosts, ["api.example.test"]);
        std::fs::write(dir.join("config.json"), vec![b' '; MAX_FILE as usize + 1]).unwrap();
        assert_eq!(load_from(&dir, "cached config.json"), Err(()), "a cached file is bounded like the player's");
        std::fs::write(dir.join("config.json"), r#"{"hosts": "api.example.test"}"#).unwrap();
        assert_eq!(load_from(&dir, "config.json"), Err(()), "a wrong type is refused, not read as empty");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_object_is_an_empty_config() {
        assert_eq!(parse("{}").unwrap(), Config::default());
        assert_eq!(parse("\u{feff}{}").unwrap(), Config::default(), "a byte order mark is fine");
    }

    fn refused(text: &str) -> String {
        parse(text).expect_err(text)
    }

    #[test]
    fn wrong_types_refuse_the_file_and_name_the_problem() {
        assert!(refused("[]").contains("object"));
        assert!(refused("nope").contains("JSON"));
        assert!(refused(r#"{"hosts": "a"}"#).starts_with("hosts:"));
        assert!(refused(r#"{"hosts": [1]}"#).starts_with("hosts:"));
        assert!(refused(r#"{"templates": []}"#).starts_with("templates:"));
        assert!(refused(r#"{"templates": {"t": 1}}"#).starts_with("templates.t:"));
        assert!(refused(r#"{"templates": {"t": {"joinable": "yes"}}}"#).starts_with("templates.t.joinable:"));
        assert!(refused(r#"{"templates": {"t": {"num_teams": "2"}}}"#).starts_with("templates.t.num_teams:"));
        assert!(refused(r#"{"templates": {"t": {"num_teams": -1}}}"#).starts_with("templates.t.num_teams:"));
        assert!(refused(r#"{"templates": {"t": {"num_teams": 1.5}}}"#).starts_with("templates.t.num_teams:"));
        assert!(refused(r#"{"templates": {"t": {"player_visibility": "ALMOST"}}}"#).starts_with("templates.t.player_visibility:"));
        assert!(refused(r#"{"templates": {"t": {"custom_data": {"a": 1}}}}"#).starts_with("templates.t.custom_data:"));
        assert!(refused(r#"{"templates": {"t": {"platform_templates": {"Steam": {"platform_id": "5"}}}}}"#).contains("platform_id"));
        assert!(refused(r#"{"templates": {"t": {"auto_startup_params": []}}}"#).contains("auto_startup_params"));
        assert!(refused(r#"{"kv": {"a": 1}}"#).starts_with("kv:"));
        assert!(refused(r#"{"kv": []}"#).starts_with("kv:"));
    }

    #[test]
    fn every_bound_refuses_the_file() {
        let hosts: Vec<String> = (0..=MAX_HOSTS).map(|i| format!("\"h{i}.example.test\"")).collect();
        assert!(refused(&format!("{{\"hosts\": [{}]}}", hosts.join(","))).contains("hosts"));
        let ok: Vec<String> = (0..MAX_HOSTS).map(|i| format!("\"h{i}.example.test\"")).collect();
        assert_eq!(parse(&format!("{{\"hosts\": [{}]}}", ok.join(","))).unwrap().hosts.len(), MAX_HOSTS);

        let templates = |n: usize| format!("{{\"templates\": {{{}}}}}", (0..n).map(|i| format!("\"t{i}\": {{}}")).collect::<Vec<_>>().join(","));
        assert_eq!(parse(&templates(MAX_TEMPLATES)).unwrap().templates.len(), MAX_TEMPLATES);
        assert!(refused(&templates(MAX_TEMPLATES + 1)).contains("templates"));

        let kv = |n: usize| format!("{{\"kv\": {{{}}}}}", (0..n).map(|i| format!("\"k{i}\": \"v\"")).collect::<Vec<_>>().join(","));
        assert_eq!(parse(&kv(MAX_KV)).unwrap().kv.len(), MAX_KV);
        assert!(refused(&kv(MAX_KV + 1)).contains("kv"));

        let long = "x".repeat(MAX_STR + 1);
        assert!(refused(&format!("{{\"hosts\": [\"{long}\"]}}")).contains("longer"));
        assert!(refused(&format!("{{\"kv\": {{\"k\": \"{long}\"}}}}")).contains("longer"));
        assert!(refused(&format!("{{\"kv\": {{\"{long}\": \"v\"}}}}")).contains("longer"));
        assert!(refused(&format!("{{\"templates\": {{\"{long}\": {{}}}}}}")).contains("longer"));
        assert!(refused(&format!("{{\"templates\": {{\"t\": {{\"session_type\": \"{long}\"}}}}}}")).contains("longer"));
        let max = "x".repeat(MAX_STR);
        assert!(parse(&format!("{{\"kv\": {{\"k\": \"{max}\"}}}}")).is_ok());
    }

    #[test]
    fn a_file_is_read_from_disk_with_its_size_bound() {
        let dir = std::env::temp_dir().join(format!("peerparty-rallyhere-config-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        assert_eq!(read(&path), Ok(None), "no file is no config and no complaint");
        std::fs::write(&path, EXAMPLE).unwrap();
        assert_eq!(read(&path).unwrap().unwrap().hosts.len(), 2);
        let padding = " ".repeat(MAX_FILE as usize);
        std::fs::write(&path, format!("{{}}{padding}")).unwrap();
        assert!(read(&path).unwrap_err().contains("larger"));
        std::fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
        assert!(read(&path).unwrap_err().contains("UTF-8"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_region_list_is_validated_and_bounded() {
        let regions = |text: &str| regions_value(&Json::parse(text).unwrap());
        let r = regions(r#"[{"region_id": "eu", "sort_order": -2, "custom_only": true, "description": "d", "ip": "x"}]"#).unwrap();
        assert_eq!(Json::Arr(r).to_string(), r#"[{"region_id":"eu","sort_order":-2,"custom_only":true,"description":"d"}]"#, "unknown fields dropped");
        for bad in [r#"{}"#, r#"[1]"#, r#"[{}]"#, r#"[{"region_id": ""}]"#, r#"[{"region_id": 1}]"#, r#"[{"region_id": "a", "sort_order": "1"}]"#, r#"[{"region_id": "a", "custom_only": 1}]"#, r#"[{"region_id": "a", "description": null}]"#] {
            assert!(regions(bad).is_err(), "{bad}");
        }
        let list = |n: usize| format!("[{}]", (0..n).map(|i| format!("{{\"region_id\": \"r{i}\"}}")).collect::<Vec<_>>().join(","));
        assert_eq!(regions(&list(MAX_REGIONS)).unwrap().len(), MAX_REGIONS);
        assert!(regions(&list(MAX_REGIONS + 1)).is_err());
        assert!(regions(&format!(r#"[{{"region_id": "{}"}}]"#, "x".repeat(MAX_STR + 1))).is_err());
    }

    #[test]
    fn hosts_are_compared_without_port_dot_or_case() {
        assert_eq!(normalize("API.Example.Test:8443"), "api.example.test");
        assert_eq!(normalize("api.example.test."), "api.example.test");
        assert_eq!(normalize(" "), "");
    }
}
