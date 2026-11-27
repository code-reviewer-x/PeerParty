//! RallyHere's inventory service (`/inventory/...`): every inventory route of the stand-in,
//! behind one entry point (`handle`), and nothing else in the layer knows more of it. A fork
//! that wants to answer inventory differently may replace this file alone, as long as it
//! keeps `handle` with the same signature.
//!
//! Store checks stay with the store: reads answer empty, an entitlement check completes
//! with nothing granted, orders are empty, and every other write (orders, item changes, key
//! claims, catalog purchases) is refused as a store call, the way PlayFab's stand-in
//! refuses its own. Nothing here reports an item or an entitlement as owned.

use std::sync::{LazyLock, Mutex};

use crate::log;
use crate::util::encoding;
use crate::util::json::Json;

use super::{error_body, query};

/// What the inventory session calls keep, in memory: (session id, platform).
#[derive(Default)]
pub struct Inventory {
    session: Option<(String, String)>,
}

static INVENTORY: LazyLock<Mutex<Inventory>> = LazyLock::new(Default::default);

/// Answers one `/inventory/` request: (HTTP status, JSON body). `path` carries the query,
/// `body` is the request's JSON (`Json::Null` when it has none), `player` is the caller's
/// player uuid.
pub fn handle(method: &str, path: &str, body: &Json, player: &str) -> (u16, String) {
    handle_in(&mut crate::sys::lock(&INVENTORY), method, path, body, player)
}

fn ok(status: u16, j: Json) -> (u16, String) {
    (status, j.to_string())
}

fn handle_in(inv: &mut Inventory, method: &str, path: &str, body: &Json, _player: &str) -> (u16, String) {
    let bare = path.split('?').next().unwrap_or_default();
    let segs: Vec<&str> = bare.trim_matches('/').split('/').collect();
    // inventory / v2 / player / {uuid} / <what> [/ <id>]
    let what: &[&str] = if segs.len() >= 5 && segs[1] == "v2" && segs[2] == "player" { &segs[4..] } else { &[] };
    match (method, what) {
        ("GET", ["inventory"]) => ok(200, Json::obj(vec![("inventory", Json::obj(vec![("items", Json::Obj(Vec::new()))]))])),
        ("POST", ["session"]) => {
            let platform = body.get("session_platform").as_str().unwrap_or("Anon").chars().take(64).collect::<String>();
            let id = inv.session.as_ref().map(|s| s.0.clone()).unwrap_or_else(encoding::uuid);
            inv.session = Some((id.clone(), platform.clone()));
            ok(202, session_json(&id, &platform))
        }
        ("GET", ["session"]) => match &inv.session {
            Some((id, platform)) => ok(200, session_json(id, platform)),
            None => (404, error_body(true, "no_inventory_session", "no inventory session was started")),
        },
        ("POST", ["entitlement"]) => entitlement(body),
        ("GET", ["order"]) => {
            let q = query(path);
            let mut page = Vec::new();
            if let Some((_, v)) = q.iter().find(|(k, _)| k == "starting_position") {
                page.push(("starting_position", Json::str(v.chars().take(64).collect::<String>())));
            }
            let now = crate::util::time::millis(std::time::SystemTime::now());
            page.push(("cursor", Json::str(encoding::base64(now.to_string().as_bytes()))));
            ok(200, Json::obj(vec![("page", Json::obj(page))]))
        }
        ("GET", ["order", _]) => (404, error_body(true, "order_not_found", "no such order")),
        ("GET", _) => super::not_implemented(method, "", bare),
        _ => {
            // A write the store owns. Refused, and said so in the log: not a gap.
            crate::log::throttled(&format!("rallyhere store {method} {bare}"), 3, |n| log!("rallyhere {method} {bare} n={n}: a store call, refused"));
            (403, error_body(true, "insufficient_permissions", "the store isn't reachable"))
        }
    }
}

fn session_json(id: &str, platform: &str) -> Json {
    Json::obj(vec![("session_id", Json::str(id)), ("session_platform", Json::str(platform))])
}

/// Entitlement processing completes and grants nothing.
fn entitlement(body: &Json) -> (u16, String) {
    let text = |k: &str| Json::str(body.get(k).as_str().unwrap_or_default().chars().take(256).collect::<String>());
    match body.get("platform_id").as_str().unwrap_or_default().to_ascii_lowercase().as_str() {
        "twitch" => return (409, error_body(true, "not_linked", "the platform account isn't linked")),
        "amazon" => return (409, error_body(true, "missing_portal_information", "the platform account isn't linked")),
        _ => {}
    }
    ok(
        200,
        Json::obj(vec![
            ("request_id", Json::str(encoding::uuid())),
            ("client_type", text("client_type")),
            ("transaction_id", text("transaction_id")),
            ("platform_region", text("platform_region")),
            ("status", Json::str("COMPLETED")),
            ("client_entitlements", Json::Arr(Vec::new())),
            ("server_entitlements", Json::Arr(Vec::new())),
            ("platform_id", text("platform_id")),
            ("platform_user_id", text("platform_user_id")),
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "/inventory/v2/player/00000000-0000-4000-8000-000000000001";

    fn call(inv: &mut Inventory, method: &str, what: &str, body: &str) -> (u16, Json) {
        let (s, b) = handle_in(inv, method, &format!("{P}{what}"), &Json::parse(body).unwrap_or(Json::Null), "me");
        (s, Json::parse(&b).unwrap_or(Json::Null))
    }

    #[test]
    fn reads_answer_empty() {
        let mut inv = Inventory::default();
        let (s, j) = call(&mut inv, "GET", "/inventory", "");
        assert_eq!(s, 200);
        assert!(j.get("inventory").get("items").as_obj().is_empty());
        let (s, j) = call(&mut inv, "GET", "/order?starting_position=2025-01-02T03:04:05Z", "");
        assert_eq!(s, 200);
        assert!(j.get("data").is_null(), "no orders");
        assert!(j.get("page").get("cursor").as_str().is_some_and(|c| encoding::base64_decode(c).is_some()));
        assert_eq!(j.get("page").get("starting_position").as_str(), Some("2025-01-02T03:04:05Z"));
        let (s, j) = call(&mut inv, "GET", "/order/abc", "");
        assert_eq!((s, j.get("error_code").as_str()), (404, Some("order_not_found")));
    }

    #[test]
    fn the_session_is_kept_in_memory() {
        let mut inv = Inventory::default();
        let (s, j) = call(&mut inv, "GET", "/session", "");
        assert_eq!((s, j.get("error_code").as_str()), (404, Some("no_inventory_session")));
        let (s, j) = call(&mut inv, "POST", "/session", r#"{"session_platform":"Steam"}"#);
        assert_eq!((s, j.get("session_platform").as_str()), (202, Some("Steam")));
        let id = j.get("session_id").as_str().unwrap().to_string();
        let (s, j) = call(&mut inv, "GET", "/session", "");
        assert_eq!((s, j.get("session_id").as_str(), j.get("session_platform").as_str()), (200, Some(id.as_str()), Some("Steam")));
    }

    #[test]
    fn an_entitlement_check_completes_and_grants_nothing() {
        let mut inv = Inventory::default();
        let body = r#"{"transaction_id":"t1","platform_token":"x","platform_id":"Steam","platform_region":"eu","client_type":"WIN",
            "entitlements":[{"platform_sku":"sku","platform_entitlement_id":"e","quantity":3}]}"#;
        let (s, j) = call(&mut inv, "POST", "/entitlement", body);
        assert_eq!(s, 200);
        assert_eq!(j.get("status").as_str(), Some("COMPLETED"));
        assert_eq!(j.get("transaction_id").as_str(), Some("t1"));
        assert!(j.get("client_entitlements").as_arr().is_empty());
        assert!(j.get("server_entitlements").as_arr().is_empty());
        let (s, j) = call(&mut inv, "POST", "/entitlement", r#"{"platform_id":"Twitch"}"#);
        assert_eq!((s, j.get("error_code").as_str()), (409, Some("not_linked")));
        let (s, j) = call(&mut inv, "POST", "/entitlement", r#"{"platform_id":"amazon"}"#);
        assert_eq!((s, j.get("error_code").as_str()), (409, Some("missing_portal_information")));
    }

    /// The store-check test: nothing here may make a purchase, an order or an item exist.
    #[test]
    fn store_writes_are_refused() {
        let mut inv = Inventory::default();
        for (method, what) in [
            ("POST", "/order"),
            ("POST", "/order/abc/cancel"),
            ("PUT", "/inventory/item-1"),
            ("PATCH", "/inventory/item-1"),
            ("DELETE", "/inventory/item-1"),
            ("POST", "/key-claim"),
            ("POST", "/catalog/purchase"),
        ] {
            let (s, j) = call(&mut inv, method, what, r#"{"count":5}"#);
            assert_eq!((s, j.get("error_code").as_str()), (403, Some("insufficient_permissions")), "{method} {what}");
            assert_eq!(j.get("auth_success"), &Json::Bool(true));
        }
        let (_, j) = call(&mut inv, "GET", "/inventory", "");
        assert!(j.get("inventory").get("items").as_obj().is_empty(), "still nothing owned");
    }

    #[test]
    fn an_unknown_read_is_a_gap() {
        let mut inv = Inventory::default();
        let (s, j) = call(&mut inv, "GET", "/catalog", "");
        assert_eq!((s, j.get("error_code").as_str()), (404, Some("not_implemented")));
    }
}
