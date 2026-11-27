//! Identity: the player ids, sign-in (`/users/v1/login`, always granted), the tokens it
//! issues and the bearer check, logout and a player's links.
//!
//! Every ID derives from the LAN PeerId, so any copy computes any player's ids and maps
//! them back by comparing against the peers it knows (`peer_of`, like the Unity stand-in's).

use peerparty_core::PeerId;

use super::{Reply, State, World};
use crate::util::encoding;
use crate::util::json::Json;
use crate::util::time::unix_now;

/// How long an access token lives, seconds.
pub const TOKEN_TTL: i64 = 21600;
/// The most tokens of each kind remembered (the oldest are forgotten).
const MAX_TOKENS: usize = 64;

/// The permissions sign-in grants (`API §3.2`): not game-specific, returned as they are.
const PERMISSIONS: &str = "session:vivox:kick:self, match:player:self:read, session:read:self, \
    inv:read_order:self, rank:read:self, notification:player:self:*, leaderboard:read:global, rank:read:config, \
    session:create, session-player-audit:read:self, match:pex:client:write, session:update:browser, \
    session:read-player:self, session:vivox:join, session:backfill:player-host, inv:key_claim:self, \
    session:read:config, session:read:event, session:update:platform, leaderboard:read:friends:self, \
    session-audit:read:self, inv:read_catalog, session:vivox:mute:self, refer:read:self, inv:read_session:self, \
    role:read, session:vivox:login, refer:set:self, setting-config:read, session:update-player:as-leader, \
    session:instance:health, sanction:report:create:self, match:match:edit:authority, custom_api:send, \
    sanction:report:read:source-self, inv:key_entitlements:self, inv:platform_entitlements:self, \
    setting:write:self, deserter:read:config, session:promote:self, deserter:read:self, session-audit:update:all, \
    session:read:permission:active, session:vivox:join_muted, inv:create_session:self, session:read:platform, \
    inv:marketing:read, inv:read_inv:any, leaderboard:read:config, notification:playerid:self:*, \
    session:voip:epic:join, session-player-audit:update:self, inv:create_order:player:self, setting:read, \
    match:match:player:read, session:shortcode:active, session:update:self, session:update-player:self, \
    session:read:browser";

pub fn permissions() -> Vec<&'static str> {
    PERMISSIONS.split(',').map(str::trim).collect()
}

/// A platform a sign-in names (`API §2`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Platform {
    pub name: &'static str,
    /// The numeric `portal_id`, for the platforms whose number is known.
    pub portal_id: Option<u32>,
}

pub const ANON: Platform = Platform { name: "Anon", portal_id: None };
pub const STEAM: Platform = Platform { name: "Steam", portal_id: Some(5) };

/// The platform a grant names; an unknown grant is `Anon`.
pub fn platform_of(grant: &str) -> Platform {
    let (name, portal_id) = match grant.to_ascii_lowercase().as_str() {
        "steam" => ("Steam", Some(5)),
        "xboxlive" | "xbox" => ("XboxLive", Some(10)),
        "psn" => ("PSN", Some(9)),
        "epic" => ("Epic", Some(28)),
        "nintendonaid" => ("NintendoNAID", None),
        "nintendoswitch" => ("NintendoSwitch", None),
        "nintendoppid" => ("NintendoPPID", None),
        "google" => ("Google", None),
        "googleplay" => ("GooglePlay", None),
        "apple" => ("Apple", None),
        "amazon" => ("Amazon", None),
        "twitch" => ("Twitch", None),
        "basic" => ("Basic", None),
        "rallyhere" => ("RallyHere", None),
        "legacyname" => ("LegacyName", None),
        _ => ("Anon", None),
    };
    Platform { name, portal_id }
}

// ---- ids ----

fn as_uuid(mut b: [u8; 16]) -> String {
    b[6] = b[6] & 0x0f | 0x40;
    b[8] = b[8] & 0x3f | 0x80;
    encoding::guid(&b)
}

/// A peer's player uuid: its 16 bytes as a version 4 UUID.
pub fn player_uuid(peer: PeerId) -> String {
    as_uuid(peer.0)
}

/// A peer's numeric player id: positive, 31 bits of the id.
pub fn player_id(peer: PeerId) -> i64 {
    let n = u32::from_be_bytes([peer.0[0], peer.0[1], peer.0[2], peer.0[3]]) & 0x7fff_ffff;
    i64::from(n.max(1))
}

/// A peer's person id: another UUID of its own, derived from the same bytes.
pub fn person_id(peer: PeerId) -> String {
    let mut b = peer.0;
    for (i, x) in b.iter_mut().enumerate() {
        *x = x.rotate_left(3) ^ (0xa5 ^ i as u8);
    }
    as_uuid(b)
}

/// A uuid that stands for the title itself (publisher, tenant...), the same in every copy.
fn title_uuid(tag: u8) -> String {
    as_uuid([tag; 16])
}

/// The LAN peer (us included) whose player uuid this is.
pub fn peer_of(world: &World, uuid: &str) -> Option<PeerId> {
    world.everyone().map(|(p, _)| p).find(|p| player_uuid(*p).eq_ignore_ascii_case(uuid))
}

// ---- tokens ----

/// The access token: header and payload as a JWT's, no signature (`alg` is `none`).
fn access_token(world: &World, platform: Platform, portal_user_id: &str, iat: i64) -> String {
    let b64 = |j: Json| encoding::base64url(j.to_string().as_bytes());
    let header = Json::obj(vec![("alg", Json::str("none")), ("kid", Json::str("peerparty")), ("typ", Json::str("at+JWT"))]);
    format!("{}.{}.", b64(header), b64(claims(world, platform, portal_user_id, iat)))
}

fn claims(world: &World, platform: Platform, portal_user_id: &str, iat: i64) -> Json {
    let mut c = vec![
        ("active_player_id", Json::int(player_id(world.me))),
        ("active_player_uuid", Json::str(player_uuid(world.me))),
        ("person_id", Json::str(person_id(world.me))),
        ("display_name", Json::str(&world.name)),
        ("platform", Json::str(platform.name)),
    ];
    if let Some(id) = platform.portal_id {
        c.push(("portal_id", Json::int(id.into())));
    }
    c.extend([
        ("portal_user_id", Json::str(portal_user_id)),
        ("permissions", Json::Arr(permissions().into_iter().map(Json::str).collect())),
        ("publisher_uuid", Json::str(title_uuid(0x11))),
        ("tenant_uuid", Json::str(title_uuid(0x22))),
        ("config_elector_uuid", Json::str(title_uuid(0x33))),
        ("client_uuid", Json::str(title_uuid(0x44))),
        ("azp", Json::str(title_uuid(0x44))),
        ("iss", Json::str("peerparty")),
        ("jti", Json::str(encoding::uuid())),
        ("iat", Json::int(iat)),
        ("nbf", Json::int(iat)),
        ("exp", Json::int(iat + TOKEN_TTL)),
        ("rhv", Json::int(1)),
    ]);
    Json::obj(c)
}

fn remember(list: &mut Vec<String>, token: &str) {
    if list.len() >= MAX_TOKENS {
        list.remove(0);
    }
    list.push(token.to_string());
}

/// The bearer check: only a `Bearer` token this copy didn't issue gets the authentication
/// error. No header, `Basic` (the game's client credentials on login) or any other scheme passes.
pub fn check_bearer(st: &State, header: Option<&str>) -> Option<Reply> {
    let h = header?.trim();
    let token = h.get(..7).filter(|p| p.eq_ignore_ascii_case("bearer "))?;
    let token = h[token.len()..].trim();
    if st.access.iter().any(|a| a == token) {
        return None;
    }
    Some(Reply::err(401, "error_no_auth", "the token was not issued here", false))
}

// ---- routes ----

/// `POST /users/v1/login`: every grant succeeds, always as this copy's player.
pub fn login(world: &World, st: &mut State, body: &Json) -> Reply {
    let grant = body.get("grant_type").as_str().unwrap_or_default().to_ascii_lowercase();
    let platform = if grant == "refresh" {
        // The platform the refreshed sign-in had, else the last one this copy signed in with.
        let token = body.get("portal_access_token").as_str().or_else(|| body.get("refresh_token").as_str()).unwrap_or_default();
        st.refresh.iter().find(|(t, _)| t == token).map(|(_, p)| *p).or(st.platform).unwrap_or(ANON)
    } else {
        platform_of(&grant)
    };
    st.platform = Some(platform);
    let portal_user_id = portal_user_id(world.me, platform);
    st.portal_user_id = portal_user_id.clone();
    let access = access_token(world, platform, &portal_user_id, unix_now());
    let refresh = encoding::uuid();
    remember(&mut st.access, &access);
    if st.refresh.len() >= MAX_TOKENS {
        st.refresh.remove(0);
    }
    st.refresh.push((refresh.clone(), platform));
    st.publish();
    let mut j = vec![
        ("permissions", Json::Arr(permissions().into_iter().map(Json::str).collect())),
        ("active_player_id", Json::int(player_id(world.me))),
        ("active_player_uuid", Json::str(player_uuid(world.me))),
        ("platform", Json::str(platform.name)),
    ];
    if let Some(id) = platform.portal_id {
        j.push(("portal_id", Json::int(id.into())));
    }
    j.extend([
        ("portal_user_id", Json::str(portal_user_id)),
        ("display_name", Json::str(&world.name)),
        ("person_id", Json::str(person_id(world.me))),
        ("access_token", Json::str(access)),
        ("refresh_token", Json::str(refresh)),
        ("publisher_uuid", Json::str(title_uuid(0x11))),
        ("tenant_uuid", Json::str(title_uuid(0x22))),
        ("config_elector_uuid", Json::str(title_uuid(0x33))),
        ("client_uuid", Json::str(title_uuid(0x44))),
        ("client_id", Json::str(title_uuid(0x44))),
        ("token_type", Json::str("Bearer")),
        ("expires_in", Json::int(TOKEN_TTL)),
    ]);
    Reply::ok(Json::obj(j))
}

/// The id a platform knows the player by: the SteamID on Steam, the player uuid elsewhere.
fn portal_user_id(peer: PeerId, platform: Platform) -> String {
    if platform == STEAM { crate::hub::accounts::steam_id(peer).to_string() } else { player_uuid(peer) }
}

/// `POST /users/v1/logout`.
pub fn logout(st: &mut State, body: &Json) -> Reply {
    let token = body.get("refresh_token").as_str().unwrap_or_default();
    match st.refresh.iter().position(|(t, _)| t == token) {
        Some(i) => {
            st.refresh.remove(i);
            Reply::ok(Json::Obj(Vec::new()))
        }
        None => Reply::err(404, "error_no_auth", "unknown refresh token", false),
    }
}

/// `GET /users/v2/player/{uuid}/links`: us, or a LAN player.
pub fn links(world: &World, st: &State, uuid: &str) -> Reply {
    let Some(peer) = peer_of(world, uuid) else {
        return Reply::err(404, "user_not_found", "no such player", true);
    };
    let (platform, portal_user_id) = world.identity_of(st, peer);
    let mut portal = vec![("portal_user_id", Json::str(portal_user_id))];
    if let Some(id) = platform.portal_id {
        portal.push(("portal_id", Json::int(id.into())));
    }
    portal.extend([
        ("platform", Json::str(platform.name)),
        ("display_name", Json::str(world.name_of(peer))),
        ("player_id", Json::int(player_id(peer))),
        ("player_uuid", Json::str(player_uuid(peer))),
    ]);
    Reply::ok(Json::obj(vec![
        (
            "player",
            Json::obj(vec![
                ("player_id", Json::int(player_id(peer))),
                ("player_uuid", Json::str(player_uuid(peer))),
                ("person_id", Json::str(person_id(peer))),
            ]),
        ),
        ("linked_portals", Json::Arr(vec![Json::obj(portal)])),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rallyhere::tests_support::{call, test_world};

    fn token_payload(token: &str) -> Json {
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "header.payload.signature");
        let header = Json::parse(&String::from_utf8(encoding::base64_decode(parts[0]).unwrap()).unwrap()).unwrap();
        assert_eq!(header.get("alg").as_str(), Some("none"));
        assert_eq!(header.get("typ").as_str(), Some("at+JWT"));
        Json::parse(&String::from_utf8(encoding::base64_decode(parts[1]).unwrap()).unwrap()).unwrap()
    }

    #[test]
    fn ids_derive_from_the_peer_id_and_map_back() {
        let a = PeerId([0xab; 16]);
        let b = PeerId([0x01; 16]);
        assert_eq!(player_uuid(a), player_uuid(a), "stable");
        assert_ne!(player_uuid(a), player_uuid(b));
        let u = player_uuid(a);
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4", "version");
        assert!(matches!(&u[19..20], "8" | "9" | "a" | "b"), "variant");
        assert!(player_id(a) > 0 && player_id(b) > 0 && player_id(a) <= i64::from(i32::MAX));
        assert_eq!(player_id(PeerId([0; 16])), 1, "never zero");
        assert_ne!(person_id(a), player_uuid(a));
        assert_eq!(person_id(a), person_id(a));
        // Any copy computes any player's uuid and finds the peer again, in any case.
        let world = test_world(a, "Me", &[(b, "Other")]);
        assert_eq!(peer_of(&world, &player_uuid(b).to_ascii_uppercase()), Some(b));
        assert_eq!(peer_of(&world, &player_uuid(a)), Some(a));
        assert_eq!(peer_of(&world, &player_uuid(PeerId([9; 16]))), None);
    }

    #[test]
    fn login_answers_the_player_and_its_claims_decode() {
        let me = PeerId([0x42; 16]);
        let world = test_world(me, "Player One", &[]);
        let mut st = State::new(None);
        let r = login(&world, &mut st, &Json::parse(r#"{"grant_type":"steam","portal_access_token":"abcd","portal_display_name":"x"}"#).unwrap());
        assert_eq!(r.status, 200);
        let j = Json::parse(&r.body).unwrap();
        assert_eq!(j.get("active_player_uuid").as_str(), Some(player_uuid(me).as_str()));
        assert_eq!(j.get("active_player_id").as_i64(), Some(player_id(me)));
        assert_eq!(j.get("person_id").as_str(), Some(person_id(me).as_str()));
        assert_eq!(j.get("display_name").as_str(), Some("Player One"));
        assert_eq!(j.get("platform").as_str(), Some("Steam"));
        assert_eq!(j.get("portal_id").as_i64(), Some(5));
        assert_eq!(j.get("portal_user_id").as_str(), Some(crate::hub::accounts::steam_id(me).to_string().as_str()));
        assert_eq!(j.get("token_type").as_str(), Some("Bearer"));
        assert_eq!(j.get("expires_in").as_i64(), Some(21600));
        assert_eq!(j.get("permissions").as_arr().len(), 59);
        let access = j.get("access_token").as_str().unwrap();
        let c = token_payload(access);
        for k in ["active_player_id", "active_player_uuid", "person_id", "display_name", "platform", "portal_id", "portal_user_id", "permissions", "publisher_uuid", "tenant_uuid", "config_elector_uuid", "client_uuid", "azp", "iss", "jti", "iat", "nbf", "exp", "rhv"] {
            assert!(!c.get(k).is_null(), "claim {k}");
        }
        assert_eq!(c.get("active_player_uuid").as_str(), j.get("active_player_uuid").as_str());
        assert_eq!(c.get("exp").as_i64().unwrap() - c.get("iat").as_i64().unwrap(), 21600);
        assert_eq!(c.get("rhv").as_i64(), Some(1));
        assert!(j.get("refresh_token").as_str().is_some_and(|t| t.len() == 36));
        assert!(st.access.iter().any(|t| t == access), "remembered");
    }

    #[test]
    fn every_grant_succeeds_with_its_platform_and_unknown_is_anon() {
        let world = test_world(PeerId([7; 16]), "Me", &[]);
        let mut st = State::new(None);
        for (grant, platform, id) in [("epic", "Epic", Some(28)), ("PSN", "PSN", Some(9)), ("xboxlive", "XboxLive", Some(10)), ("google", "Google", None), ("something-new", "Anon", None), ("", "Anon", None)] {
            let r = login(&world, &mut st, &Json::parse(&format!(r#"{{"grant_type":"{grant}"}}"#)).unwrap());
            assert_eq!(r.status, 200, "{grant}");
            let j = Json::parse(&r.body).unwrap();
            assert_eq!(j.get("platform").as_str(), Some(platform), "{grant}");
            assert_eq!(j.get("portal_id").as_i64(), id, "{grant}");
            assert_eq!(j.get("portal_user_id").as_str(), Some(player_uuid(world.me).as_str()));
            assert_eq!(j.get("active_player_uuid").as_str(), Some(player_uuid(world.me).as_str()), "always the same player");
        }
        // A body that isn't JSON at all still signs in.
        assert_eq!(login(&world, &mut st, &Json::Null).status, 200);
    }

    #[test]
    fn the_bearer_is_checked_against_the_tokens_issued() {
        let world = test_world(PeerId([7; 16]), "Me", &[]);
        let mut st = State::new(None);
        assert!(check_bearer(&st, None).is_none(), "no bearer passes");
        let bad = check_bearer(&st, Some("Bearer nope")).unwrap();
        assert_eq!(bad.status, 401);
        let j = Json::parse(&bad.body).unwrap();
        assert_eq!((j.get("auth_success"), j.get("error_code").as_str()), (&Json::Bool(false), Some("error_no_auth")));
        let r = login(&world, &mut st, &Json::parse(r#"{"grant_type":"steam"}"#).unwrap());
        let access = Json::parse(&r.body).unwrap().get("access_token").as_str().unwrap().to_string();
        assert!(check_bearer(&st, Some(&format!("Bearer {access}"))).is_none());
        assert!(check_bearer(&st, Some(&format!("bearer {access}"))).is_none());
        assert!(check_bearer(&st, Some("Bearer")).is_none() && check_bearer(&st, Some("Bearer ")).is_none(), "no token part: not a bearer to check");
        for other in ["Basic dGVzdDpzZWNyZXQ=", "basic dGVzdDpzZWNyZXQ=", "Digest x", &access] {
            assert!(check_bearer(&st, Some(other)).is_none(), "{other}");
        }
        // Through the router: any route gets the same answer.
        let (s, _) = call(&world, &mut st, "GET", "/config/v1/time/utc", Some("Bearer nope"), "");
        assert_eq!(s, 401);
        let (s, _) = call(&world, &mut st, "GET", "/config/v1/time/utc", Some(&format!("Bearer {access}")), "");
        assert_eq!(s, 200);
        // A login sent with the client's Basic credentials signs in, and so does any other route.
        let basic = Some("Basic dGVzdF9jbGllbnQ6c2VjcmV0");
        let (s, b) = call(&world, &mut st, "POST", "/users/v1/login", basic, r#"{"grant_type":"steam"}"#);
        assert_eq!(s, 200);
        assert!(Json::parse(&b).unwrap().get("access_token").as_str().is_some());
        assert_eq!(call(&world, &mut st, "GET", "/config/v1/time/utc", basic, "").0, 200, "Basic passes on any route");
        let (s, _) = call(&world, &mut st, "GET", "/session/v1/session/x", Some("Bearer nope"), "");
        assert_eq!(s, 401, "even an unknown route is checked first");
    }

    #[test]
    fn refresh_keeps_the_platform_and_logout_forgets_the_token() {
        let world = test_world(PeerId([7; 16]), "Me", &[]);
        let mut st = State::new(None);
        let first = Json::parse(&login(&world, &mut st, &Json::parse(r#"{"grant_type":"epic"}"#).unwrap()).body).unwrap();
        let refresh = first.get("refresh_token").as_str().unwrap().to_string();
        let r = login(&world, &mut st, &Json::parse(&format!(r#"{{"grant_type":"refresh","portal_access_token":"{refresh}"}}"#)).unwrap());
        let j = Json::parse(&r.body).unwrap();
        assert_eq!((r.status, j.get("platform").as_str()), (200, Some("Epic")));
        assert_ne!(j.get("refresh_token").as_str(), Some(refresh.as_str()), "a new one");
        // The other field a refresh may use, and a token never issued: still signs in.
        let r = login(&world, &mut st, &Json::parse(&format!(r#"{{"grant_type":"refresh","refresh_token":"{refresh}"}}"#)).unwrap());
        assert_eq!(Json::parse(&r.body).unwrap().get("platform").as_str(), Some("Epic"));
        assert_eq!(login(&world, &mut st, &Json::parse(r#"{"grant_type":"refresh","portal_access_token":"never"}"#).unwrap()).status, 200);
        let out = logout(&mut st, &Json::parse(&format!(r#"{{"refresh_token":"{refresh}"}}"#)).unwrap());
        assert_eq!((out.status, out.body.as_str()), (200, "{}"));
        assert_eq!(logout(&mut st, &Json::parse(&format!(r#"{{"refresh_token":"{refresh}"}}"#)).unwrap()).status, 404);
    }

    #[test]
    fn tokens_are_bounded() {
        let world = test_world(PeerId([7; 16]), "Me", &[]);
        let mut st = State::new(None);
        for _ in 0..(MAX_TOKENS + 10) {
            login(&world, &mut st, &Json::parse(r#"{"grant_type":"steam"}"#).unwrap());
        }
        assert_eq!((st.access.len(), st.refresh.len()), (MAX_TOKENS, MAX_TOKENS));
    }

    #[test]
    fn links_of_self_and_of_an_unknown_player() {
        let me = PeerId([1; 16]);
        let other = PeerId([2; 16]);
        let world = test_world(me, "Me", &[(other, "Other")]);
        let mut st = State::new(None);
        let r = links(&world, &st, &player_uuid(me));
        assert_eq!(r.status, 200);
        let j = Json::parse(&r.body).unwrap();
        assert_eq!(j.get("player").get("player_uuid").as_str(), Some(player_uuid(me).as_str()));
        assert_eq!(j.get("player").get("player_id").as_i64(), Some(player_id(me)));
        assert_eq!(j.get("player").get("person_id").as_str(), Some(person_id(me).as_str()));
        let p = &j.get("linked_portals").as_arr()[0];
        assert_eq!(p.get("display_name").as_str(), Some("Me"));
        assert_eq!(p.get("platform").as_str(), Some("Anon"), "before any sign-in");
        login(&world, &mut st, &Json::parse(r#"{"grant_type":"steam"}"#).unwrap());
        let j = Json::parse(&links(&world, &st, &player_uuid(me)).body).unwrap();
        assert_eq!(j.get("linked_portals").as_arr()[0].get("platform").as_str(), Some("Steam"));
        let j = Json::parse(&links(&world, &st, &player_uuid(other)).body).unwrap();
        assert_eq!(j.get("linked_portals").as_arr()[0].get("display_name").as_str(), Some("Other"));
        let r = links(&world, &st, "00000000-0000-4000-8000-000000000000");
        let j = Json::parse(&r.body).unwrap();
        assert_eq!((r.status, j.get("error_code").as_str()), (404, Some("user_not_found")));
    }
}
