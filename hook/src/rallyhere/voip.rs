//! Voice through Epic: `GET /session/v1/session/{id}/player/me/voip/epic:join`.
//!
//! A game's voice manager asks this once it is in a session, then joins a room through the
//! EOS SDK (`EOS_RTC_JoinRoom`), which PeerParty's EOS layer serves on LAN voice rooms
//! (hook/src/eos/rtc.rs). The answer carries what that join needs: a room name every member
//! of the session gets alike, and the caller's own ProductUserId as the EOS layer gives it
//! to this copy. The room's token and base URL are never checked by the EOS layer (it reads
//! neither), so they are opaque placeholders, not a URL of any service. Only the `session`
//! voice type is answered; every other `voip` route and type is a gap.

use peerparty_core::{PeerId, sha1};

use super::{Reply, World, session};
use crate::util::json::Json;

/// What the opaque `participant_token` and `client_base_url` hold: not empty (a voice manager
/// refuses an empty one), and nothing anyone could connect to.
const PLACEHOLDER: &str = "peerparty-local";
/// The longest session id kept as it is in a room name.
const MAX_PLAIN_ID: usize = 64;
/// The id RallyHere's own organisation, product, environment and sandbox keys hold here.
const NIL_ID: &str = "00000000-0000-0000-0000-000000000000";

/// The EOS room name of a session: the same for every member, stable, and made of letters,
/// digits, `-` and `_` only. A session id that isn't such (or is long) is hashed.
pub fn room_name(session_id: &str) -> String {
    let plain = !session_id.is_empty() && session_id.len() <= MAX_PLAIN_ID && session_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if plain {
        format!("rallyhere-{session_id}")
    } else {
        format!("rallyhere-{}", peerparty_core::hex(&sha1::sha1(session_id.as_bytes())))
    }
}

/// The answer for `me`, a member of the session `session_id`.
pub fn credentials(session_id: &str, me: PeerId) -> Json {
    Json::obj(vec![
        ("org_id", Json::str(NIL_ID)),
        ("product_id", Json::str(NIL_ID)),
        ("environment_id", Json::str(NIL_ID)),
        ("sandbox_id", Json::str(NIL_ID)),
        ("room_id", Json::str(room_name(session_id))),
        ("participant_token", Json::str(PLACEHOLDER)),
        ("client_base_url", Json::str(PLACEHOLDER)),
        ("product_user_id", Json::str(crate::eos::product_user_id(me))),
    ])
}

/// `GET /session/v1/session/{id or short code}/player/me/voip/epic:join?voip_session_type=`.
/// A session this copy isn't in is answered as the other session routes do: 404
/// `session_not_found`.
pub fn epic_join(world: &World, id: &str, voip_type: Option<&str>, host: &str, path: &str) -> Reply {
    let Some(lan) = &world.lan else { return session::no_lan() };
    if let Some(t) = voip_type.filter(|t| *t != "session") {
        let (status, body) = super::not_implemented("GET", host, &format!("{path}?voip_session_type={t}"));
        return Reply { status, body, etag: None };
    }
    match session::find(lan, id) {
        Some(l) => Reply::ok(credentials(&l.id, world.me)),
        None => session::not_found(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_eos_room_name(n: &str) -> bool {
        !n.is_empty() && n.len() <= 256 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }

    #[test]
    fn a_room_name_is_stable_per_session_and_always_a_valid_eos_name() {
        let id = "0b2c5e9a-1111-4222-8333-444455556666";
        assert_eq!(room_name(id), format!("rallyhere-{id}"));
        assert_eq!(room_name(id), room_name(id));
        let odd = ["", "a b", "caf\u{e9}", "../x", "a\0b", &"x".repeat(5000), &"y".repeat(65)];
        for o in odd {
            let n = room_name(o);
            assert!(valid_eos_room_name(&n), "{o:?} -> {n}");
            assert_eq!(n, room_name(o));
        }
        assert_ne!(room_name("a b"), room_name("a c"), "different odd ids are different rooms");
        assert_ne!(room_name(&"x".repeat(5000)), room_name(&"x".repeat(5001)));
    }

    #[test]
    fn the_answer_has_the_sdks_keys_and_the_callers_own_id() {
        let (a, b) = (PeerId([1; 16]), PeerId([2; 16]));
        let ja = credentials("s1", a);
        let jb = credentials("s1", b);
        let keys = ["org_id", "product_id", "environment_id", "sandbox_id", "room_id", "participant_token", "client_base_url", "product_user_id"];
        for k in keys {
            assert!(ja.get(k).as_str().is_some_and(|v| !v.is_empty()), "{k}");
        }
        assert_eq!(ja.get("room_id").as_str(), jb.get("room_id").as_str());
        assert_eq!(ja.get("product_user_id").as_str(), Some(crate::eos::product_user_id(a).as_str()));
        assert_ne!(ja.get("product_user_id").as_str(), jb.get("product_user_id").as_str());
        assert_ne!(credentials("s2", a).get("room_id").as_str(), ja.get("room_id").as_str());
    }

    #[test]
    fn without_a_lan_the_route_is_unavailable() {
        let world = super::super::tests_support::test_world(PeerId([1; 16]), "me", &[]);
        let r = epic_join(&world, "s", None, "h", "/p");
        assert_eq!(r.status, 503);
    }
}
