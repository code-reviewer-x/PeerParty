//! Notifications (`API §8`): a queue per player and the long-poll that reads it.
//!
//! session.rs pushes one notification per change to a session, on every member's copy
//! (decision 5). `GET /notification/v1/player/{uuid}/stream/notification/lp` answers at
//! once when the queue holds notifications newer than the poll's cursor, and otherwise
//! waits on a condition variable until one arrives or the deadline passes.
//!
//! Each long-poll holds one of the HTTPS server's connection threads (64 at most) while it
//! waits, so only `MAX_WAITING` may wait per player: one more is answered at once with no
//! notifications and the cursor it gave, and the game simply polls again.

use std::collections::{HashMap, VecDeque};
use std::sync::{Condvar, LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::Reply;
use crate::util::json::Json;

pub const SESSION_UPDATED: &str = "session_updated";
pub const PLAYER_ADDED: &str = "session_player_added";
pub const PLAYER_REMOVED: &str = "session_player_removed";
pub const INSTANCE_UPDATED: &str = "session_instance_updated";
pub const BROWSER_UPDATED: &str = "session_browser_info_updated";

/// Notifications kept per player; the oldest goes first.
const QUEUE_LEN: usize = 50;
/// Long-polls that may wait at once per player.
const MAX_WAITING: usize = 4;
/// Players with a queue (one per copy in this process); the least recently used one
/// nobody waits on goes first.
const MAX_PLAYERS: usize = 64;

const DEFAULT_PAGE: i64 = 10;
const MAX_PAGE: i64 = 100;
const DEFAULT_DEADLINE: i64 = 30;
const MAX_DEADLINE: i64 = 900;

struct Note {
    /// Its time in milliseconds since 1970: its id, and what cursors compare. Strictly
    /// increasing within a queue (see `Queue::last`).
    ms: i64,
    json: Json,
}

#[derive(Default)]
struct Queue {
    notes: VecDeque<Note>,
    /// The latest time this queue used: of its last notification, or "now" handed out as
    /// a cursor. A new notification comes after it, never in the same millisecond, so a
    /// poll that follows its cursor (strictly after) never skips one.
    last: i64,
    /// Long-polls waiting on this queue.
    waiting: usize,
    used: Option<Instant>,
}

/// The queues by player uuid (lowercase), and the condition variable a push wakes.
static QUEUES: LazyLock<(Mutex<HashMap<String, Queue>>, Condvar)> = LazyLock::new(Default::default);

fn now_ms() -> i64 {
    crate::util::time::millis(SystemTime::now())
}

/// The queue of `player`, made when missing; with too many players, one nobody waits
/// on is dropped first.
fn queue<'a>(all: &'a mut HashMap<String, Queue>, player: &str) -> &'a mut Queue {
    if !all.contains_key(player) && all.len() >= MAX_PLAYERS {
        let idle = all.iter().filter(|(_, q)| q.waiting == 0).min_by_key(|(_, q)| q.used).map(|(k, _)| k.clone());
        if let Some(k) = idle {
            all.remove(&k);
        }
    }
    let q = all.entry(player.to_string()).or_default();
    q.used = Some(Instant::now());
    q
}

/// Tells `player` of one change to `session`: its notifications, as (message, one of the
/// constants above; the session's ETag after the change), all at once.
pub fn push(player: &str, session: &str, notes: &[(&str, String)]) {
    push_at(player, session, notes, None);
}

/// `push`, at `at` (tests) or now, both taken under the lock so that times follow the
/// order of the queue.
fn push_at(player: &str, session: &str, notes: &[(&str, String)], at: Option<i64>) {
    if notes.is_empty() {
        return;
    }
    let (m, cv) = &*QUEUES;
    {
        let mut all = crate::sys::lock(m);
        let q = queue(&mut all, &player.to_ascii_lowercase());
        let now = at.unwrap_or_else(now_ms);
        for (message, etag) in notes {
            let ms = now.max(q.last + 1);
            q.last = ms;
            let json = Json::obj(vec![
                ("message", Json::str(*message)),
                ("rh_url", Json::str(format!("session/v1/session/{session}"))),
                ("custom_data", Json::obj(Vec::new())),
                ("etag", Json::str(etag)),
                ("notification_id", Json::str(format!("{ms}-0"))),
                ("created", Json::str(crate::util::time::iso(UNIX_EPOCH + Duration::from_millis(ms.max(0) as u64)))),
            ]);
            if q.notes.len() >= QUEUE_LEN {
                q.notes.pop_front();
            }
            q.notes.push_back(Note { ms, json });
        }
    }
    // Woken after the lock is let go, so a waiter doesn't wake only to wait for it.
    cv.notify_all();
}

/// The millisecond part of a `<ms>-<n>` cursor; None (everything) when empty or malformed.
fn cursor(text: &str) -> Option<i64> {
    let (ms, n) = text.trim().split_once('-')?;
    let digits = |s: &str| !s.is_empty() && s.len() <= 19 && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(ms) || !digits(n) {
        return None;
    }
    ms.parse().ok()
}

/// `max_page_size`: 1..100, 10 when missing, malformed or below 1, 100 above.
fn page_size(text: Option<&str>) -> usize {
    match text.and_then(|t| t.trim().parse::<i64>().ok()) {
        Some(n) if n < 1 => DEFAULT_PAGE as usize,
        Some(n) => n.min(MAX_PAGE) as usize,
        None => DEFAULT_PAGE as usize,
    }
}

/// `deadline` in seconds: 1..900, 30 when missing, malformed or not above 0, 900 above.
fn deadline(text: Option<&str>) -> u64 {
    match text.and_then(|t| t.trim().parse::<i64>().ok()) {
        Some(n) if n <= 0 => DEFAULT_DEADLINE as u64,
        Some(n) => n.min(MAX_DEADLINE) as u64,
        None => DEFAULT_DEADLINE as u64,
    }
}

/// `GET /notification/v1/player/{player}/stream/notification/lp` for the signed-in
/// player `me` (`API §8`).
pub fn long_poll(me: &str, player: &str, query: &[(String, String)]) -> Reply {
    if !player.eq_ignore_ascii_case(me) {
        return Reply::err(401, "unauthorized", "not the signed-in player", false);
    }
    let arg = |k: &str| query.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    let after = cursor(arg("exclude_before").unwrap_or_default());
    let page = page_size(arg("max_page_size"));
    // Clamped first, so that the end is never computed from what the game sent.
    let end = Instant::now() + Duration::from_secs(deadline(arg("deadline")));
    let key = me.to_ascii_lowercase();
    let is_newer = |n: &Note| after.is_none_or(|a| n.ms > a);
    let newer = |q: &Queue| q.notes.iter().any(is_newer);
    let (m, cv) = &*QUEUES;
    let mut all = crate::sys::lock(m);
    if !all.get(&key).is_some_and(newer) && queue(&mut all, &key).waiting < MAX_WAITING {
        queue(&mut all, &key).waiting += 1;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            all = cv.wait_timeout(all, left).unwrap_or_else(|e| e.into_inner()).0;
            if all.get(&key).is_some_and(newer) {
                break;
            }
        }
        // A queue with a waiter is never dropped, so it is still there.
        if let Some(q) = all.get_mut(&key) {
            q.waiting -= 1;
        }
    }
    // Oldest first, at most a page; ms are unique in a queue, so the rest comes next poll.
    // Over the wait cap, this is empty and answered at once.
    let q = queue(&mut all, &key);
    let notes: Vec<(i64, Json)> = q.notes.iter().filter(|n| is_newer(n)).take(page).map(|n| (n.ms, n.json.clone())).collect();
    // The cursor: the last notification's time, or with none the poll's own, or now when it
    // gave none (and then the queue's next notification comes after it).
    let last = match (notes.last(), after) {
        (Some((ms, _)), _) => *ms,
        (None, Some(a)) => a,
        (None, None) => {
            let now = now_ms().max(q.last);
            q.last = now;
            now
        }
    };
    drop(all);
    let list = notes.into_iter().map(|(_, j)| j).collect();
    Reply::ok(Json::obj(vec![("notifications", Json::Arr(list)), ("cursor", Json::str(format!("{last}-0")))]))
}

/// What `player`'s queue holds, oldest first (tests).
#[cfg(test)]
pub fn queued(player: &str) -> Vec<Json> {
    crate::sys::lock(&QUEUES.0).get(&player.to_ascii_lowercase()).map(|q| q.notes.iter().map(|n| n.json.clone()).collect()).unwrap_or_default()
}

/// How many long-polls of `player` are waiting (tests).
#[cfg(test)]
pub fn waiting(player: &str) -> usize {
    crate::sys::lock(&QUEUES.0).get(&player.to_ascii_lowercase()).map_or(0, |q| q.waiting)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A player of its own per test, since the queues are shared by the process.
    fn player() -> String {
        static N: AtomicU32 = AtomicU32::new(0);
        format!("00000000-0000-4000-8000-{:08x}{:04x}", std::process::id(), N.fetch_add(1, Ordering::Relaxed))
    }

    /// One notification of its own change to `session` for `p`, at `ms` or now.
    fn one(p: &str, message: &str, session: &str, etag: &str, ms: Option<i64>) {
        push_at(p, session, &[(message, etag.to_string())], ms);
    }

    fn q(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn poll(p: &str, pairs: &[(&str, &str)]) -> Json {
        let r = long_poll(p, p, &q(pairs));
        assert_eq!(r.status, 200, "{}", r.body);
        Json::parse(&r.body).unwrap()
    }

    fn etags(j: &Json) -> Vec<String> {
        j.get("notifications").as_arr().iter().map(|n| n.get("etag").as_str().unwrap().to_string()).collect()
    }

    #[test]
    fn a_notification_is_the_json_of_the_api() {
        let p = player();
        one(&p, SESSION_UPDATED, "0b2c5e9a-1111-4222-8333-444455556666", "W/\"42\"", Some(1_735_787_045_123));
        let j = poll(&p, &[("exclude_before", "")]);
        assert_eq!(
            j.get("notifications").as_arr()[0].to_string(),
            r#"{"message":"session_updated","rh_url":"session/v1/session/0b2c5e9a-1111-4222-8333-444455556666","custom_data":{},"etag":"W/\"42\"","notification_id":"1735787045123-0","created":"2025-01-02T03:04:05.123Z"}"#
        );
        assert_eq!(j.get("cursor").as_str(), Some("1735787045123-0"));
    }

    #[test]
    fn the_queue_keeps_the_last_fifty() {
        let p = player();
        for i in 0..55 {
            one(&p, SESSION_UPDATED, "s", &i.to_string(), Some(1000 + i));
        }
        let all = queued(&p);
        assert_eq!(all.len(), 50);
        assert_eq!(all[0].get("etag").as_str(), Some("5"), "the oldest went first");
        let j = poll(&p, &[("max_page_size", "100")]);
        assert_eq!(etags(&j).len(), 50);
        assert_eq!(j.get("cursor").as_str(), Some("1054-0"));
    }

    #[test]
    fn cursors_count_their_milliseconds_and_garbage_is_empty() {
        assert_eq!(cursor(""), None);
        assert_eq!(cursor("1735787045123-0"), Some(1_735_787_045_123));
        assert_eq!(cursor("1735787045123-7"), Some(1_735_787_045_123));
        for bad in ["garbage", "123", "-0", "12-", "12-x", "x-0", "1.5-0", "99999999999999999999-0", " - "] {
            assert_eq!(cursor(bad), None, "{bad}");
        }
        // Garbage reads everything.
        let p = player();
        one(&p, SESSION_UPDATED, "s", "a", Some(5000));
        assert_eq!(etags(&poll(&p, &[("exclude_before", "garbage")])), ["a"]);
        assert_eq!(etags(&poll(&p, &[("exclude_before", "4999-0")])), ["a"]);
    }

    #[test]
    fn page_size_and_deadline_are_clamped() {
        for (given, want) in [(None, 10), (Some("x"), 10), (Some("0"), 10), (Some("-4"), 10), (Some("1"), 1), (Some("57"), 57), (Some("100"), 100), (Some("101"), 100), (Some("99999999999"), 100)] {
            assert_eq!(page_size(given), want, "{given:?}");
        }
        for (given, want) in [(None, 30), (Some("x"), 30), (Some("0"), 30), (Some("-1"), 30), (Some("1"), 1), (Some("25"), 25), (Some("900"), 900), (Some("901"), 900), (Some("99999999999"), 900)] {
            assert_eq!(deadline(given), want, "{given:?}");
        }
    }

    #[test]
    fn a_page_holds_at_most_max_page_size_and_the_rest_comes_next() {
        let p = player();
        for i in 0..15 {
            one(&p, SESSION_UPDATED, "s", &i.to_string(), Some(2000 + i));
        }
        let first = poll(&p, &[("exclude_before", ""), ("max_page_size", "10")]);
        assert_eq!(etags(&first), (0..10).map(|i| i.to_string()).collect::<Vec<_>>(), "oldest first");
        let cursor = first.get("cursor").as_str().unwrap().to_string();
        assert_eq!(cursor, "2009-0");
        let rest = poll(&p, &[("exclude_before", &cursor), ("max_page_size", "10")]);
        assert_eq!(etags(&rest), (10..15).map(|i| i.to_string()).collect::<Vec<_>>());
        // Default page: 10.
        assert_eq!(etags(&poll(&p, &[])).len(), 10);
    }

    #[test]
    fn notifications_of_one_millisecond_all_reach_a_poll_that_follows_its_cursor() {
        let p = player();
        // One change with three notifications, then two more, all in the same millisecond.
        push_at(&p, "s", &[(PLAYER_ADDED, "0".into()), (SESSION_UPDATED, "1".into()), (INSTANCE_UPDATED, "2".into())], Some(3000));
        one(&p, BROWSER_UPDATED, "s", "3", Some(3000));
        one(&p, SESSION_UPDATED, "s", "4", Some(2990));
        let ids: Vec<String> = queued(&p).iter().map(|n| n.get("notification_id").as_str().unwrap().to_string()).collect();
        assert_eq!(ids, ["3000-0", "3001-0", "3002-0", "3003-0", "3004-0"], "times strictly increase within a queue");
        let mut got = Vec::new();
        let mut c = String::new();
        for _ in 0..3 {
            let j = poll(&p, &[("exclude_before", &c), ("max_page_size", "2"), ("deadline", "1")]);
            got.extend(etags(&j));
            c = j.get("cursor").as_str().unwrap().to_string();
        }
        assert_eq!(got, ["0", "1", "2", "3", "4"]);
        // "Now" handed out as a cursor: what comes next is after it, even in that millisecond.
        let fresh = player();
        let j = poll(&fresh, &[("deadline", "1")]);
        let c = j.get("cursor").as_str().unwrap().to_string();
        one(&fresh, SESSION_UPDATED, "s", "next", cursor(&c));
        assert_eq!(etags(&poll(&fresh, &[("exclude_before", &c)])), ["next"]);
    }

    #[test]
    fn newer_notifications_are_answered_at_once() {
        let p = player();
        one(&p, PLAYER_ADDED, "s", "a", Some(now_ms() - 10));
        let t = Instant::now();
        let j = poll(&p, &[("exclude_before", ""), ("deadline", "25")]);
        assert!(t.elapsed() < Duration::from_millis(500), "{:?}", t.elapsed());
        assert_eq!(etags(&j), ["a"]);
    }

    #[test]
    fn a_push_wakes_a_waiting_poll() {
        let p = player();
        let since = format!("{}-0", now_ms());
        let (p2, since2) = (p.clone(), since.clone());
        let t = Instant::now();
        let waiter = std::thread::spawn(move || poll(&p2, &[("exclude_before", &since2), ("deadline", "25")]));
        while waiting(&p) == 0 {
            std::thread::sleep(Duration::from_millis(5));
        }
        std::thread::sleep(Duration::from_millis(100));
        one(&p, PLAYER_ADDED, "s", "woken", None);
        let j = waiter.join().unwrap();
        assert!(t.elapsed() < Duration::from_secs(3), "woken by the push, not the deadline: {:?}", t.elapsed());
        assert_eq!(etags(&j), ["woken"]);
        assert_eq!(waiting(&p), 0);
    }

    #[test]
    fn a_deadline_not_above_zero_waits_the_default() {
        // The end comes from the clamped deadline: -5 waits (30 s), it isn't answered at once.
        let p = player();
        let since = format!("{}-0", now_ms());
        let (p2, since2) = (p.clone(), since.clone());
        let t = Instant::now();
        let waiter = std::thread::spawn(move || poll(&p2, &[("exclude_before", &since2), ("deadline", "-5")]));
        std::thread::sleep(Duration::from_millis(300));
        one(&p, SESSION_UPDATED, "s", "late", None);
        let j = waiter.join().unwrap();
        assert!(t.elapsed() >= Duration::from_millis(250), "{:?}", t.elapsed());
        assert_eq!(etags(&j), ["late"]);
    }

    #[test]
    fn a_poll_with_nothing_new_times_out_with_its_cursor() {
        let p = player();
        one(&p, SESSION_UPDATED, "s", "old", Some(1234));
        let t = Instant::now();
        let j = poll(&p, &[("exclude_before", "1234-0"), ("deadline", "1")]);
        let took = t.elapsed();
        assert!(took >= Duration::from_millis(900) && took < Duration::from_secs(3), "{took:?}");
        assert_eq!(j.to_string(), r#"{"notifications":[],"cursor":"1234-0"}"#);
        // No cursor given and nothing at all: now.
        let fresh = player();
        let before = now_ms();
        let j = poll(&fresh, &[("deadline", "1")]);
        let c = cursor(j.get("cursor").as_str().unwrap()).unwrap();
        assert!(c >= before && c <= now_ms(), "{c}");
    }

    #[test]
    fn only_four_polls_wait_per_player() {
        let p = player();
        let since = format!("{}-0", now_ms());
        let waiters: Vec<_> = (0..MAX_WAITING)
            .map(|_| {
                let (p, since) = (p.clone(), since.clone());
                std::thread::spawn(move || poll(&p, &[("exclude_before", &since), ("deadline", "20")]))
            })
            .collect();
        let t = Instant::now();
        while waiting(&p) < MAX_WAITING {
            assert!(t.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(5));
        }
        // A fifth is answered at once, empty, with the cursor it gave.
        let t = Instant::now();
        let j = poll(&p, &[("exclude_before", "777-3"), ("deadline", "20")]);
        assert!(t.elapsed() < Duration::from_millis(500));
        assert_eq!(j.to_string(), r#"{"notifications":[],"cursor":"777-0"}"#);
        // Another player still waits.
        let other = player();
        let (o2, since2) = (other.clone(), since.clone());
        let theirs = std::thread::spawn(move || poll(&o2, &[("exclude_before", &since2), ("deadline", "20")]));
        while waiting(&other) == 0 {
            std::thread::sleep(Duration::from_millis(5));
        }
        one(&p, SESSION_UPDATED, "s", "all", None);
        one(&other, SESSION_UPDATED, "s", "theirs", None);
        for w in waiters {
            assert_eq!(etags(&w.join().unwrap()), ["all"]);
        }
        assert_eq!(etags(&theirs.join().unwrap()), ["theirs"]);
        assert_eq!(waiting(&p), 0);
    }

    #[test]
    fn another_players_stream_is_refused() {
        let (me, other) = (player(), player());
        let r = long_poll(&me, &other, &[]);
        assert_eq!(r.status, 401);
        let j = Json::parse(&r.body).unwrap();
        assert_eq!((j.get("error_code").as_str(), j.get("auth_success")), (Some("unauthorized"), &Json::Bool(false)));
        // Any case of our own is ours.
        one(&me, SESSION_UPDATED, "s", "mine", Some(10));
        assert_eq!(long_poll(&me, &me.to_uppercase(), &[]).status, 200);
    }
}
