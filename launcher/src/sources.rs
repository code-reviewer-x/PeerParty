//! Game data sources: public places the player names (Settings > Advanced,
//! `PEERPARTY_DATA_SOURCES`, `--data-source`) that hold game data files, fetched for a game
//! just before it starts into a cache the hook reads after the player's own files.
//!
//! A source is a base address (`https://` only; a raw git file address works, as any plain
//! web server does), laid out as the player's own folders are:
//!
//! - `<base>/patterns/<exe file name>.json`: the curl patterns file (hook/src/config/hooks.rs);
//! - `<base>/rallyhere/<exe stem, lowercase>/config.json`: the RallyHere config file
//!   (hook/src/rallyhere/config.rs);
//! - `<base>/rallyhere/<exe stem, lowercase>/harvested/{template,kv,regions,instance}.json`:
//!   title data in the layout official mode keeps (hook/src/rallyhere/harvest.rs).
//!
//! There are none to begin with: no address is built in. Only the started game's files are
//! asked for, and for each file the first source that has it wins.
//!
//! What comes back is a stranger's: GET only, with no cookies or sign-in, a few seconds at
//! most, bounded in size, and a file is kept only when the hook's own checks (protocol's
//! `gamedata`, which the hook reads it with) take it whole. A source may redirect to
//! another HTTPS host (never to plain HTTP); the log names that host. Kept files go under
//! PeerParty's folder, `remote\` (`patterns\`, `rallyhere\<stem>\`,
//! `rallyhere\<stem>\harvested\`), each written whole: a temporary file, then a rename. A
//! file no source has, a source that can't be reached and a refused file all leave the
//! cached copy as it was, and the game starts whatever happens, after at most `WAIT`.

// The fetch itself is Windows' (WinHTTP); on Linux the list is handed to Windows'
// peerparty.exe inside Proton, which fetches where the hook under Wine reads.
#![cfg_attr(not(windows), allow(dead_code))]

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use peerparty_protocol::gamedata::{patterns, rallyhere};

/// The cache's folder inside PeerParty's.
pub const FOLDER: &str = "remote";
/// The most sources one run asks; the rest are left out.
pub const MAX_SOURCES: usize = 8;
/// The longest source address.
const MAX_ADDRESS: usize = 2048;
/// The largest patterns file (the hook's own bound).
pub const MAX_PATTERNS: usize = patterns::MAX_FILE as usize;
/// The largest RallyHere file (the hook's bound for config.json and the harvested files).
pub const MAX_RALLYHERE: usize = rallyhere::MAX_FILE as usize;
/// How long a start waits for the fetches at most.
pub const WAIT: Duration = Duration::from_secs(8);
/// The harvested files, as harvest.rs names them.
const HARVESTED: [&str; 4] = ["template.json", "kv.json", "regions.json", "instance.json"];

/// Where a run's sources came from, for the log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    CommandLine,
    Environment,
    Settings,
}

impl Origin {
    fn name(self) -> &'static str {
        match self {
            Origin::CommandLine => "--data-source",
            Origin::Environment => peerparty_protocol::env::DATA_SOURCES,
            Origin::Settings => "Settings",
        }
    }
}

/// A list's items: addresses hold neither `;` nor white space.
pub fn split_list(v: &str) -> impl Iterator<Item = &str> {
    v.split(|c: char| c == ';' || c.is_whitespace()).filter(|s| !s.is_empty())
}

/// A source as asked: `https://<host>[:port][/path]`, the scheme lowercase and no `/` at
/// the end. Err says why it isn't used.
pub fn base(source: &str) -> Result<String, String> {
    let s = source.trim();
    if s.len() > MAX_ADDRESS {
        return Err(format!("longer than {MAX_ADDRESS} characters"));
    }
    if s.chars().any(|c| c.is_control() || c.is_whitespace() || c == '\\') {
        return Err("a space, backslash or control character in it".into());
    }
    let Some((scheme, rest)) = s.split_once("://") else { return Err("it doesn't start with https://".into()) };
    if !scheme.eq_ignore_ascii_case("https") {
        return Err(format!("only https sources are used, not {}", scheme.to_ascii_lowercase()));
    }
    if rest.contains(['?', '#']) {
        return Err("a ? or # in it: a source is a folder".into());
    }
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    if authority.contains('@') {
        return Err("a user name or password in it: sources are public, nothing is signed in to".into());
    }
    let host = match authority.strip_prefix('[') {
        Some(v6) => v6.split_once(']').filter(|(_, after)| after.is_empty() || port_ok(after)).map(|(h, _)| h),
        None => match authority.split_once(':') {
            Some((h, p)) => port_ok(&format!(":{p}")).then_some(h),
            None => Some(authority),
        },
    };
    match host {
        Some(h) if !h.is_empty() => Ok(format!("https://{authority}{}", path.trim_end_matches('/'))),
        Some(_) => Err("no host in it".into()),
        None => Err("a bad port in it".into()),
    }
}

/// `:<port>`, 1 to 65535.
fn port_ok(p: &str) -> bool {
    p.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()).is_some_and(|p| p != 0)
}

/// The host a base names, for the log.
fn host_of(base: &str) -> &str {
    let rest = base.strip_prefix("https://").unwrap_or(base);
    &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())]
}

/// A source as the log shows it: its scheme and host only. Its path, query and any user
/// name or password (a token, say) never reach the log.
fn shown(source: &str) -> String {
    let (scheme, rest) = source.split_once("://").unwrap_or(("", source));
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host: String = host.chars().take(80).collect();
    if scheme.is_empty() { host } else { format!("{}://{host}", scheme.chars().take(16).collect::<String>().to_ascii_lowercase()) }
}

/// Whether two bases (from `base`) are one source: the host without case, the path with it.
fn same_source(a: &str, b: &str) -> bool {
    fn split(s: &str) -> (&str, &str) {
        let rest = s.strip_prefix("https://").unwrap_or(s);
        rest.split_at(rest.find('/').unwrap_or(rest.len()))
    }
    let ((ha, pa), (hb, pb)) = (split(a), split(b));
    ha.eq_ignore_ascii_case(hb) && pa == pb
}

/// This run's sources: `--data-source`'s when given, else `PEERPARTY_DATA_SOURCES`'s when
/// set (even empty: none for this run), else Settings'. Each one usable once, in order,
/// at most `MAX_SOURCES`; with a line for each one left out.
pub fn chosen(cli: &[String], env: Option<&str>, settings: &str) -> (Vec<String>, Origin, Vec<String>) {
    let (raw, from): (Vec<&str>, Origin) = if !cli.is_empty() {
        (cli.iter().flat_map(|s| split_list(s)).collect(), Origin::CommandLine)
    } else if let Some(v) = env {
        (split_list(v).collect(), Origin::Environment)
    } else {
        (split_list(settings).collect(), Origin::Settings)
    };
    let mut bases: Vec<String> = Vec::new();
    let mut lines = Vec::new();
    for s in raw {
        match base(s) {
            Err(why) => lines.push(format!("data source {} (from {}) is refused: {why}", shown(s), from.name())),
            Ok(_) if bases.len() == MAX_SOURCES => {
                lines.push(format!("more than {MAX_SOURCES} data sources: {} and the ones after it are left out", shown(s)));
                break;
            }
            Ok(b) if !bases.iter().any(|x| same_source(x, &b)) => bases.push(b),
            Ok(_) => {}
        }
    }
    (bases, from, lines)
}

/// One name as one path segment of an address: everything but ASCII letters, digits and
/// `-._~` percent-encoded, as UTF-8.
pub fn segment(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// What a file must be to be kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Patterns,
    /// config.json.
    Config,
    /// A harvested file, by its name.
    Harvested(&'static str),
}

impl Kind {
    pub fn max(self) -> usize {
        match self {
            Kind::Patterns => MAX_PATTERNS,
            Kind::Config | Kind::Harvested(_) => MAX_RALLYHERE,
        }
    }
}

/// A file a game may have at the sources.
#[derive(Clone, Debug, PartialEq)]
pub struct Wanted {
    /// Its path under a base, escaped (`rallyhere/my%20game/config.json`).
    pub path: String,
    /// Its place in the cache, under `remote\`.
    pub cache: PathBuf,
    pub kind: Kind,
}

/// The files the game at `exe` may have: its patterns file, then its RallyHere config and
/// harvested files. Names as the hook uses them: the exe's file name for the patterns, its
/// stem in lowercase for the RallyHere folder.
pub fn wanted(exe: &Path) -> Vec<Wanted> {
    let (Some(file), Some(stem)) = (exe.file_name(), exe.file_stem()) else { return Vec::new() };
    let file = file.to_string_lossy();
    let stem = stem.to_string_lossy().to_ascii_lowercase();
    if file.is_empty() || stem.is_empty() || stem == "." || stem == ".." {
        return Vec::new();
    }
    let mut out = vec![
        Wanted { path: format!("patterns/{}.json", segment(&file)), cache: Path::new("patterns").join(format!("{file}.json")), kind: Kind::Patterns },
        Wanted { path: format!("rallyhere/{}/config.json", segment(&stem)), cache: Path::new("rallyhere").join(&stem).join("config.json"), kind: Kind::Config },
    ];
    for h in HARVESTED {
        out.push(Wanted { path: format!("rallyhere/{}/harvested/{h}", segment(&stem)), cache: Path::new("rallyhere").join(&stem).join("harvested").join(h), kind: Kind::Harvested(h) });
    }
    out
}

/// Whether `bytes` can be kept as a file of `kind`: within its bound, UTF-8 text the hook
/// reads without a complaint, by the hook's own checks (protocol's `gamedata`). A patterns
/// file the hook would only partly use (an entry or a pattern it leaves out) isn't kept
/// either: it could replace a cached one it uses whole.
pub fn check(kind: Kind, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > kind.max() {
        return Err(format!("larger than {} KiB", kind.max() / 1024));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "not UTF-8 text".to_string())?;
    match kind {
        Kind::Patterns => {
            let (entries, problems) = patterns::parse(text);
            match problems.into_iter().next() {
                Some(p) => Err(p),
                None if entries.is_empty() => Err("no usable entry".into()),
                None => Ok(()),
            }
        }
        Kind::Config => rallyhere::parse(text).map(drop),
        Kind::Harvested(file) => rallyhere::check_harvested(file, text),
    }
}

/// Why a source gave no file.
#[derive(Clone, Debug, PartialEq)]
pub enum Failure {
    /// Its answer's status (404: it hasn't the file).
    Status(u32),
    /// No usable answer (unreachable, too slow, too long, refused).
    Other(String),
}

/// A source's answer: the file, and the address that gave it (another host's when the
/// source redirected there).
#[derive(Clone, Debug, PartialEq)]
pub struct Got {
    pub body: Vec<u8>,
    pub url: String,
}

/// A GET: `max` bytes at most.
pub trait Fetch: Send + Sync {
    fn get(&self, url: &str, max: usize) -> Result<Got, Failure>;
}

/// Windows' own client, anonymous and quick.
#[cfg(windows)]
pub struct WinHttp;

#[cfg(windows)]
impl Fetch for WinHttp {
    fn get(&self, url: &str, max: usize) -> Result<Got, Failure> {
        use crate::backend::http::{self, GetError, Limits};
        const LIMITS: Limits = Limits { connect_ms: 4_000, answer_ms: 5_000, anonymous: true };
        match http::fetch_from(url, "application/json", max, &LIMITS) {
            Ok((body, url)) => Ok(Got { body, url }),
            Err(GetError::Status(c)) => Err(Failure::Status(c)),
            Err(GetError::Failed(why)) => Err(Failure::Other(why)),
        }
    }
}

/// What became of one file.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// Cached from source n (from 0), and the host it redirected to, if another.
    Saved(usize, Option<String>),
    /// Source n has the file the cache already holds (and the host it redirected to).
    Same(usize, Option<String>),
    /// Every source answered that it hasn't the file (or there was none to ask).
    Missing,
    /// Not fetched, for these reasons; the cached copy, if any, is left as it was.
    Kept(Vec<String>),
    /// The start didn't wait for it.
    Late,
}

/// The file `w` from the first source that has it, into the cache under `root`, unless
/// `deadline` passes first.
pub fn fetch_one(f: &dyn Fetch, bases: &[String], w: &Wanted, root: &Path, deadline: Instant) -> Outcome {
    let mut why = Vec::new();
    for (i, b) in bases.iter().enumerate() {
        if Instant::now() >= deadline {
            return Outcome::Late;
        }
        match f.get(&format!("{b}/{}", w.path), w.kind.max()) {
            Ok(got) => match check(w.kind, &got.body) {
                Ok(()) if Instant::now() >= deadline => return Outcome::Late,
                Ok(()) => {
                    let via = redirected(b, &got.url);
                    return match write_whole(&root.join(&w.cache), &got.body) {
                        Ok(true) => Outcome::Saved(i, via),
                        Ok(false) => Outcome::Same(i, via),
                        Err(e) => Outcome::Kept(vec![e]),
                    };
                }
                Err(e) => why.push(format!("source {}: refused, {e}", i + 1)),
            },
            // Hasn't it: the next source may.
            Err(Failure::Status(404 | 410)) => {}
            Err(Failure::Status(c)) => why.push(format!("source {}: HTTP {c}", i + 1)),
            Err(Failure::Other(e)) => why.push(format!("source {}: {e}", i + 1)),
        }
    }
    if why.is_empty() { Outcome::Missing } else { Outcome::Kept(why) }
}

/// The host the answer came from (`url`), when it isn't `base`'s: the source redirected
/// there.
fn redirected(base: &str, url: &str) -> Option<String> {
    let host = host_of(url);
    (!host.eq_ignore_ascii_case(host_of(base))).then(|| shown(host))
}

/// Writes `bytes` to `path` whole (a temporary file beside it, then a rename over it), so
/// that the hook reads the old file or the new one, never a part. False when it already
/// held them (left untouched).
pub fn write_whole(path: &Path, bytes: &[u8]) -> Result<bool, String> {
    if let Ok(f) = fs::File::open(path) {
        let mut old = Vec::new();
        if f.take(bytes.len() as u64 + 1).read_to_end(&mut old).is_ok() && old == bytes {
            return Ok(false);
        }
    }
    let dir = path.parent().ok_or("no folder")?;
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    static N: AtomicU32 = AtomicU32::new(0);
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = dir.join(format!(".{name}.{}-{}.part", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let done = fs::write(&tmp, bytes).and_then(|()| fs::rename(&tmp, path));
    if let Err(e) = done {
        let _ = fs::remove_file(&tmp);
        return Err(format!("{}: {e}", path.display()));
    }
    Ok(true)
}

/// Every file of the game at `exe`, each on a thread of its own, waiting `wait` at most:
/// what became of each, by its place in the cache.
pub fn fetch_all(f: Arc<dyn Fetch>, bases: &[String], exe: &Path, root: &Path, wait: Duration) -> Vec<(Wanted, Outcome)> {
    let deadline = Instant::now() + wait;
    let wanted = wanted(exe);
    let bases: Arc<[String]> = bases.into();
    let (tx, rx) = mpsc::channel();
    for (n, w) in wanted.iter().enumerate() {
        let (f, bases, w, root, sender) = (f.clone(), bases.clone(), w.clone(), root.to_path_buf(), tx.clone());
        let spawned = std::thread::Builder::new().name("peerparty-data".into()).spawn(move || {
            let _ = sender.send((n, fetch_one(&*f, &bases, &w, &root, deadline)));
        });
        if spawned.is_err() {
            let _ = tx.send((n, Outcome::Kept(vec!["no thread for it".into()])));
        }
    }
    drop(tx);
    let mut outcomes: Vec<Outcome> = vec![Outcome::Late; wanted.len()];
    while let Ok((n, o)) = rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        outcomes[n] = o;
    }
    wanted.into_iter().zip(outcomes).collect()
}

fn via_text(via: &Option<String>) -> String {
    via.as_ref().map(|h| format!(", redirected to {h}")).unwrap_or_default()
}

/// The log's lines for a fetch.
pub fn report(bases: &[String], done: &[(Wanted, Outcome)]) -> Vec<String> {
    let name = |w: &Wanted| w.cache.to_string_lossy().replace('\\', "/");
    let mut lines = Vec::new();
    let mut missing = Vec::new();
    let mut late = Vec::new();
    // Files that failed for the same reasons (a source offline fails them all) share a line.
    let mut kept: Vec<(String, Vec<String>)> = Vec::new();
    for (w, o) in done {
        match o {
            Outcome::Saved(i, via) => lines.push(format!("game data: {} updated from source {} ({}{})", name(w), i + 1, host_of(&bases[*i]), via_text(via))),
            Outcome::Same(i, via) => lines.push(format!("game data: {} up to date (source {}{})", name(w), i + 1, via_text(via))),
            Outcome::Missing => missing.push(name(w)),
            Outcome::Late => late.push(name(w)),
            Outcome::Kept(why) => {
                let why = why.join("; ");
                match kept.iter_mut().find(|(w, _)| *w == why) {
                    Some((_, files)) => files.push(name(w)),
                    None => kept.push((why, vec![name(w)])),
                }
            }
        }
    }
    for (why, files) in kept {
        lines.push(format!("game data: {} not fetched ({why}); the cached copy, if any, is kept", files.join(", ")));
    }
    if !late.is_empty() {
        lines.push(format!("game data: {} took too long; the game starts with the cached copy, if any", late.join(", ")));
    }
    if !missing.is_empty() {
        lines.push(format!("game data: no source has {}", missing.join(", ")));
    }
    lines
}

/// Before a game starts: this run's sources (`cli`, then the environment the game gets,
/// then Settings' `settings`), and on Windows the game's files fetched from them into the
/// cache under PeerParty's folder `data_dir`. Logs what it did; never fails the start.
pub fn before_start(cli: &[String], env: &mut crate::launch::ChildEnv, settings: &str, exe: &Path, data_dir: &Path) {
    let bases = prepare(cli, env, settings);
    #[cfg(windows)]
    if !bases.is_empty() {
        for line in report(&bases, &fetch_all(Arc::new(WinHttp), &bases, exe, &data_dir.join(FOLDER), WAIT)) {
            eprintln!("peerparty: {line}");
        }
    }
    #[cfg(not(windows))]
    let _ = (bases, exe, data_dir);
}

/// This run's sources, logged, and put in the environment the game's start gets: the
/// peerparty.exe that starts the game (inside Proton on Linux) fetches, and on Linux this
/// process only hands it the list.
fn prepare(cli: &[String], env: &mut crate::launch::ChildEnv, settings: &str) -> Vec<String> {
    use peerparty_protocol::env::DATA_SOURCES;
    let from_env = env.get(DATA_SOURCES).map(|v| v.to_string_lossy().into_owned());
    let (bases, from, refused) = chosen(cli, from_env.as_deref(), settings);
    for line in refused {
        eprintln!("peerparty: {line}");
    }
    if !bases.is_empty() {
        eprintln!("peerparty: game data: {} source(s), from {}", bases.len(), from.name());
        env.set(DATA_SOURCES, bases.join(";"));
    } else if cfg!(not(windows)) {
        // No source: said explicitly to Windows' peerparty.exe inside Proton, which would
        // otherwise read the Wine prefix's own Settings.
        env.set(DATA_SOURCES, ";");
    }
    bases
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Answers by URL; anything else is a 404. Records what was asked.
    #[derive(Default)]
    struct Fake {
        answers: HashMap<String, Result<Got, Failure>>,
        asked: Mutex<Vec<String>>,
        delay: Duration,
    }

    impl Fake {
        fn with(self, url: &str, answer: Result<&str, Failure>) -> Self {
            self.with_from(url, answer, url)
        }
        /// An answer that came from `from` (the source redirected there).
        fn with_from(mut self, url: &str, answer: Result<&str, Failure>, from: &str) -> Self {
            self.answers.insert(url.into(), answer.map(|s| Got { body: s.as_bytes().to_vec(), url: from.into() }));
            self
        }
        fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().clone()
        }
    }

    impl Fetch for Fake {
        fn get(&self, url: &str, max: usize) -> Result<Got, Failure> {
            self.asked.lock().unwrap().push(url.into());
            std::thread::sleep(self.delay);
            match self.answers.get(url).cloned().unwrap_or(Err(Failure::Status(404))) {
                Ok(g) if g.body.len() > max => Err(Failure::Other("the answer is too long".into())),
                other => other,
            }
        }
    }

    fn root(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("peerparty-sources-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    const CONFIG: &str = r#"{"hosts": ["api.example.invalid"], "templates": {"party": {"max_players": 4}}, "kv": {"k": "v"}}"#;
    const PATTERNS: &str = r#"{"versions": [{"curl_easy_setopt_patterns": ["48 89 5C 24 08 57 ??"]}]}"#;
    const A: &str = "https://a.example.invalid/data";
    const B: &str = "https://b.example.invalid";

    fn bases() -> Vec<String> {
        vec![A.into(), B.into()]
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    #[test]
    fn sources_are_https_folders_and_nothing_else() {
        assert_eq!(base("https://a.example.invalid/peerparty-data/"), Ok("https://a.example.invalid/peerparty-data".into()));
        assert_eq!(base(" HTTPS://a.example.invalid "), Ok("https://a.example.invalid".into()));
        assert_eq!(base("https://127.0.0.1:8443/x//"), Ok("https://127.0.0.1:8443/x".into()));
        assert_eq!(base("https://[::1]:8443/x"), Ok("https://[::1]:8443/x".into()));
        for (bad, why) in [
            ("http://a.example.invalid/x", "only https sources are used, not http"),
            ("FTP://a.example.invalid/x", "only https sources are used, not ftp"),
            ("file:///C:/data", "only https sources are used, not file"),
            ("a.example.invalid/x", "it doesn't start with https://"),
            ("https://user:pw@a.example.invalid/x", "a user name or password in it: sources are public, nothing is signed in to"),
            ("https://a.example.invalid/x?token=1", "a ? or # in it: a source is a folder"),
            ("https://a.example.invalid/x#y", "a ? or # in it: a source is a folder"),
            ("https:///x", "no host in it"),
            ("https://a.example.invalid:0/x", "a bad port in it"),
            ("https://a.example.invalid:70000/x", "a bad port in it"),
            ("https://[::1/x", "a bad port in it"),
            ("https://a.example.invalid\\x", "a space, backslash or control character in it"),
        ] {
            assert_eq!(base(bad), Err(why.to_string()), "{bad}");
        }
        assert!(base(&format!("https://a.example.invalid/{}", "x".repeat(MAX_ADDRESS))).is_err());
    }

    #[test]
    fn the_command_line_then_the_environment_then_settings() {
        let settings = "https://s.example.invalid";
        let (b, from, _) = chosen(&[], None, settings);
        assert_eq!((b, from), (vec![settings.to_string()], Origin::Settings));
        let (b, from, _) = chosen(&[], Some("https://e1.example.invalid; https://e2.example.invalid"), settings);
        assert_eq!((b, from), (vec!["https://e1.example.invalid".to_string(), "https://e2.example.invalid".into()], Origin::Environment));
        // Set but empty, or separators only (the Linux launcher's "none"): none for this run,
        // Settings' list isn't used.
        for none in ["", ";", " ; ;"] {
            let (b, from, _) = chosen(&[], Some(none), settings);
            assert_eq!((b.len(), from), (0, Origin::Environment), "{none:?}");
        }
        let cli = vec!["https://c1.example.invalid".to_string(), "https://c2.example.invalid/".into()];
        let (b, from, _) = chosen(&cli, Some("https://e1.example.invalid"), settings);
        assert_eq!((b, from), (vec!["https://c1.example.invalid".to_string(), "https://c2.example.invalid".into()], Origin::CommandLine));
        // Nothing anywhere: no source, nothing fetched.
        assert_eq!(chosen(&[], None, "").0.len(), 0);
    }

    #[test]
    fn refused_and_repeated_sources_are_left_out_in_order() {
        let list = "http://x.example.invalid/p https://a.example.invalid https://user:secret@y.example.invalid/z;https://A.example.invalid/ https://b.example.invalid https://c.example.invalid/x?token=hidden";
        let (b, _, lines) = chosen(&[], None, list);
        assert_eq!(b, ["https://a.example.invalid", "https://b.example.invalid"]);
        assert_eq!(lines.len(), 3);
        // Scheme and host only: no path, user name, password or query in the log.
        assert!(lines[0].starts_with("data source http://x.example.invalid (from Settings) is refused: only https"), "{lines:?}");
        assert!(lines[1].starts_with("data source https://y.example.invalid (from Settings) is refused: a user name or password"), "{lines:?}");
        assert!(lines[2].starts_with("data source https://c.example.invalid (from Settings) is refused: a ? or #"), "{lines:?}");
        assert!(lines.iter().all(|l| !l.contains("secret") && !l.contains("user:") && !l.contains("token") && !l.contains("/p ") && !l.contains("/z")), "{lines:?}");
        let many: Vec<String> = (0..MAX_SOURCES + 2).map(|n| format!("https://s{n}.example.invalid/k?x={n}")).collect();
        let (b, _, lines) = chosen(&[], None, &many.iter().map(|s| s.replace('?', "/")).collect::<Vec<_>>().join(";"));
        assert_eq!(b.len(), MAX_SOURCES);
        assert_eq!(lines, [format!("more than {MAX_SOURCES} data sources: https://s8.example.invalid and the ones after it are left out")]);
    }

    /// One source: the scheme and host in any case, the path as written.
    #[test]
    fn a_source_is_its_host_in_any_case_and_its_path_as_written() {
        let (b, _, _) = chosen(&[], None, "https://a.example.invalid/Data https://A.EXAMPLE.invalid/Data https://a.example.invalid/data HTTPS://a.example.INVALID/Data/");
        assert_eq!(b, ["https://a.example.invalid/Data", "https://a.example.invalid/data"]);
        assert!(same_source("https://a.example.invalid:8443/x", "https://A.example.invalid:8443/x"));
        assert!(!same_source("https://a.example.invalid:8443/x", "https://a.example.invalid/x"));
        assert_eq!(shown("https://u:p@h.example.invalid:8443/a?b#c"), "https://h.example.invalid:8443");
        assert_eq!(shown("h.example.invalid/a"), "h.example.invalid");
    }

    #[test]
    fn only_this_games_files_with_their_names_escaped() {
        let w = wanted(Path::new(r"C:\Games\Lantern Keep\Lantern Keep+Été-Win64.exe"));
        let paths: Vec<&str> = w.iter().map(|w| w.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "patterns/Lantern%20Keep%2B%C3%89t%C3%A9-Win64.exe.json",
                "rallyhere/lantern%20keep%2B%C3%89t%C3%A9-win64/config.json",
                "rallyhere/lantern%20keep%2B%C3%89t%C3%A9-win64/harvested/template.json",
                "rallyhere/lantern%20keep%2B%C3%89t%C3%A9-win64/harvested/kv.json",
                "rallyhere/lantern%20keep%2B%C3%89t%C3%A9-win64/harvested/regions.json",
                "rallyhere/lantern%20keep%2B%C3%89t%C3%A9-win64/harvested/instance.json",
            ]
        );
        // The cache keeps the names as the hook looks them up: the exe's file name, the
        // stem lowercased (ASCII only, as the hook does).
        assert_eq!(w[0].cache, Path::new("patterns").join("Lantern Keep+Été-Win64.exe.json"));
        assert_eq!(w[1].cache, Path::new("rallyhere").join("lantern keep+Été-win64").join("config.json"));
        assert_eq!(w[4].cache, Path::new("rallyhere").join("lantern keep+Été-win64").join("harvested").join("regions.json"));
        assert_eq!((w[0].kind, w[1].kind, w[5].kind), (Kind::Patterns, Kind::Config, Kind::Harvested("instance.json")));
        assert_eq!(segment("a/b?c#d%e"), "a%2Fb%3Fc%23d%25e");
        assert_eq!(segment("Az09-._~"), "Az09-._~");
        assert!(wanted(Path::new("")).is_empty());

        let r = root("only");
        let fake = Arc::new(Fake::default());
        fetch_all(fake.clone(), &bases(), Path::new(r"C:\g\Tide.exe"), &r, Duration::from_secs(10));
        let mut asked = fake.asked();
        asked.sort();
        assert_eq!(asked.len(), 12, "6 files from 2 sources: {asked:?}");
        assert!(asked.iter().all(|u| u.contains("/patterns/Tide.exe.json") || u.contains("/rallyhere/tide/")), "{asked:?}");
        assert!(!r.exists(), "nothing found, nothing written");
    }

    #[test]
    fn the_first_source_that_has_a_file_wins() {
        let r = root("first");
        let fake = Fake::default()
            .with(&format!("{B}/patterns/Tide.exe.json"), Ok(PATTERNS))
            .with(&format!("{A}/rallyhere/tide/config.json"), Ok(CONFIG))
            .with(&format!("{B}/rallyhere/tide/config.json"), Ok(r#"{"kv": {"from": "b"}}"#));
        let w = wanted(Path::new("Tide.exe"));
        assert_eq!(fetch_one(&fake, &bases(), &w[0], &r, far()), Outcome::Saved(1, None));
        assert_eq!(fetch_one(&fake, &bases(), &w[1], &r, far()), Outcome::Saved(0, None));
        assert_eq!(fs::read_to_string(r.join(&w[1].cache)).unwrap(), CONFIG);
        assert_eq!(fs::read_to_string(r.join(&w[0].cache)).unwrap(), PATTERNS);
        // A's config was found: B was never asked for it.
        assert!(!fake.asked().contains(&format!("{B}/rallyhere/tide/config.json")));
        // Again: the same file, left as it was.
        assert_eq!(fetch_one(&fake, &bases(), &w[1], &r, far()), Outcome::Same(0, None));
        let _ = fs::remove_dir_all(&r);
    }

    /// The hook's own checks decide (protocol's `gamedata`): what it reads whole is kept, what
    /// it refuses or reads only in part isn't. The refused cases are the hook's own tests'.
    #[test]
    fn files_are_kept_only_when_the_hook_takes_them_whole() {
        // Notes (`_` keys) are fine everywhere.
        for (kind, good) in [
            (Kind::Patterns, PATTERNS),
            (Kind::Patterns, r#"{"_comment": ["n"], "versions": [{"_note": "x", "file_version": "1.2.3.4", "curl_easy_setopt_patterns": ["48 89 5C 24 08 57 48 83 EC 20"]}]}"#),
            (Kind::Config, CONFIG),
            (Kind::Config, "{}"),
            (Kind::Config, r#"{"_note": [1], "templates": {"_note": "x", "t": {"joinable": true}}, "kv": {"_c": "note", "k": "v"}}"#),
            (Kind::Harvested("template.json"), r#"{"_note": 1, "party": {"num_teams": 2}}"#),
            (Kind::Harvested("kv.json"), r#"{"k": "v", "_c": 1}"#),
            (Kind::Harvested("regions.json"), r#"[{"region_id": "1"}]"#),
            (Kind::Harvested("instance.json"), r#"{"instance_startup_params": {"map": ""}, "join_params": {"private_conn_str": ""}}"#),
        ] {
            assert_eq!(check(kind, good.as_bytes()), Ok(()), "{kind:?} {good}");
        }
        assert_eq!(check(Kind::Config, format!("\u{feff}{CONFIG}").as_bytes()), Ok(()), "a byte order mark is fine");
        // Nested deeper than protocol's JSON reads (64 levels).
        let deep = format!("{{\"_n\": {}{}}}", "[".repeat(70), "]".repeat(70));
        let setopt = "48 89 5C 24 08 57 48 83 EC 20";
        for (kind, bad) in [
            (Kind::Config, "[1, 2]".to_string()),
            (Kind::Config, "not json".into()),
            (Kind::Config, "{\"a\": 1".into()),
            (Kind::Config, deep.clone()),
            (Kind::Config, r#"{"hosts": null}"#.into()),
            (Kind::Config, r#"{"hosts": "api.example.invalid"}"#.into()),
            (Kind::Config, r#"{"hosts": [1]}"#.into()),
            (Kind::Config, r#"{"templates": []}"#.into()),
            (Kind::Config, r#"{"templates": {"t": 1}}"#.into()),
            (Kind::Config, r#"{"templates": {"t": {"joinable": "yes"}}}"#.into()),
            (Kind::Config, r#"{"templates": {"t": {"num_teams": 1.5}}}"#.into()),
            (Kind::Config, r#"{"templates": {"t": {"player_visibility": "ALMOST"}}}"#.into()),
            (Kind::Config, r#"{"kv": {"k": 1}}"#.into()),
            (Kind::Config, r#"{"instance": "x"}"#.into()),
            (Kind::Config, r#"{"instance": {"instance_startup_params": {"map": null}}}"#.into()),
            (Kind::Config, r#"{"instance": {"join_params": {"private_conn_str": 1}}}"#.into()),
            (Kind::Patterns, "{}".into()),
            (Kind::Patterns, deep.clone()),
            (Kind::Patterns, r#"{"versions": ["x"]}"#.into()),
            (Kind::Patterns, r#"{"versions": [{"curl_easy_setopt_patterns": [1]}]}"#.into()),
            (Kind::Patterns, format!(r#"{{"versions": [{{"sha256": "00", "curl_easy_setopt_patterns": ["{setopt}"]}}]}}"#)),
            (Kind::Patterns, format!(r#"{{"versions": [{{"curl_easy_setopt_patterns": ["{setopt}"], "curl_easy_mystery_patterns": ["{setopt}"]}}]}}"#)),
            (Kind::Patterns, format!(r#"{{"versions": [{{"curl_easy_setopt_patterns": ["{setopt}", "48 89 5C 24 ??"]}}]}}"#)),
            (Kind::Patterns, format!(r#"{{"versions": [{{"curl_easy_setopt_patterns": ["{setopt}"], "Typo": []}}]}}"#)),
            (Kind::Harvested("regions.json"), "{}".into()),
            (Kind::Harvested("regions.json"), "[1]".into()),
            (Kind::Harvested("regions.json"), "[{}]".into()),
            (Kind::Harvested("regions.json"), r#"[{"region_id": "a", "description": null}]"#.into()),
            (Kind::Harvested("template.json"), r#"{"party": 1}"#.into()),
            (Kind::Harvested("template.json"), r#"{"party": {"joinable": "yes"}}"#.into()),
            (Kind::Harvested("kv.json"), r#"{"k": {}}"#.into()),
            (Kind::Harvested("instance.json"), "[]".into()),
            (Kind::Harvested("instance.json"), r#"{"join_params": {"private_conn_str": 1}}"#.into()),
            (Kind::Harvested("other.json"), "{}".into()),
        ] {
            assert!(check(kind, bad.as_bytes()).is_err(), "{kind:?} {:?}", &bad[..bad.len().min(60)]);
        }
        assert_eq!(check(Kind::Config, b"\xff\xfe{}"), Err("not UTF-8 text".into()));
        // The size caps: 256 KiB for RallyHere files, 1 MiB for patterns.
        let padded = |n: usize| format!("{{\"kv\": {{}}, \"_pad\": \"{}\"}}", "x".repeat(n - 22)).into_bytes();
        assert_eq!(padded(MAX_RALLYHERE).len(), MAX_RALLYHERE);
        assert_eq!(check(Kind::Config, &padded(MAX_RALLYHERE)), Ok(()));
        assert!(check(Kind::Config, &padded(MAX_RALLYHERE + 1)).unwrap_err().contains("256 KiB"));
        let big = format!("{{\"versions\": [{{\"curl_easy_setopt_patterns\": [\"{}\"]}}]}}", "9".repeat(MAX_PATTERNS));
        assert!(check(Kind::Patterns, big.as_bytes()).unwrap_err().contains("1024 KiB"));
        let kv = |n: usize| format!("{{{}}}", (0..n).map(|i| format!("\"k{i}\": \"v\"")).collect::<Vec<_>>().join(","));
        assert_eq!(check(Kind::Harvested("kv.json"), kv(rallyhere::MAX_KV).as_bytes()), Ok(()));
        assert!(check(Kind::Harvested("kv.json"), kv(rallyhere::MAX_KV + 1).as_bytes()).is_err());
    }

    #[test]
    fn a_bad_file_isnt_cached_and_the_next_source_is_asked() {
        let r = root("bad");
        let w = &wanted(Path::new("Tide.exe"))[1];
        let fake = Fake::default().with(&format!("{A}/rallyhere/tide/config.json"), Ok("<html>not found</html>")).with(&format!("{B}/rallyhere/tide/config.json"), Ok(CONFIG));
        assert_eq!(fetch_one(&fake, &bases(), w, &r, far()), Outcome::Saved(1, None));
        assert_eq!(fs::read_to_string(r.join(&w.cache)).unwrap(), CONFIG);
        // Only bad files: nothing replaces the cached one.
        let fake = Fake::default().with(&format!("{A}/rallyhere/tide/config.json"), Ok("[]")).with(&format!("{B}/rallyhere/tide/config.json"), Ok(&"x".repeat(MAX_RALLYHERE + 1)));
        match fetch_one(&fake, &bases(), w, &r, far()) {
            Outcome::Kept(why) => assert!(why[0].contains("source 1: refused, isn't a JSON object") && why[1].contains("source 2"), "{why:?}"),
            o => panic!("{o:?}"),
        }
        assert_eq!(fs::read_to_string(r.join(&w.cache)).unwrap(), CONFIG);
        let _ = fs::remove_dir_all(&r);
    }

    #[test]
    fn offline_or_missing_keeps_the_cached_file() {
        let r = root("keep");
        let w = &wanted(Path::new("Tide.exe"))[0];
        write_whole(&r.join(&w.cache), PATTERNS.as_bytes()).unwrap();
        // 404 on every source: nothing removed.
        assert_eq!(fetch_one(&Fake::default(), &bases(), w, &r, far()), Outcome::Missing);
        assert_eq!(fs::read_to_string(r.join(&w.cache)).unwrap(), PATTERNS);
        // Unreachable, or a server error: kept, and the log says why.
        let fake = Fake::default().with(&format!("{A}/patterns/Tide.exe.json"), Err(Failure::Other("the request failed".into()))).with(&format!("{B}/patterns/Tide.exe.json"), Err(Failure::Status(503)));
        assert_eq!(fetch_one(&fake, &bases(), w, &r, far()), Outcome::Kept(vec!["source 1: the request failed".into(), "source 2: HTTP 503".into()]));
        assert_eq!(fs::read_to_string(r.join(&w.cache)).unwrap(), PATTERNS);
        // No source at all: nothing asked, nothing touched.
        assert_eq!(fetch_one(&Fake::default(), &[], w, &r, far()), Outcome::Missing);
        let lines = report(&bases(), &[(w.clone(), Outcome::Missing), (w.clone(), Outcome::Kept(vec!["source 1: HTTP 503".into()]))]);
        assert_eq!(lines, ["game data: patterns/Tide.exe.json not fetched (source 1: HTTP 503); the cached copy, if any, is kept", "game data: no source has patterns/Tide.exe.json"]);
        // A source offline fails every file the same way: one line for them.
        let all = wanted(Path::new("Tide.exe"));
        let offline: Vec<(Wanted, Outcome)> = all.iter().map(|w| (w.clone(), Outcome::Kept(vec!["source 1: couldn't connect".into()]))).collect();
        let lines = report(&bases(), &offline);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with("game data: patterns/Tide.exe.json, rallyhere/tide/config.json, ") && lines[0].ends_with(" not fetched (source 1: couldn't connect); the cached copy, if any, is kept"), "{lines:?}");
        let _ = fs::remove_dir_all(&r);
    }

    #[test]
    fn the_cache_is_written_whole_and_only_when_it_changes() {
        let r = root("whole");
        let file = r.join("rallyhere").join("tide").join("harvested").join("kv.json");
        assert_eq!(write_whole(&file, b"{\"a\": \"1\"}"), Ok(true));
        let first = fs::metadata(&file).unwrap().modified().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(write_whole(&file, b"{\"a\": \"1\"}"), Ok(false));
        assert_eq!(fs::metadata(&file).unwrap().modified().unwrap(), first, "unchanged: not rewritten");
        assert_eq!(write_whole(&file, b"{\"a\": \"2\"}"), Ok(true));
        assert_eq!(fs::read(&file).unwrap(), b"{\"a\": \"2\"}");
        let left: Vec<_> = fs::read_dir(file.parent().unwrap()).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left, ["kv.json"], "no temporary file left");
        let _ = fs::remove_dir_all(&r);
    }

    #[test]
    fn a_slow_source_doesnt_hold_the_start() {
        let r = root("slow");
        let fake = Arc::new(Fake { delay: Duration::from_millis(1500), ..Fake::default() }.with(&format!("{A}/rallyhere/tide/config.json"), Ok(CONFIG)));
        let started = Instant::now();
        let done = fetch_all(fake, &bases(), Path::new("Tide.exe"), &r, Duration::from_millis(200));
        assert!(started.elapsed() < Duration::from_millis(1200), "{:?}", started.elapsed());
        assert_eq!(done.len(), 6);
        assert!(done.iter().all(|(_, o)| *o == Outcome::Late), "{done:?}");
        // The answer that comes after the start isn't written either.
        std::thread::sleep(Duration::from_millis(2000));
        assert!(!r.join("rallyhere").join("tide").join("config.json").exists());
        let _ = fs::remove_dir_all(&r);
    }

    #[test]
    fn a_whole_fetch_fills_the_cache_in_its_layout() {
        let r = root("all");
        let fake = Arc::new(
            Fake::default()
                .with(&format!("{A}/patterns/Tide.exe.json"), Ok(PATTERNS))
                .with(&format!("{B}/rallyhere/tide/config.json"), Ok(CONFIG))
                .with(&format!("{B}/rallyhere/tide/harvested/regions.json"), Ok(r#"[{"region_id": "1"}]"#))
                .with(&format!("{A}/rallyhere/tide/harvested/kv.json"), Ok(r#"{"kvs": {"k": "v"}}"#)),
        );
        let done = fetch_all(fake, &bases(), Path::new(r"D:\Games\Tide.exe"), &r, Duration::from_secs(10));
        let outcomes: Vec<&Outcome> = done.iter().map(|(_, o)| o).collect();
        assert_eq!(outcomes[..3], [&Outcome::Saved(0, None), &Outcome::Saved(1, None), &Outcome::Missing]);
        assert!(matches!(outcomes[3], Outcome::Kept(_)));
        assert_eq!(outcomes[4..], [&Outcome::Saved(1, None), &Outcome::Missing]);
        assert!(r.join("patterns").join("Tide.exe.json").is_file());
        assert!(r.join("rallyhere").join("tide").join("config.json").is_file());
        assert!(r.join("rallyhere").join("tide").join("harvested").join("regions.json").is_file());
        assert!(!r.join("rallyhere").join("tide").join("harvested").join("kv.json").exists());
        let lines = report(&bases(), &done);
        assert_eq!(lines[0], "game data: patterns/Tide.exe.json updated from source 1 (a.example.invalid)");
        assert_eq!(lines.last().unwrap(), "game data: no source has rallyhere/tide/harvested/template.json, rallyhere/tide/harvested/instance.json");
        let _ = fs::remove_dir_all(&r);
    }

    /// A source may send the file from another HTTPS host: kept, and the log names it.
    #[test]
    fn a_redirect_to_another_host_is_followed_and_logged() {
        let r = root("redirect");
        let w = &wanted(Path::new("Tide.exe"))[1];
        let fake = Fake::default().with_from(&format!("{A}/rallyhere/tide/config.json"), Ok(CONFIG), "https://files.example.invalid/blob/config.json?sig=secret");
        let o = fetch_one(&fake, &bases(), w, &r, far());
        assert_eq!(o, Outcome::Saved(0, Some("files.example.invalid".into())));
        assert_eq!(report(&bases(), &[(w.clone(), o)]), ["game data: rallyhere/tide/config.json updated from source 1 (a.example.invalid, redirected to files.example.invalid)"]);
        // The same host (any case): nothing to say.
        let fake = Fake::default().with_from(&format!("{A}/rallyhere/tide/config.json"), Ok(CONFIG), "https://A.example.invalid/other/config.json");
        assert_eq!(fetch_one(&fake, &bases(), w, &r, far()), Outcome::Same(0, None));
        let _ = fs::remove_dir_all(&r);
    }

    #[test]
    fn the_sources_go_to_the_game_and_settings_come_last() {
        use crate::launch::ChildEnv;
        use peerparty_protocol::env::DATA_SOURCES;
        let fresh = || {
            let mut env = ChildEnv::default();
            // The test's own environment mustn't decide.
            env.remove(DATA_SOURCES);
            env
        };
        let mut env = fresh();
        assert!(prepare(&[], &mut env, "").is_empty());
        // No source: nothing set on Windows; on Linux "none" said to Proton's peerparty.exe.
        let none = if cfg!(windows) { None } else { Some(std::ffi::OsString::from(";")) };
        assert_eq!(env.get(DATA_SOURCES), none);
        let mut env = fresh();
        assert_eq!(prepare(&[], &mut env, "http://x.example.invalid https://s.example.invalid/d/"), ["https://s.example.invalid/d"]);
        assert_eq!(env.get(DATA_SOURCES).unwrap(), "https://s.example.invalid/d");
        // A variable the start already has (a .bat's, the Linux launcher's) wins over Settings.
        let mut env = fresh();
        env.set(DATA_SOURCES, "https://e.example.invalid");
        assert_eq!(prepare(&[], &mut env, "https://s.example.invalid"), ["https://e.example.invalid"]);
        // And --data-source over both.
        assert_eq!(prepare(&["https://c.example.invalid".into()], &mut env, "https://s.example.invalid"), ["https://c.example.invalid"]);
        assert_eq!(env.get(DATA_SOURCES).unwrap(), "https://c.example.invalid");
    }

    /// A real source: `PPTEST_DATA_SOURCE` (a base address) and `PPTEST_DATA_EXE` (a game's
    /// exe file name). Needs the internet (or a local HTTPS server Windows trusts).
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn fetches_from_a_real_source() {
        let (Ok(source), Ok(exe)) = (std::env::var("PPTEST_DATA_SOURCE"), std::env::var("PPTEST_DATA_EXE")) else {
            eprintln!("PPTEST_DATA_SOURCE and PPTEST_DATA_EXE unset: skipped");
            return;
        };
        let r = root("real");
        let (bases, _, refused) = chosen(&[source], None, "");
        assert!(refused.is_empty(), "{refused:?}");
        let done = fetch_all(Arc::new(WinHttp), &bases, Path::new(&exe), &r, WAIT);
        for line in report(&bases, &done) {
            eprintln!("{line}");
        }
        for (w, o) in &done {
            if matches!(o, Outcome::Saved(..) | Outcome::Same(..)) {
                assert_eq!(check(w.kind, &fs::read(r.join(&w.cache)).unwrap()), Ok(()));
            }
        }
        eprintln!("cache: {}", r.display());
    }
}
