//! The player's hooks files: functions PeerParty hooks in a module that doesn't export
//! them (a library linked into a game's exe or into one of its DLLs), found by their
//! bytes (sys/scan.rs). Bytes change from one build of a module to the next, so each
//! module has a file of its own, `%LOCALAPPDATA%\peerparty\patterns\<module>.json` (the
//! module's file name, `MyGame-Win64-Shipping.exe.json`; `PEERPARTY_PATTERNS_DIR` names
//! another folder), and its patterns are tied to a build by the module's SHA-256 or its
//! file version. PeerParty only reads these files. A module with no file there falls back to
//! the launcher's cache of the files fetched from the player's sources
//! (`%LOCALAPPDATA%\peerparty\remote\patterns`); the player's file always wins, and when
//! `PEERPARTY_PATTERNS_DIR` is set only that folder is read.
//!
//! ```json
//! { "versions": [
//!     { "sha256": "9f86d0...", "curl_easy_setopt_patterns": [ "..." ], "curl_easy_cleanup_patterns": [ "..." ] },
//!     { "file_version": "4.27.2.0", "curl_easy_setopt_patterns": [ "..." ], "curl_easy_cleanup_patterns": [ "..." ] },
//!     { "curl_easy_setopt_patterns": [ "..." ], "curl_easy_cleanup_patterns": [ "..." ] } ] }
//! ```
//!
//! An entry applies when everything it names matches (no `sha256` or `file_version`: any
//! build). Of the entries that apply, one with a SHA-256 wins over one with a version,
//! which wins over one with neither; then the first. Within an entry, a function may
//! list several patterns: the first that matches exactly one place is used. Keys that
//! start with `_` are notes.

use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::log;
#[cfg(test)]
use crate::sys::scan::Pattern;

// The file's shape and its parser are shared with the launcher, which checks the files it
// fetches for the cache with them (protocol/src/gamedata/patterns.rs).
use peerparty_protocol::gamedata::patterns::MAX_FILE;
pub use peerparty_protocol::gamedata::patterns::{Function, ModuleHooks, parse};

/// The folders the files are in, in the order they are read: the player's own, then the
/// launcher's cache of the files fetched from the player's sources
/// (`%LOCALAPPDATA%\peerparty\remote\patterns`). `PEERPARTY_PATTERNS_DIR` names the only
/// folder read when it is set.
fn dirs() -> Vec<PathBuf> {
    dirs_of(super::HookConfig::global().patterns_dir.clone(), crate::util::local_store::peerparty_dir())
}

fn dirs_of(named: Option<PathBuf>, peerparty: Option<PathBuf>) -> Vec<PathBuf> {
    if let Some(d) = named {
        return vec![d];
    }
    let Some(base) = peerparty else { return Vec::new() };
    vec![base.join("patterns"), base.join("remote").join("patterns")]
}

/// The entry for the module loaded at `base` from `path`, named `name`, if its file
/// has one for this build. The module's SHA-256 is only worked out when an entry names
/// one, or to say in the log what an entry would need.
pub fn for_module(name: &str, base: usize, path: &str) -> Option<ModuleHooks> {
    for_module_in(&dirs(), name, base, path)
}

/// The first of `dirs` that holds a usable file for the module is the one read, whatever it
/// has for this build: a player's file wins over the cache's, and a build only the cache
/// knows gets no entry from the cache when the player's file doesn't have it. A file that is
/// too big, unreadable or has no usable entry counts as absent (and says so in the log).
fn for_module_in(dirs: &[PathBuf], name: &str, base: usize, path: &str) -> Option<ModuleHooks> {
    // A loader name is a file name; anything else can't name a file of ours.
    if name.is_empty() || name.contains(['/', '\\', ':']) || name.starts_with('.') {
        return None;
    }
    let (file, entries) = dirs.iter().find_map(|dir| {
        let file = dir.join(format!("{name}.json"));
        read_entries(&file).map(|e| (file, e))
    })?;
    let version = unsafe { crate::sys::pe::file_version(base as *const u8) };
    let mut hash = None;
    let mut sha = || hash.get_or_insert_with(|| sha256_of(Path::new(path))).clone();
    let wants_hash = entries.iter().any(|e| e.sha256.is_some());
    let found = choose(&entries, version.as_deref(), || if wants_hash { sha() } else { None });
    let shown = |h: Option<String>| h.map(|h| format!(", sha256 {h}")).unwrap_or_default();
    match found {
        Some(i) => {
            let by = ["for any build", "by its version", "by its sha256"][entries[i].rank() as usize];
            log!("hooks: {name} (version {}): entry {} of {} applies, {by}", version.as_deref().unwrap_or("none"), i + 1, file.display());
            Some(entries[i].clone())
        }
        None => {
            log!(
                "hooks: {name} (version {}{}): no entry of {} is for this build",
                version.as_deref().unwrap_or("none"),
                shown(sha()),
                file.display()
            );
            None
        }
    }
}

/// The entries of the file at `file`: None when there is no such file or it can't be used
/// (the log says why). The file is untrusted, wherever it is: bounded and parsed the same.
fn read_entries(file: &Path) -> Option<Vec<ModuleHooks>> {
    let size = std::fs::metadata(file).ok().filter(|m| m.is_file())?.len();
    if size > MAX_FILE {
        log!("hooks: {} is over {MAX_FILE} bytes; not read", file.display());
        return None;
    }
    let Ok(text) = std::fs::read_to_string(file) else {
        log!("hooks: {} can't be read", file.display());
        return None;
    };
    let (entries, problems) = parse(&text);
    for p in &problems {
        log!("hooks: {}: {p}", file.display());
    }
    if entries.is_empty() {
        return None;
    }
    Some(entries)
}

/// The entry that applies (its index), for a module with `version` and the SHA-256
/// `hash` gives (asked only when an entry names one).
pub fn choose(entries: &[ModuleHooks], version: Option<&str>, hash: impl FnOnce() -> Option<String>) -> Option<usize> {
    let mut hash = Some(hash);
    let mut known: Option<Option<String>> = None;
    let mut best: Option<usize> = None;
    for (i, e) in entries.iter().enumerate() {
        if let Some(want) = &e.sha256 {
            let have = known.get_or_insert_with(|| hash.take().and_then(|f| f()));
            if have.as_deref() != Some(want.as_str()) {
                continue;
            }
        }
        if let Some(want) = &e.file_version {
            if version != Some(want.as_str()) {
                continue;
            }
        }
        if best.is_none_or(|b| e.rank() > entries[b].rank()) {
            best = Some(i);
        }
    }
    best
}

/// A file's SHA-256, lowercase hex, read in pieces (a game's exe can be hundreds of MB).
fn sha256_of(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(crate::util::encoding::hex(&hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SETOPT: &str = "89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20";

    fn entry(sha256: Option<&str>, version: Option<&str>) -> ModuleHooks {
        ModuleHooks {
            sha256: sha256.map(str::to_string),
            file_version: version.map(str::to_string),
            functions: vec![(Function::CurlEasySetopt, vec![Pattern::parse(SETOPT).unwrap()])],
        }
    }

    #[test]
    fn a_hooks_file_reads() {
        let text = format!(
            r#"{{ "_comment": "notes",
              "versions": [
                {{ "sha256": "{}", "_note": "x", "curl_easy_setopt_patterns": [ "{SETOPT}", "not a pattern", "01 02" ], "Typo": [] }},
                {{ "file_version": " 1.2.3.4 ", "curl_easy_cleanup_patterns": [ "40 53 48 83 EC 20 48 8B D9 48 85 C9 0F 84 ?? ?? 00 00" ] }},
                {{ "sha256": "short", "curl_easy_setopt_patterns": [ "{SETOPT}" ] }},
                {{ "curl_easy_reset_patterns": [ 5 ] }}
              ] }}"#,
            "AB".repeat(32)
        );
        let (hooks, problems) = parse(&text);
        assert_eq!(hooks.len(), 2, "{problems:?}");
        assert_eq!(hooks[0].sha256.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(hooks[0].patterns(Function::CurlEasySetopt).len(), 1);
        assert_eq!(hooks[1].file_version.as_deref(), Some("1.2.3.4"));
        assert_eq!(hooks[1].patterns(Function::CurlEasyCleanup).len(), 1);
        assert!(hooks[1].patterns(Function::CurlEasyReset).is_empty());
        // Two bad patterns, the typo, the short hash, the entry with nothing usable.
        assert_eq!(problems.len(), 6, "{problems:?}");
        assert!(problems.iter().any(|p| p.contains("Typo")));
        assert_eq!(Function::CurlEasyReset.name(), "curl_easy_reset");
    }

    #[test]
    fn the_most_specific_matching_entry_applies() {
        let h = "ab".repeat(32);
        let entries = vec![entry(None, None), entry(None, Some("1.0.0.0")), entry(Some(&h), None), entry(Some(&h), Some("2.0.0.0"))];
        // By hash, over the version and the catch-all.
        assert_eq!(choose(&entries, Some("1.0.0.0"), || Some(h.clone())), Some(2));
        // An entry needs all it names: hash right, version wrong.
        assert_eq!(choose(&entries[3..], Some("1.0.0.0"), || Some(h.clone())), None);
        assert_eq!(choose(&entries[3..], Some("2.0.0.0"), || Some(h.clone())), Some(0));
        // Another build: by version, else the catch-all.
        assert_eq!(choose(&entries, Some("1.0.0.0"), || Some("cd".repeat(32))), Some(1));
        assert_eq!(choose(&entries, Some("9.9.9.9"), || None), Some(0));
        assert_eq!(choose(&entries, None, || None), Some(0));
        // No catch-all: nothing for an unknown build.
        assert_eq!(choose(&entries[1..], Some("9.9.9.9"), || None), None);
        // The hash is worked out only when an entry names one.
        assert_eq!(choose(&entries[..2], Some("1.0.0.0"), || panic!("hashed")), Some(1));
    }

    #[test]
    fn a_files_sha256_is_its_contents() {
        let path = std::env::temp_dir().join(format!("peerparty-hooks-test-{}", std::process::id()));
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(sha256_of(&path).as_deref(), Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        std::fs::remove_file(&path).unwrap();
        assert_eq!(sha256_of(&path), None);
    }

    /// docs/examples/patterns/ reads as the docs say, with nothing left out.
    #[test]
    fn the_example_file_reads() {
        let (hooks, problems) = parse(include_str!("../../../docs/examples/patterns/MyGame-Win64-Shipping.exe.json"));
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(hooks.len(), 3);
        assert!(hooks.iter().all(|m| !m.patterns(Function::CurlEasySetopt).is_empty() && !m.patterns(Function::CurlEasyCleanup).is_empty()));
        assert_eq!(hooks.iter().map(ModuleHooks::rank).collect::<Vec<_>>(), [2, 1, 0]);
    }

    #[test]
    fn a_broken_file_reads_as_none() {
        assert_eq!(parse("{").0, Vec::new());
        assert_eq!(parse("[]").0, Vec::new());
        assert_eq!(parse("{\"versions\": 3}").0, Vec::new());
        assert_eq!(parse("{\"Modules\": {}}").1, vec!["no \"versions\" list".to_string()]);
    }

    /// A loaded module's file in a folder of hooks files: its entry by its version, then by
    /// its SHA-256; another build's entries don't apply.
    #[test]
    fn a_loaded_modules_file_is_found_and_its_build_told() {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
        let wide: Vec<u16> = "kernel32.dll".encode_utf16().chain(Some(0)).collect();
        let base = unsafe { GetModuleHandleW(wide.as_ptr()) } as usize;
        let path = Path::new(&std::env::var("SystemRoot").unwrap()).join("System32").join("kernel32.dll");
        let path = path.to_str().unwrap();
        let version = unsafe { crate::sys::pe::file_version(base as *const u8) }.unwrap();
        let hash = sha256_of(Path::new(path)).unwrap();
        let dir = std::env::temp_dir().join(format!("peerparty-hooks-dir-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // The file's name in any case, as Windows finds it.
        let write = |entries: &[String]| std::fs::write(dir.join("KERNEL32.DLL.json"), format!("{{\"versions\": [{}]}}", entries.join(","))).unwrap();
        let e = |cond: String, byte: &str| format!(r#"{{ {cond} "curl_easy_setopt_patterns": [ "{byte} 01 02 03 04 05" ] }}"#);
        let first = |m: Option<ModuleHooks>| m.map(|m| m.patterns(Function::CurlEasySetopt)[0].clone());
        let p = |byte: &str| Some(Pattern::parse(&format!("{byte} 01 02 03 04 05")).unwrap());
        let by_version = |v: &str| format!(r#""file_version": "{v}","#);
        write(&[e(by_version("0.0.0.1"), "AA"), e(by_version(&version), "BB"), e(String::new(), "CC")]);
        assert_eq!(first(for_module_in(std::slice::from_ref(&dir), "kernel32.dll", base, path)), p("BB"));
        write(&[e(by_version(&version), "BB"), e(format!(r#""sha256": "{}","#, hash.to_uppercase()), "DD")]);
        assert_eq!(first(for_module_in(std::slice::from_ref(&dir), "kernel32.dll", base, path)), p("DD"));
        write(&[e(by_version("0.0.0.1"), "AA")]);
        assert_eq!(for_module_in(std::slice::from_ref(&dir), "kernel32.dll", base, path), None);
        assert_eq!(for_module_in(std::slice::from_ref(&dir), "user32.dll", base, path), None, "no file");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn temp(tag: &str) -> PathBuf {
        let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        let d = std::env::temp_dir().join(format!("peerparty-hooks-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A file of one catch-all entry whose setopt pattern starts with `byte`.
    fn file_of(byte: &str) -> String {
        format!(r#"{{"versions": [{{ "curl_easy_setopt_patterns": [ "{byte} 01 02 03 04 05" ] }}]}}"#)
    }

    fn first_byte(m: Option<ModuleHooks>) -> Option<Pattern> {
        m.map(|m| m.patterns(Function::CurlEasySetopt)[0].clone())
    }

    #[test]
    fn the_players_file_wins_over_the_cached_one() {
        let (local, cache) = (temp("local"), temp("cache"));
        let dirs = [local.clone(), cache.clone()];
        let p = |byte: &str| Some(Pattern::parse(&format!("{byte} 01 02 03 04 05")).unwrap());
        let read = || first_byte(for_module_in(&dirs, "game.exe", 0, ""));
        assert_eq!(read(), None, "neither has a file");
        std::fs::write(cache.join("game.exe.json"), file_of("CC")).unwrap();
        assert_eq!(read(), p("CC"), "the cache alone is used");
        std::fs::write(local.join("game.exe.json"), file_of("AA")).unwrap();
        assert_eq!(read(), p("AA"), "the player's file wins");
        // A player's file that can't be used counts as absent.
        std::fs::write(local.join("game.exe.json"), "not json").unwrap();
        assert_eq!(read(), p("CC"));
        std::fs::write(local.join("game.exe.json"), vec![b' '; MAX_FILE as usize + 1]).unwrap();
        assert_eq!(read(), p("CC"), "an oversized player's file is not read");
        // A cached file is bounded like any other.
        std::fs::remove_file(local.join("game.exe.json")).unwrap();
        std::fs::write(cache.join("game.exe.json"), vec![b' '; MAX_FILE as usize + 1]).unwrap();
        assert_eq!(read(), None, "an oversized cached file is refused");
        std::fs::write(cache.join("game.exe.json"), r#"{"versions": [{"curl_easy_setopt_patterns": ["zz"]}]}"#).unwrap();
        assert_eq!(read(), None, "a cached file with no usable entry is refused");
        // A valid file of the player's that has nothing for this build is still the file read.
        std::fs::write(cache.join("game.exe.json"), file_of("CC")).unwrap();
        std::fs::write(local.join("game.exe.json"), r#"{"versions": [{"file_version": "0.0.0.1", "curl_easy_setopt_patterns": ["AA 01 02 03 04 05"]}]}"#).unwrap();
        assert_eq!(read(), None, "the player's file is the one read, even without an entry for the build");
        let _ = std::fs::remove_dir_all(&local);
        let _ = std::fs::remove_dir_all(&cache);
    }

    #[test]
    fn a_named_folder_is_the_only_one_read() {
        let base = PathBuf::from(r"C:\pp");
        assert_eq!(dirs_of(Some(PathBuf::from(r"C:\own")), Some(base.clone())), [PathBuf::from(r"C:\own")]);
        assert_eq!(dirs_of(None, Some(base.clone())), [base.join("patterns"), base.join("remote").join("patterns")]);
        assert!(dirs_of(None, None).is_empty());
    }

    #[test]
    fn only_plain_file_names_name_a_file() {
        for bad in ["", "..\\x.exe", "a/b.dll", "C:x.exe", ".hidden"] {
            assert_eq!(for_module(bad, 0, ""), None, "{bad}");
        }
    }
}
