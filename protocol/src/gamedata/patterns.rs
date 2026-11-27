//! A player's curl patterns file (hook/src/config/hooks.rs): functions PeerParty hooks in
//! a module that doesn't export them, found by their bytes, one file per module
//! (`<module>.json`). The hook reads the files with `parse`, and the launcher checks a file
//! it fetched for the hook's cache (launcher/src/sources.rs) with it too, so that it never
//! keeps a file the hook would refuse.
//!
//! A pattern is hex bytes with `?` / `??` wildcards ("40 53 48 83 EC 20 ?? 8B D9"); the
//! hook searches a module's executable sections for it (hook/src/sys/scan.rs).

use crate::json::Json;

/// The most bytes a pattern may have, and the fewest it must fix (not wildcards): a
/// pattern of a few bytes matches by chance.
pub const MAX_LEN: usize = 256;
pub const MIN_FIXED: usize = 6;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pattern {
    /// Each byte, None for a wildcard.
    bytes: Vec<Option<u8>>,
    /// Where the first fixed byte is: the search looks for it, then compares the rest.
    anchor: usize,
}

impl Pattern {
    pub fn parse(text: &str) -> Result<Pattern, String> {
        let mut bytes = Vec::new();
        for token in text.split_whitespace() {
            if bytes.len() == MAX_LEN {
                return Err(format!("longer than {MAX_LEN} bytes"));
            }
            if token.chars().all(|c| c == '?') && token.len() <= 2 {
                bytes.push(None);
                continue;
            }
            match u8::from_str_radix(token, 16) {
                Ok(b) if token.len() == 2 => bytes.push(Some(b)),
                _ => return Err(format!("{token:?} is not a hex byte or ??")),
            }
        }
        let fixed = bytes.iter().filter(|b| b.is_some()).count();
        if fixed < MIN_FIXED {
            return Err(format!("only {fixed} fixed bytes, at least {MIN_FIXED} needed"));
        }
        let anchor = bytes.iter().position(Option::is_some).unwrap_or(0);
        Ok(Pattern { bytes, anchor })
    }

    /// Where it matches in `hay` (offsets), at most `max` of them.
    pub fn matches(&self, hay: &[u8], max: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let Some(first) = self.bytes[self.anchor] else { return out };
        if hay.len() < self.bytes.len() {
            return out;
        }
        let last_start = hay.len() - self.bytes.len();
        let mut from = 0;
        while from <= last_start && out.len() < max {
            // The anchor byte's next place, then the whole pattern there.
            let window = &hay[from + self.anchor..=last_start + self.anchor];
            let Some(i) = window.iter().position(|&b| b == first) else { break };
            let start = from + i;
            if self.bytes.iter().zip(&hay[start..]).all(|(p, h)| p.is_none_or(|p| p == *h)) {
                out.push(start);
            }
            from = start + 1;
        }
        out
    }
}

/// A function a hooks file can name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Function {
    CurlEasySetopt,
    CurlEasyCleanup,
    CurlEasyReset,
}

impl Function {
    /// Its key in an entry, and its name in the log.
    const ALL: [(Function, &'static str, &'static str); 3] = [
        (Function::CurlEasySetopt, "curl_easy_setopt_patterns", "curl_easy_setopt"),
        (Function::CurlEasyCleanup, "curl_easy_cleanup_patterns", "curl_easy_cleanup"),
        (Function::CurlEasyReset, "curl_easy_reset_patterns", "curl_easy_reset"),
    ];

    pub fn name(self) -> &'static str {
        Function::ALL.iter().find(|(f, _, _)| *f == self).map_or("?", |(_, _, n)| n)
    }
}

/// One entry of a module's file: the build it's for, and its patterns.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ModuleHooks {
    /// Lowercase hex.
    pub sha256: Option<String>,
    pub file_version: Option<String>,
    pub functions: Vec<(Function, Vec<Pattern>)>,
}

impl ModuleHooks {
    pub fn patterns(&self, f: Function) -> &[Pattern] {
        self.functions.iter().find(|(g, _)| *g == f).map_or(&[], |(_, p)| p)
    }

    /// How sure a match is: 2 by SHA-256, 1 by version, 0 for any build.
    pub fn rank(&self) -> u8 {
        if self.sha256.is_some() {
            2
        } else {
            u8::from(self.file_version.is_some())
        }
    }
}

/// The files are the player's own, but bounded all the same: one this big or entries
/// this many are a mistake, not a configuration.
pub const MAX_FILE: u64 = 1 << 20;
pub const MAX_ENTRIES: usize = 64;
pub const MAX_PATTERNS: usize = 16;

/// A file's entries, and what in it was left out and why.
pub fn parse(text: &str) -> (Vec<ModuleHooks>, Vec<String>) {
    let mut problems = Vec::new();
    let Some(root) = Json::parse(text.trim_start_matches('\u{feff}')) else {
        return (Vec::new(), vec!["not JSON".into()]);
    };
    let mut out: Vec<ModuleHooks> = Vec::new();
    for (n, entry) in root.get("versions").as_arr().iter().enumerate() {
        let at = format!("versions[{n}]");
        if out.len() == MAX_ENTRIES {
            problems.push(format!("more than {MAX_ENTRIES} entries; the rest are left out"));
            break;
        }
        let mut hooks = ModuleHooks::default();
        let mut usable = true;
        for (key, value) in entry.as_obj() {
            if key.starts_with('_') {
                continue;
            }
            if key == "sha256" {
                match value.as_str().map(|s| s.trim().to_ascii_lowercase()) {
                    Some(h) if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) => hooks.sha256 = Some(h),
                    _ => {
                        problems.push(format!("{at}: sha256 isn't 64 hex digits"));
                        usable = false;
                    }
                }
                continue;
            }
            if key == "file_version" {
                match value.as_str().map(str::trim).filter(|v| !v.is_empty()) {
                    Some(v) => hooks.file_version = Some(v.to_string()),
                    None => {
                        problems.push(format!("{at}: file_version isn't a version"));
                        usable = false;
                    }
                }
                continue;
            }
            let Some((f, _, _)) = Function::ALL.iter().find(|(_, k, _)| *k == key) else {
                problems.push(format!("{at}: unknown key {key:?}"));
                continue;
            };
            let mut patterns = Vec::new();
            for (i, p) in value.as_arr().iter().enumerate() {
                if patterns.len() == MAX_PATTERNS {
                    problems.push(format!("{at}: {key}: more than {MAX_PATTERNS} patterns; the rest are left out"));
                    break;
                }
                match p.as_str().map(Pattern::parse) {
                    Some(Ok(p)) => patterns.push(p),
                    Some(Err(e)) => problems.push(format!("{at}: {key}[{i}]: {e}")),
                    None => problems.push(format!("{at}: {key}[{i}] is not a string")),
                }
            }
            if !patterns.is_empty() {
                hooks.functions.push((*f, patterns));
            }
        }
        // An entry whose build can't be told is never used: it would apply to every build.
        if usable && !hooks.functions.is_empty() {
            out.push(hooks);
        } else if usable {
            problems.push(format!("{at}: no usable pattern"));
        }
    }
    if out.is_empty() && root.get("versions").as_arr().is_empty() {
        problems.push("no \"versions\" list".into());
    }
    (out, problems)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_parse() {
        let p = Pattern::parse("40 53 48 83 ec 20 ?? 8B D9 ? 85").unwrap();
        assert_eq!(p.bytes.len(), 11);
        assert_eq!(p.bytes[6], None);
        assert_eq!(p.bytes[9], None);
        assert_eq!(p.bytes[4], Some(0xEC));
        let p = Pattern::parse("?? ?? 01 02 03 04 05 06").unwrap();
        assert_eq!(p.anchor, 2);
        assert!(Pattern::parse("").is_err());
        assert!(Pattern::parse("01 02 03 04 05").is_err(), "too few fixed bytes");
        assert!(Pattern::parse("01 02 03 ?? ?? ?? 04 05").is_err(), "wildcards don't count");
        assert!(Pattern::parse("01 02 03 04 05 0G").is_err());
        assert!(Pattern::parse("01 02 03 04 05 123").is_err());
        assert!(Pattern::parse("01 02 03 04 05 06 ???").is_err());
        assert!(Pattern::parse(&"AA ".repeat(MAX_LEN)).is_ok());
        assert!(Pattern::parse(&"AA ".repeat(MAX_LEN + 1)).is_err());
    }

    #[test]
    fn patterns_match_with_wildcards() {
        let p = Pattern::parse("?? 10 11 12 ?? 14 15 16").unwrap();
        let mut hay = vec![0u8; 64];
        hay[20..28].copy_from_slice(&[0xFF, 0x10, 0x11, 0x12, 0x77, 0x14, 0x15, 0x16]);
        assert_eq!(p.matches(&hay, 3), vec![20]);
        hay[50..58].copy_from_slice(&[0x00, 0x10, 0x11, 0x12, 0x00, 0x14, 0x15, 0x16]);
        assert_eq!(p.matches(&hay, 3), vec![20, 50]);
        assert_eq!(p.matches(&hay, 1), vec![20]);
        // At the very end, and not past it.
        let end = [0u8, 0x10, 0x11, 0x12, 0, 0x14, 0x15, 0x16];
        assert_eq!(p.matches(&end, 3), vec![0]);
        assert_eq!(p.matches(&end[..7], 3), Vec::<usize>::new());
        // Near misses.
        assert_eq!(p.matches(&[0, 0x10, 0x11, 0x12, 0, 0x14, 0x15, 0x17], 3), Vec::<usize>::new());
    }
}
