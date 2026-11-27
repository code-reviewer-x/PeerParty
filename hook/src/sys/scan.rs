//! Finding a function in a module by its bytes: a pattern of hex bytes with `?` / `??`
//! wildcards ("40 53 48 83 EC 20 ?? 8B D9"), as the player writes them in the hooks file
//! (config/hooks.rs). Only a module's executable sections are searched, and a pattern
//! counts only when it matches exactly one place: one that matches several would hook
//! whichever came first, maybe not the function meant.

use crate::sys::pe;

// The pattern itself (its text and matching) is shared with the launcher, which checks a
// patterns file with it (protocol/src/gamedata/patterns.rs).
pub use peerparty_protocol::gamedata::patterns::Pattern;

/// Where a pattern matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Found {
    Nowhere,
    At(usize),
    /// In this many places (counting stops at a few).
    Many(usize),
}

/// Keeps a loaded module pinned for the duration of a background scan so FreeLibrary
/// on another thread cannot unmap it mid-read.
struct Pinned(windows_sys::Win32::Foundation::HMODULE);

impl Drop for Pinned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { windows_sys::Win32::Foundation::FreeLibrary(self.0) };
        }
    }
}

fn pin_module(base: usize) -> Option<Pinned> {
    use windows_sys::Win32::System::LibraryLoader::{GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GetModuleHandleExW};
    let mut h = std::ptr::null_mut();
    if unsafe { GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, base as *const u16, &mut h) } == 0 {
        return None;
    }
    let guard = Pinned(h);
    (h as usize == base).then_some(guard)
}

/// Where `pattern` is in the executable sections of the module loaded at `base`. A
/// section the process can't read (a packer's, still locked) is skipped.
pub fn find(base: usize, pattern: &Pattern) -> Found {
    if base < 0x1_0000 {
        return Found::Nowhere;
    }
    // Outside the loader lock (retry scans), pin the module so an unload can't unmap it
    // under us; under the loader lock the module can't unload, and FreeLibrary mustn't run.
    let _pinned = if crate::watch::in_loader() {
        if !crate::sys::read::readable(base, 64) {
            return Found::Nowhere;
        }
        None
    } else {
        let Some(p) = pin_module(base) else { return Found::Nowhere };
        Some(p)
    };
    let Ok(ranges) = (unsafe { pe::code_ranges(base as *const u8) }) else { return Found::Nowhere };
    let mut found = Vec::new();
    for (at, len) in ranges {
        if !crate::sys::read::readable(at, len) {
            continue;
        }
        // SAFETY: the whole range is mapped and readable, checked just above; the module
        // is either pinned or held by the loader lock for the duration of this scan.
        let hay = unsafe { std::slice::from_raw_parts(at as *const u8, len) };
        found.extend(pattern.matches(hay, 3 - found.len()).into_iter().map(|o| at + o));
        if found.len() >= 2 {
            break;
        }
    }
    match found.as_slice() {
        [] => Found::Nowhere,
        [one] => Found::At(*one),
        many => Found::Many(many.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A function of this test's own image, found by its first bytes and only there.
    #[test]
    fn finds_a_function_in_a_loaded_module() {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
        let base = unsafe { GetModuleHandleW(std::ptr::null()) } as usize;
        let ranges = unsafe { pe::code_ranges(base as *const u8).unwrap() };
        let (at, len) = ranges[0];
        let code = unsafe { std::slice::from_raw_parts(at as *const u8, len) };
        // Some 32-byte run in the code that occurs once: its pattern finds it.
        let unique = (0..len.saturating_sub(32))
            .step_by(997)
            .find_map(|o| {
                let text: Vec<String> = code[o..o + 32].iter().map(|b| format!("{b:02X}")).collect();
                let p = Pattern::parse(&text.join(" ")).ok()?;
                (find(base, &p) == Found::At(at + o)).then_some(o)
            });
        assert!(unique.is_some(), "no unique 32-byte run found");
        // A run of one repeated byte isn't unique.
        let p = Pattern::parse(&"CC ".repeat(8)).unwrap();
        assert!(matches!(find(base, &p), Found::Many(_) | Found::Nowhere));
        assert_eq!(find(0, &p), Found::Nowhere);
        assert_eq!(find(0x1_0000, &p), Found::Nowhere, "unmapped address");
        assert_eq!(find(base + 0x1000, &p), Found::Nowhere, "not a module base");
    }
}
