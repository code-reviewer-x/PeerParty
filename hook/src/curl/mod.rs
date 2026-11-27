//! The game's libcurl, wherever it is: XCurl.dll (the GDK's), a DLL that exports
//! `curl_easy_setopt` (libcurl.dll and the like), or a copy linked into one of the game's
//! own modules, found by the patterns the player lists in its hooks file
//! (config/hooks.rs). `curl_easy_setopt`, `curl_easy_cleanup` and `curl_easy_reset` are
//! hooked, for two things:
//!
//! - tls.rs: a request to a host PeerParty answers itself accepts PeerParty's
//!   certificate, and only it. A curl with its own TLS never asks crypt32, so without
//!   this a lookup redirected to PeerParty's HTTPS server ends in a failed certificate
//!   check. XCurl runs on WinHTTP, whose check crypt32 makes: it needs none of this.
//! - The trace, with `PEERPARTY_HTTP_TRACE=1` (or `PEERPARTY_XBL_TRACE=1`): each request
//!   to a service PeerParty stands in for (net/dns.rs `is_service_host`, and every
//!   `*.xboxlive.com` host) is logged once it's done, with its full URL and its request
//!   and response bodies (up to 4 KB each). Other hosts are never logged: their bodies
//!   are the game's business (sign-in tokens, analytics) and would bury the rest. The
//!   bodies flow through the read and write callbacks the game sets
//!   (CURLOPT_READFUNCTION / WRITEFUNCTION), so those are wrapped: once a handle has
//!   both a callback and its data pointer, curl is given our wrapper and a slot of ours
//!   that names the game's pair. Headers (tokens) are never logged.
//!
//! XCurl is hooked only for the trace: a game failed to load its first map with those
//! hooks (and xboxlive/winhttp.rs's) always on. Any other curl is hooked whenever
//! PeerParty runs (`PEERPARTY_SKIP=curl` turns that off), its bodies only wrapped for
//! the trace. A path to an Xbox Live host may name the player making it
//! (xboxlive/mod.rs `own_xuid_in`).
//!
//! With the RallyHere layer in official mode (rallyhere/harvest.rs), the bodies are also
//! wrapped without the trace, and the answer of a call to one of the title's routes that
//! hold title data is kept (up to `harvest::MAX_BODY`, other calls' bodies not at all) and
//! handed to the harvest once the call is over: at `curl_easy_cleanup`, at
//! `curl_easy_reset`, or when the handle, used again, is given its next URL or method.
//! curl's status code isn't read; the harvest goes by the body's shape.

pub mod tls;

use std::collections::HashMap;
use std::ffi::CString;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex, OnceLock};

use retour::GenericDetour;

use crate::config::hooks::{Function, ModuleHooks};
use crate::log;
use crate::sys::detour::Armed;
use crate::sys::pe::Export;
use crate::sys::scan::{self, Found};

// curl/curl.h option numbers: LONG = 0, OBJECTPOINT = 10000, FUNCTIONPOINT = 20000.
const OPT_WRITEDATA: u32 = 10001;
const OPT_URL: u32 = 10002;
const OPT_READDATA: u32 = 10009;
const OPT_CUSTOMREQUEST: u32 = 10036;
const OPT_UPLOAD: u32 = 46;
const OPT_POST: u32 = 47;
const OPT_NOBODY: u32 = 44;
const OPT_HTTPGET: u32 = 80;
const OPT_WRITEFUNCTION: u32 = 20011;
const OPT_READFUNCTION: u32 = 20012;
/// A URL given as a `CURLU` handle: its host can't be read here.
const OPT_CURLU: u32 = 10282;

/// CURLE_BAD_FUNCTION_ARGUMENT.
const BAD_ARGUMENT: u32 = 43;

const BODY_MAX: usize = 4096;
/// The most of an answer kept for the harvest: one byte over its bound, so a longer one is
/// seen as too long rather than cut.
const HARVEST_MAX: usize = crate::rallyhere::harvest::MAX_BODY + 1;
/// The longest URL read from the game.
const URL_MAX: usize = 8192;
/// Requests remembered at most, for a curl whose cleanup isn't hooked.
const KEEP: usize = 4096;

/// `curl_easy_setopt(handle, option, ...)`: one argument after the option. It is taken
/// and passed on as two pointer-sized ones: a `curl_off_t` option (30000 and up) passes
/// 64 bits, two stack slots on x86, and the second must reach curl too. On x64 the
/// spare one is a register curl doesn't read.
type SetOpt = unsafe extern "C" fn(usize, u32, usize, usize) -> u32;
type Cleanup = unsafe extern "C" fn(usize);
/// `size_t (*)(char *buffer, size_t size, size_t nitems, void *userdata)`.
type DataFn = unsafe extern "C" fn(*mut u8, usize, usize, usize) -> usize;

/// Which curl a copy is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// XCurl.dll: traced only.
    XCurl,
    /// A DLL that exports curl's functions.
    Library,
    /// Found by patterns in a module that doesn't export them.
    Listed,
}

/// One curl in the process: its hooks, each calling the original through its own slot.
struct Copy {
    what: OnceLock<(Kind, String)>,
    setopt: OnceLock<GenericDetour<SetOpt>>,
    cleanup: OnceLock<GenericDetour<Cleanup>>,
    reset: OnceLock<GenericDetour<Cleanup>>,
}

impl Copy {
    const fn new() -> Copy {
        Copy { what: OnceLock::new(), setopt: OnceLock::new(), cleanup: OnceLock::new(), reset: OnceLock::new() }
    }

    fn kind(&self) -> Option<Kind> {
        self.what.get().map(|(k, _)| *k)
    }

    fn label(&self) -> &str {
        self.what.get().map_or("curl", |(_, l)| l.as_str())
    }
}

/// The copies a process may have hooked at once; a game has one or two.
const COPIES_MAX: usize = 4;
static COPIES: [Copy; COPIES_MAX] = [const { Copy::new() }; COPIES_MAX];
static USED: AtomicUsize = AtomicUsize::new(0);
/// The detours, one set per copy (each knows its copy by its index).
const SETOPTS: [SetOpt; COPIES_MAX] = [setopt::<0>, setopt::<1>, setopt::<2>, setopt::<3>];
const CLEANUPS: [Cleanup; COPIES_MAX] = [cleanup::<0>, cleanup::<1>, cleanup::<2>, cleanup::<3>];
const RESETS: [Cleanup; COPIES_MAX] = [reset::<0>, reset::<1>, reset::<2>, reset::<3>];
/// Every function address hooked here: one found twice (exported and listed) is
/// hooked once.
static HOOKED: Mutex<Vec<usize>> = Mutex::new(Vec::new());

#[derive(Default)]
struct Call {
    url: String,
    /// The method the request options make: the last of `CURLOPT_POST`, `_UPLOAD`,
    /// `_NOBODY` set (`HTTPGET`, or the same one turned off, goes back to GET); empty for GET.
    base: &'static str,
    /// `CURLOPT_CUSTOMREQUEST`, which wins over `base`.
    custom: Option<&'static str>,
    sent: Vec<u8>,
    got: Vec<u8>,
    /// Its answer goes to the RallyHere harvest (`harvest::watches`).
    harvest: bool,
}

impl Call {
    fn method(&self) -> &'static str {
        self.custom.unwrap_or(if self.base.is_empty() { "GET" } else { self.base })
    }

    /// Whether the call went out: a body was sent or received.
    fn done(&self) -> bool {
        !self.sent.is_empty() || !self.got.is_empty()
    }

    /// A handle used again: once its call went out, the next option set is for the next
    /// call, which starts with the handle's options (its URL and method stay). The call
    /// that is over.
    fn next(&mut self) -> Option<Call> {
        if !self.done() {
            return None;
        }
        let next = Call { url: self.url.clone(), base: self.base, custom: self.custom, harvest: self.harvest, ..Call::default() };
        Some(std::mem::replace(self, next))
    }
}

/// A `CURLOPT_CUSTOMREQUEST` method, as the trace names it.
fn custom_method(value: usize) -> &'static str {
    match crate::sys::read::cstr(value).unwrap_or_default().to_ascii_uppercase().as_str() {
        "GET" => "GET",
        "DELETE" => "DELETE",
        "PUT" => "PUT",
        "PATCH" => "PATCH",
        "POST" => "POST",
        "HEAD" => "HEAD",
        _ => "OTHER",
    }
}

/// One direction (read or write) of a handle's body callback: what the game set.
#[derive(Default, Clone, Copy)]
struct Side {
    func: usize,
    data: usize,
    data_set: bool,
}

impl Side {
    /// The game's callback is wrapped only once both it and its data pointer are known:
    /// the wrapper is passed a slot of ours as its data, and curl's own default callback
    /// (no function set) must never be handed that slot.
    fn wrapped(&self) -> bool {
        self.func != 0 && self.data_set
    }
}

/// What the wrappers get as their data pointer: one per handle address, never freed,
/// so a handle copied by `curl_easy_duphandle` (which copies our slot along) still
/// finds the callback the game set.
struct Slot {
    handle: usize,
    read: Mutex<Side>,
    write: Mutex<Side>,
}

#[derive(Default)]
struct Calls {
    by_handle: HashMap<usize, Call>,
    slots: HashMap<usize, &'static Slot>,
}

static CALLS: LazyLock<Mutex<Calls>> = LazyLock::new(Mutex::default);
static TLS: LazyLock<Mutex<tls::Handles>> = LazyLock::new(Mutex::default);

/// Whether the game's calls are traced (curl's here, WinHTTP's in xboxlive/winhttp.rs).
pub fn trace() -> bool {
    let c = crate::config::HookConfig::global();
    c.http_trace || c.xbl_trace
}

/// Whether a curl other than XCurl is hooked in this game.
pub fn enabled() -> bool {
    crate::net::enabled() && !crate::net::skip("curl")
}

/// Whether XCurl's calls are traced here (xboxlive/winhttp.rs then leaves them to this module).
pub fn xcurl_traced() -> bool {
    COPIES.iter().any(|c| c.kind() == Some(Kind::XCurl) && c.setopt.get().is_some())
}

fn export(exports: &[Export], name: &str) -> usize {
    exports.iter().find(|e| e.name == name).map_or(0, |e| e.addr as usize)
}

/// XCurl.dll loaded (watch/mod.rs). The number of functions hooked.
pub fn attach_xcurl(module: &str, exports: &[Export]) -> usize {
    let f = |n| export(exports, n);
    install(Kind::XCurl, module, f("curl_easy_setopt"), f("curl_easy_cleanup"), f("curl_easy_reset"), false)
}

/// A DLL that exports `curl_easy_setopt` loaded (watch/mod.rs). The number hooked.
pub fn attach_library(module: &str, exports: &[Export]) -> usize {
    let f = |n| export(exports, n);
    install(Kind::Library, module, f("curl_easy_setopt"), f("curl_easy_cleanup"), f("curl_easy_reset"), false)
}

/// How long a module with a hooks file is searched again for what it didn't
/// show at load: a packed exe unpacks its code once it starts.
const RETRY_FOR: std::time::Duration = std::time::Duration::from_secs(60);
const RETRY_EVERY: std::time::Duration = std::time::Duration::from_millis(500);

/// A module with a hooks file entry for its build loaded (watch/mod.rs): its functions are found by
/// their patterns and hooked. When `curl_easy_setopt` or `curl_easy_cleanup` isn't
/// there yet, the search goes on for a while in the background.
pub fn attach_listed(base: usize, module: &str, hooks: ModuleHooks) {
    if hooks.patterns(Function::CurlEasySetopt).is_empty() {
        log!("curl {module}: the hooks file lists no curl_easy_setopt_patterns; nothing hooked");
        return;
    }
    if install_listed(base, module, &hooks, false, true) {
        return;
    }
    log!("curl {module}: not found yet; searching again for {}s (a packed module unpacks as it starts)", RETRY_FOR.as_secs());
    let name = module.to_string();
    let started = std::thread::Builder::new().name("peerparty-curl-scan".into()).spawn(move || {
        let module = name;
        let until = std::time::Instant::now() + RETRY_FOR;
        while std::time::Instant::now() < until {
            std::thread::sleep(RETRY_EVERY);
            if crate::sys::win::module_of(base) != base {
                log!("curl {module}: module unloaded; stopped searching");
                return;
            }
            if install_listed(base, &module, &hooks, true, false) {
                return;
            }
        }
        if !install_listed(base, &module, &hooks, true, true) {
            log!("curl {module}: gave up searching; its curl isn't hooked");
        }
    });
    if let Err(e) = started {
        log!("curl {module}: no thread to search again: {e}");
    }
}

/// Finds the listed functions and hooks them once setopt and cleanup are both found.
/// False to search again later. `report`: log each pattern's outcome.
fn install_listed(base: usize, module: &str, hooks: &ModuleHooks, late: bool, report: bool) -> bool {
    let find = |f: Function| -> Option<usize> {
        let patterns = hooks.patterns(f);
        for (i, p) in patterns.iter().enumerate() {
            match scan::find(base, p) {
                Found::At(at) => {
                    log!("curl {module}: {} at +{:#x} (pattern {})", f.name(), at - base, i + 1);
                    return Some(at);
                }
                Found::Many(n) if report => log!("curl {module}: {} pattern {} matches {n} places; not used", f.name(), i + 1),
                Found::Nowhere if report => log!("curl {module}: {} pattern {} matches nowhere", f.name(), i + 1),
                _ => {}
            }
        }
        None
    };
    let (Some(setopt), Some(cleanup)) = (find(Function::CurlEasySetopt), find(Function::CurlEasyCleanup)) else {
        if report && hooks.patterns(Function::CurlEasyCleanup).is_empty() {
            log!("curl {module}: the hooks file lists no curl_easy_cleanup_patterns: curl_easy_setopt alone isn't hooked (a handle's address comes back after cleanup)");
        }
        return false;
    };
    let reset = if hooks.patterns(Function::CurlEasyReset).is_empty() { None } else { find(Function::CurlEasyReset) };
    install(Kind::Listed, module, setopt, cleanup, reset.unwrap_or(0), late);
    true
}

/// Hooks one curl's functions; `late`: found after the game started, so its other
/// threads are held while each is patched. The number hooked.
fn install(kind: Kind, module: &str, setopt: usize, cleanup: usize, reset: usize, late: bool) -> usize {
    if setopt == 0 {
        log!("curl {module}: no curl_easy_setopt");
        return 0;
    }
    // The handle state is keyed by address: without cleanup's hook a new handle at an
    // old one's address would inherit its settings.
    if cleanup == 0 {
        log!("curl {module}: no curl_easy_cleanup; not hooked");
        return 0;
    }
    {
        let mut hooked = crate::sys::lock(&HOOKED);
        if hooked.contains(&setopt) {
            log!("curl {module}: this curl is hooked already");
            return 0;
        }
        hooked.extend([setopt, cleanup, reset].into_iter().filter(|a| *a != 0));
    }
    let i = USED.fetch_add(1, Ordering::Relaxed);
    if i >= COPIES_MAX {
        log!("curl {module}: more than {COPIES_MAX} copies of curl; not hooked");
        return 0;
    }
    let copy = &COPIES[i];
    let _ = copy.what.set((kind, module.to_string()));
    let arm = |slot: &OnceLock<GenericDetour<Cleanup>>, at: usize, detour: Cleanup, label: &str| {
        at != 0 && crate::sys::detour::try_arm(slot, unsafe { std::mem::transmute::<usize, Cleanup>(at) }, detour, "curl", label, late) == Armed::Hooked
    };
    // Cleanup and reset first: by the time setopt notes a handle, its end is seen too.
    if !arm(&copy.cleanup, cleanup, CLEANUPS[i], "curl_easy_cleanup") {
        crate::sys::lock(&HOOKED).retain(|a| *a != setopt && *a != cleanup && *a != reset);
        log!("curl {module}: curl_easy_cleanup couldn't be hooked; curl_easy_setopt left alone");
        return 0;
    }
    let mut n = 1 + usize::from(arm(&copy.reset, reset, RESETS[i], "curl_easy_reset"));
    let target: SetOpt = unsafe { std::mem::transmute::<usize, SetOpt>(setopt) };
    n += usize::from(crate::sys::detour::try_arm(&copy.setopt, target, SETOPTS[i], "curl", "curl_easy_setopt", late) == Armed::Hooked);
    let what = match kind {
        Kind::XCurl => "its calls are traced",
        _ if trace() => "PeerParty's hosts take PeerParty's certificate; calls traced",
        _ => "PeerParty's hosts take PeerParty's certificate",
    };
    log!("curl {module} hooked {n} ({what})");
    n
}

/// The host and path of an `https://host/path?query` URL.
pub(crate) fn split_url(url: &str) -> (&str, &str) {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    }
}

fn host_of(url: &str) -> String {
    split_url(url).0.rsplit('@').next().unwrap_or_default().split(':').next().unwrap_or_default().to_ascii_lowercase()
}

fn is_xbox(url: &str) -> bool {
    host_of(url).ends_with(".xboxlive.com")
}

/// Whether a request to `url` is logged by the trace.
fn traced(kind: Kind, url: &str) -> bool {
    is_xbox(url) || (kind != Kind::XCurl && crate::net::dns::is_service_host(&host_of(url)))
}

fn new_slot(h: usize) -> &'static Slot {
    Box::leak(Box::new(Slot { handle: h, read: Mutex::new(Side::default()), write: Mutex::new(Side::default()) }))
}

/// A body option set on a handle (`func`: its callback, else its data pointer): what
/// curl is given instead, and the other option of the pair to set too when this one
/// starts or ends the wrapping.
fn body_option(slot: &'static Slot, write: bool, func: bool, value: usize) -> (usize, Option<(u32, usize)>) {
    let (side, wrapper, func_opt, data_opt) = if write {
        (&slot.write, write_wrap as DataFn as usize, OPT_WRITEFUNCTION, OPT_WRITEDATA)
    } else {
        (&slot.read, read_wrap as DataFn as usize, OPT_READFUNCTION, OPT_READDATA)
    };
    let mut s = crate::sys::lock(side);
    let was = s.wrapped();
    if func {
        s.func = value;
    } else {
        s.data = value;
        s.data_set = true;
    }
    let now = s.wrapped();
    let ours = slot as *const Slot as usize;
    let value = match (now, func) {
        (true, true) => wrapper,
        (true, false) => ours,
        (false, _) => value,
    };
    let other = match (was, now, func) {
        (false, true, true) => Some((data_opt, ours)),
        (false, true, false) => Some((func_opt, wrapper)),
        // The callback set back to curl's own: the game's data pointer goes back too.
        (true, false, true) => Some((data_opt, s.data)),
        _ => None,
    };
    (value, other)
}

unsafe extern "C" fn setopt<const I: usize>(h: usize, option: u32, value: usize, high: usize) -> u32 {
    let copy = &COPIES[I];
    let Some(hook) = copy.setopt.get() else { return BAD_ARGUMENT };
    let kind = copy.kind().unwrap_or(Kind::XCurl);
    let mut value = value;
    // A replacement for a string option, kept alive until curl has copied it.
    let mut text_value = None;
    let url = (option == OPT_URL && value != 0).then(|| crate::sys::read::utf8(value, URL_MAX).unwrap_or_default());
    let body_opt = matches!(option, OPT_READFUNCTION | OPT_WRITEFUNCTION | OPT_READDATA | OPT_WRITEDATA);
    let harvesting = (url.is_some() || body_opt) && crate::rallyhere::harvest::active();
    let watched = harvesting && url.as_deref().is_some_and(|u| crate::rallyhere::harvest::watches(&host_of(u), split_url(u).1));
    if kind != Kind::XCurl {
        if let Some(url) = &url {
            certificates(copy, h, url);
        } else if tls::is_option(option) {
            let text = (option == tls::OPT_PINNEDPUBLICKEY && value != 0)
                .then(|| crate::sys::read::utf8(value, URL_MAX).and_then(|t| CString::new(t).ok()))
                .flatten();
            if let Some(v) = crate::sys::lock(&TLS).set(h, option, value, text, crate::https::tls::curl_pin) {
                value = v.arg();
                text_value = Some(v);
            }
        } else if option == OPT_CURLU && value != 0 {
            crate::log::throttled(&format!("curl {} curlu", copy.label()), 1, |_| {
                log!("gap: curl {}: a URL given as CURLOPT_CURLU; its host isn't read, so its certificate is left to curl", copy.label());
            });
        }
    }
    let mut also = None;
    let mut over = None;
    {
        let mut calls = crate::sys::lock(&CALLS);
        let c = &mut *calls;
        if c.by_handle.len() >= KEEP && !c.by_handle.contains_key(&h) {
            c.by_handle.clear();
        }
        match option {
            OPT_URL if value != 0 => {
                let call = c.by_handle.entry(h).or_default();
                over = call.next();
                call.url = url.unwrap_or_default();
                call.harvest = watched;
            }
            OPT_CUSTOMREQUEST | OPT_POST | OPT_UPLOAD | OPT_NOBODY | OPT_HTTPGET => {
                let call = c.by_handle.entry(h).or_default();
                over = call.next();
                let on = value != 0;
                match option {
                    // NULL: back to the method the other options make.
                    OPT_CUSTOMREQUEST => call.custom = on.then(|| custom_method(value)),
                    OPT_HTTPGET if on => call.base = "",
                    OPT_HTTPGET => {}
                    _ => {
                        let m = match option {
                            OPT_POST => "POST",
                            OPT_UPLOAD => "PUT",
                            _ => "HEAD",
                        };
                        if on {
                            call.base = m;
                        } else if call.base == m {
                            call.base = "";
                        }
                    }
                }
            }
            _ if body_opt && (harvesting || trace()) => {
                let slot: &'static Slot = c.slots.entry(h).or_insert_with(|| new_slot(h));
                let write = matches!(option, OPT_WRITEFUNCTION | OPT_WRITEDATA);
                let func = matches!(option, OPT_READFUNCTION | OPT_WRITEFUNCTION);
                (value, also) = body_option(slot, write, func, value);
            }
            _ => {}
        }
    }
    if let Some(call) = over {
        finish(copy, kind, call);
    }
    if let Some((opt, v)) = also {
        unsafe { hook.call(h, opt, v, 0) };
    }
    let result = unsafe { hook.call(h, option, value, high) };
    drop(text_value);
    result
}

/// A handle's URL is set: when its host is PeerParty's, curl is told to take PeerParty's
/// key; when it was and isn't any more, the game's settings go back (tls.rs).
fn certificates(copy: &Copy, h: usize, url: &str) {
    let local = tls::https_host(url).is_some_and(|host| answered_here(&host));
    let Some(pin) = (if local || crate::sys::lock(&TLS).is_ours(h) { crate::https::tls::curl_pin() } else { None }) else {
        return;
    };
    let plan = crate::sys::lock(&TLS).url(h, local, pin);
    let Some(hook) = copy.setopt.get() else { return };
    for (i, (option, v)) in plan.iter().enumerate() {
        let code = unsafe { hook.call(h, *option, v.arg(), 0) };
        if i == 0 && local && code != 0 {
            crate::sys::lock(&TLS).unpinned(h);
            crate::log::throttled(&format!("curl {} no pin", copy.label()), 1, |_| {
                log!("gap: curl {} can't pin a public key (CURLcode {code}): its certificate check is left as it is, and refuses PeerParty's", copy.label());
            });
            return;
        }
    }
    if local {
        let host = tls::https_host(url).unwrap_or_default();
        crate::log::throttled(&format!("curl {} pin {host}", copy.label()), 1, |_| {
            log!("curl {}: {host} is answered here; that request accepts PeerParty's certificate only", copy.label());
        });
    }
}

fn answered_here(host: &str) -> bool {
    #[cfg(test)]
    if crate::sys::lock(&tests::LOCAL_HOST).as_deref() == Some(host) {
        return true;
    }
    crate::net::dns::answered_here(host)
}

/// The handle, and the game's callback and data, behind a wrapper's data pointer:
/// always one of our slots (the wrapper is only ever set together with one), which are
/// never freed.
fn original(data: usize, write: bool) -> Option<(usize, DataFn, usize)> {
    if data == 0 {
        return None;
    }
    let slot = unsafe { &*(data as *const Slot) };
    let s = *crate::sys::lock(if write { &slot.write } else { &slot.read });
    (s.func != 0).then(|| (slot.handle, unsafe { std::mem::transmute::<usize, DataFn>(s.func) }, s.data))
}

fn keep(h: usize, bytes: &[u8], write: bool) {
    let mut calls = crate::sys::lock(&CALLS);
    if let Some(call) = calls.by_handle.get_mut(&h) {
        // The harvest takes answers only; without the trace nothing else is kept.
        let max = if call.harvest && write {
            HARVEST_MAX
        } else if trace() {
            BODY_MAX
        } else {
            0
        };
        let buf = if write { &mut call.got } else { &mut call.sent };
        let room = max.saturating_sub(buf.len());
        buf.extend_from_slice(&bytes[..bytes.len().min(room)]);
    }
}

/// CURL_READFUNC_ABORT.
const READ_ABORT: usize = 0x1000_0000;

unsafe extern "C" fn read_wrap(buf: *mut u8, size: usize, n: usize, data: usize) -> usize {
    let Some((h, f, game_data)) = original(data, false) else { return READ_ABORT };
    let got = unsafe { f(buf, size, n, game_data) };
    // CURL_READFUNC_ABORT / PAUSE are large sentinels, not lengths.
    if got <= size.saturating_mul(n) && !buf.is_null() {
        keep(h, unsafe { std::slice::from_raw_parts(buf, got) }, false);
    }
    got
}

unsafe extern "C" fn write_wrap(buf: *mut u8, size: usize, n: usize, data: usize) -> usize {
    let Some((h, f, game_data)) = original(data, true) else { return 0 };
    let len = size.saturating_mul(n);
    if !buf.is_null() {
        keep(h, unsafe { std::slice::from_raw_parts(buf, len) }, true);
    }
    unsafe { f(buf, size, n, game_data) }
}

/// `curl_easy_reset`: every option back to curl's default, so nothing is wrapped or
/// pinned, and the handle's last call is over.
unsafe extern "C" fn reset<const I: usize>(h: usize) {
    let call = {
        let mut calls = crate::sys::lock(&CALLS);
        if let Some(slot) = calls.slots.get(&h) {
            *crate::sys::lock(&slot.read) = Side::default();
            *crate::sys::lock(&slot.write) = Side::default();
        }
        calls.by_handle.remove(&h)
    };
    crate::sys::lock(&TLS).forget(h);
    if let Some(call) = call.filter(Call::done) {
        let copy = &COPIES[I];
        finish(copy, copy.kind().unwrap_or(Kind::XCurl), call);
    }
    if let Some(hook) = COPIES[I].reset.get() {
        unsafe { hook.call(h) }
    }
}

fn text(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(&bytes[..bytes.len().min(BODY_MAX)]).replace(['\r', '\n'], " ");
    if bytes.len() >= BODY_MAX { format!("{s}...") } else { s }
}

unsafe extern "C" fn cleanup<const I: usize>(h: usize) {
    let copy = &COPIES[I];
    let kind = copy.kind().unwrap_or(Kind::XCurl);
    let call = {
        // The slot itself stays (never freed): a copy made of this handle may still
        // point at it. Only the handle's claim on it goes, since curl_easy_init can
        // hand the same address out again, and a new handle starts with nothing wrapped.
        let mut calls = crate::sys::lock(&CALLS);
        calls.slots.remove(&h);
        calls.by_handle.remove(&h)
    };
    crate::sys::lock(&TLS).forget(h);
    if let Some(call) = call {
        finish(copy, kind, call);
    }
    if let Some(hook) = copy.cleanup.get() {
        unsafe { hook.call(h) }
    }
}

/// A call that is over: logged when traced, its answer handed to the harvest when held for it.
fn finish(copy: &Copy, kind: Kind, call: Call) {
    let (host, path) = split_url(&call.url);
    let method = call.method();
    if traced(kind, &call.url) {
        if let Some(x) = crate::xboxlive::own_xuid_in(host, path) {
            crate::xboxlive::learn(x);
        }
        if trace() {
            log!("http-trace {} {} {} sent {} got {}", copy.label(), method, call.url, text(&call.sent), text(&call.got));
        } else {
            let host = host_of(&call.url);
            let shape = crate::xboxlive::shape(path);
            crate::log::throttled(&format!("curl {} {} {host}{shape}", copy.label(), method), 2, |n| {
                log!("curl {} {} https://{host}{shape} n={n}", copy.label(), method);
            });
        }
    }
    if call.harvest {
        crate::rallyhere::harvest::observed(method, path, &call.got);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host the tests have answered here, without a service's DNS behind it.
    pub(super) static LOCAL_HOST: Mutex<Option<String>> = Mutex::new(None);

    unsafe extern "C" fn sink(_: *mut u8, size: usize, n: usize, _: usize) -> usize {
        size * n
    }

    /// A real libcurl DLL (`PPTEST_LIBCURL`, a 64-bit one in a 64-bit test: Git for
    /// Windows ships `mingw64\bin\libcurl-4.dll`), hooked as the hook does any DLL that
    /// exports curl, and called the way a game calls it: `curl_easy_setopt` through its
    /// `...`. The game's code never turns curl's checks off, yet the request to
    /// PeerParty's server goes through, so the hook saw the URL through the ellipsis and
    /// gave curl the pin; with the hook gone the same handle would fail the check.
    #[test]
    fn a_libcurl_dll_reaches_peerpartys_server_through_its_hooked_setopt() {
        let Ok(path) = std::env::var("PPTEST_LIBCURL") else {
            eprintln!("skipped: PPTEST_LIBCURL not set");
            return;
        };
        use windows_sys::Win32::System::LibraryLoader::{LoadLibraryExW, LOAD_WITH_ALTERED_SEARCH_PATH};
        let wide: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        let module = unsafe { LoadLibraryExW(wide.as_ptr(), std::ptr::null_mut(), LOAD_WITH_ALTERED_SEARCH_PATH) };
        assert!(!module.is_null(), "{path} doesn't load");
        let table = unsafe { crate::sys::pe::exports(module as *const u8).unwrap() };
        let f = |n: &str| export(&table.code, n);
        // What the game calls: curl's own declarations, the setopt one with its ellipsis.
        type Init = unsafe extern "C" fn() -> usize;
        type Setopt = unsafe extern "C" fn(usize, u32, ...) -> u32;
        type Perform = unsafe extern "C" fn(usize) -> u32;
        type GetInfo = unsafe extern "C" fn(usize, u32, ...) -> u32;
        type Done = unsafe extern "C" fn(usize);
        let init: Init = unsafe { std::mem::transmute(f("curl_easy_init")) };
        let setopt: Setopt = unsafe { std::mem::transmute(f("curl_easy_setopt")) };
        let perform: Perform = unsafe { std::mem::transmute(f("curl_easy_perform")) };
        let getinfo: GetInfo = unsafe { std::mem::transmute(f("curl_easy_getinfo")) };
        let done: Done = unsafe { std::mem::transmute(f("curl_easy_cleanup")) };
        assert_eq!(attach_library("libcurl-test.dll", &table.code), 3, "setopt, cleanup and reset");

        let ip = crate::https::server().expect("server").to_string();
        *crate::sys::lock(&LOCAL_HOST) = Some(ip.clone());
        let url = std::ffi::CString::new(format!("https://{ip}/Client/LoginWithCustomID")).unwrap();
        let body = std::ffi::CString::new("{\"CustomId\":\"x\"}").unwrap();
        let h = unsafe { init() };
        assert_ne!(h, 0);
        unsafe {
            assert_eq!(setopt(h, OPT_URL, url.as_ptr()), 0);
            assert_eq!(setopt(h, OPT_WRITEFUNCTION, sink as DataFn), 0);
            // CURLOPT_POSTFIELDS, and a curl_off_t one: CURLOPT_POSTFIELDSIZE_LARGE.
            assert_eq!(setopt(h, 10015, body.as_ptr()), 0);
            assert_eq!(setopt(h, 30120, body.as_bytes().len() as i64), 0);
            // CURLOPT_TIMEOUT.
            assert_eq!(setopt(h, 13, 10 as std::ffi::c_long), 0);
        }
        assert!(crate::sys::lock(&TLS).is_ours(h), "the hook read the URL through the ellipsis");
        let code = unsafe { perform(h) };
        let mut status: std::ffi::c_long = 0;
        // CURLINFO_RESPONSE_CODE.
        unsafe { getinfo(h, 0x200002, &mut status as *mut std::ffi::c_long) };
        assert_eq!(code, 0, "curl_easy_perform: CURLcode {code}");
        assert!(status >= 200, "an HTTP answer: {status}");
        // Pointed at another host, the handle is the game's again.
        let other = std::ffi::CString::new("https://www.example.com/").unwrap();
        unsafe { setopt(h, OPT_URL, other.as_ptr()) };
        assert!(!crate::sys::lock(&TLS).is_ours(h));
        unsafe { done(h) };
        // The control: the same request, with the host not answered here, so the hook
        // leaves the handle alone; curl's own check refuses PeerParty's certificate.
        *crate::sys::lock(&LOCAL_HOST) = None;
        let h = unsafe { init() };
        unsafe {
            setopt(h, OPT_URL, url.as_ptr());
            setopt(h, OPT_WRITEFUNCTION, sink as DataFn);
            setopt(h, 13, 10 as std::ffi::c_long);
        }
        assert!(!crate::sys::lock(&TLS).is_ours(h));
        let code = unsafe { perform(h) };
        // CURLE_PEER_FAILED_VERIFICATION, or CURLE_SSL_CONNECT_ERROR from some back ends.
        assert!(matches!(code, 60 | 35), "without the pin curl must refuse: CURLcode {code}");
        unsafe { done(h) };
    }

    #[test]
    fn splits_urls() {
        assert_eq!(split_url("https://social.xboxlive.com/users/xuid(1)/people?view=All"), ("social.xboxlive.com", "/users/xuid(1)/people?view=All"));
        assert_eq!(split_url("https://rta.xboxlive.com"), ("rta.xboxlive.com", "/"));
        assert!(is_xbox("https://sessiondirectory.xboxlive.com/handles/query"));
        assert!(is_xbox("https://user@Social.XboxLive.com:443/x"));
        assert!(!is_xbox("https://telemetry.example.net/x"));
        assert!(!is_xbox("https://xboxlive.com.example.org/"));
    }

    /// Windows' own curl.exe, with the settings tls.rs gives a handle (checks off, the
    /// pin on), reaches PeerParty's server; with another key pinned it doesn't connect.
    #[test]
    fn a_real_curl_takes_peerpartys_server_by_its_pin_alone() {
        let curl = std::path::Path::new(&std::env::var("SystemRoot").unwrap_or_default()).join(r"System32\curl.exe");
        if !curl.is_file() {
            eprintln!("skipped: no curl.exe");
            return;
        }
        let ip = crate::https::server().expect("server");
        let pin = crate::https::tls::curl_pin().expect("pin").to_str().unwrap().to_string();
        let run = |pin: &str| {
            use std::os::windows::process::CommandExt;
            std::process::Command::new(&curl)
                .creation_flags(0x0800_0000)
                .args(["-s", "-o", "NUL", "-w", "%{http_code}", "--max-time", "10", "-k", "--pinnedpubkey", pin])
                .arg(format!("https://{ip}/"))
                .output()
                .expect("curl.exe")
        };
        let out = run(&pin);
        let code = String::from_utf8_lossy(&out.stdout).to_string();
        // CURLE_NOT_BUILT_IN, CURLE_UNKNOWN_OPTION: a curl.exe without pinning.
        if matches!(out.status.code(), Some(2 | 4 | 48)) {
            eprintln!("skipped: this curl.exe can't pin ({:?})", out.status.code());
            return;
        }
        assert!(out.status.success(), "curl failed: {:?} {}", out.status.code(), String::from_utf8_lossy(&out.stderr));
        assert!(code.len() == 3 && code != "000", "an HTTP answer: {code}");
        let wrong = format!("sha256//{}", crate::util::encoding::base64(&[7u8; 32]));
        let out = run(&wrong);
        // CURLE_SSL_PINNEDPUBKEYNOTMATCH.
        assert_eq!(out.status.code(), Some(90), "{}", String::from_utf8_lossy(&out.stderr));
    }

    #[test]
    fn the_trace_keeps_to_known_services() {
        assert!(traced(Kind::XCurl, "https://social.xboxlive.com/x"));
        assert!(!traced(Kind::XCurl, "https://a1b2.playfabapi.com/Client/Login"), "XCurl's trace is Xbox Live's");
        assert!(traced(Kind::Listed, "https://a1b2.playfabapi.com/Client/Login"));
        assert!(traced(Kind::Library, "https://profile.xboxlive.com/users"));
        assert!(!traced(Kind::Listed, "https://telemetry.example.net/x"));
    }

    #[test]
    fn a_callback_is_wrapped_once_its_data_is_known_in_either_order() {
        let ours = |s: &'static Slot| s as *const Slot as usize;
        let wrapper = write_wrap as DataFn as usize;
        // Callback first: passed on as it is until the data comes, then both swap.
        let s = new_slot(1);
        assert_eq!(body_option(s, true, true, 0x1111), (0x1111, None));
        assert_eq!(body_option(s, true, false, 0x2222), (ours(s), Some((OPT_WRITEFUNCTION, wrapper))));
        assert_eq!(original(ours(s), true).map(|(h, f, d)| (h, f as usize, d)), Some((1, 0x1111, 0x2222)));
        // Data first.
        let s = new_slot(2);
        assert_eq!(body_option(s, true, false, 0x2222), (0x2222, None));
        assert_eq!(body_option(s, true, true, 0x1111), (wrapper, Some((OPT_WRITEDATA, ours(s)))));
        // Back to curl's own callback: the game's data pointer goes back too.
        assert_eq!(body_option(s, true, true, 0), (0, Some((OPT_WRITEDATA, 0x2222))));
        // Data alone never becomes the slot (curl's default callback would write to it).
        let s = new_slot(3);
        assert_eq!(body_option(s, false, false, 0x3333), (0x3333, None));
        assert!(original(ours(s), false).is_none());
    }

    /// The fake curl's options as it was given them: (handle, option, value).
    static FAKE: Mutex<Vec<(usize, u32, usize)>> = Mutex::new(Vec::new());

    /// A curl that only notes its options, with a prologue long enough for a detour.
    #[inline(never)]
    unsafe extern "C" fn fake_setopt(h: usize, option: u32, value: usize, high: usize) -> u32 {
        let (h, option, value) = (std::hint::black_box(h), std::hint::black_box(option), std::hint::black_box(value));
        let _ = std::hint::black_box(high);
        crate::sys::lock(&FAKE).push((h, option, value));
        0
    }

    #[inline(never)]
    unsafe extern "C" fn fake_cleanup(h: usize) {
        let h = std::hint::black_box(h);
        crate::sys::lock(&FAKE).retain(|(x, _, _)| *x != h);
    }

    /// `curl_easy_reset`: the handle's options go, the handle stays.
    #[inline(never)]
    unsafe extern "C" fn fake_reset(h: usize) {
        let h = std::hint::black_box(h);
        let mut fake = crate::sys::lock(&FAKE);
        fake.retain(|(x, _, _)| *x != h);
        fake.shrink_to_fit();
    }

    /// What the fake curl holds for `h`'s `option`.
    fn fake_value(h: usize, option: u32) -> Option<usize> {
        crate::sys::lock(&FAKE).iter().rev().find(|(x, o, _)| *x == h && *o == option).map(|(_, _, v)| *v)
    }

    const GAME_DATA: usize = 0x6A3E;

    /// The game's write callback: takes everything when given its own data pointer.
    unsafe extern "C" fn game_sink(_: *mut u8, size: usize, n: usize, data: usize) -> usize {
        if data == GAME_DATA { size * n } else { 0 }
    }

    /// The fake curl answering `h`'s call: `body` through the write callback it holds, in pieces.
    fn answer(h: usize, body: &[u8]) {
        let f = unsafe { std::mem::transmute::<usize, DataFn>(fake_value(h, OPT_WRITEFUNCTION).unwrap()) };
        let data = fake_value(h, OPT_WRITEDATA).unwrap();
        for piece in body.chunks(10) {
            assert_eq!(unsafe { f(piece.as_ptr() as *mut u8, 1, piece.len(), data) }, piece.len(), "the game's callback got its data");
        }
    }

    /// A fake curl hooked as any curl is, called the way a game calls it, with the
    /// RallyHere layer in official mode for `api.example.test` (on this thread): the
    /// answers of its title-data routes reach the harvest's files once each call is over;
    /// another route's or another host's answer is not held or written.
    #[test]
    fn an_official_call_to_the_title_reaches_the_harvest_through_the_hooked_curl() {
        let dir = crate::rallyhere::tests_support::temp_dir("curl-harvest");
        crate::rallyhere::harvest::TEST.with(|t| *t.borrow_mut() = Some(("api.example.test".into(), dir.clone())));
        let hooked = install(Kind::Library, "fake-curl.dll", fake_setopt as SetOpt as usize, fake_cleanup as Cleanup as usize, fake_reset as Cleanup as usize, false);
        assert_eq!(hooked, 3, "setopt, cleanup and reset");
        let setopt = std::hint::black_box(fake_setopt as SetOpt);
        let cleanup = std::hint::black_box(fake_cleanup as Cleanup);
        let reset = std::hint::black_box(fake_reset as Cleanup);
        let method = |h: usize| crate::sys::lock(&CALLS).by_handle.get(&h).map(Call::method);
        let custom = |h: usize, m: Option<&std::ffi::CStr>| unsafe { setopt(h, OPT_CUSTOMREQUEST, m.map_or(0, |m| m.as_ptr() as usize), 0) };
        let start = |h: usize, url: &str| {
            let url = CString::new(url).unwrap();
            unsafe {
                setopt(h, OPT_WRITEFUNCTION, game_sink as DataFn as usize, 0);
                setopt(h, OPT_WRITEDATA, GAME_DATA, 0);
                setopt(h, OPT_URL, url.as_ptr() as usize, 0);
            }
        };

        let h = 0x7E57_0001;
        start(h, "https://api.example.test/session/v1/template");
        assert_eq!(fake_value(h, OPT_WRITEFUNCTION), Some(write_wrap as DataFn as usize), "curl was given the wrapper");
        answer(h, br#"{"templates":{"example_party":{"joinable":true,"owner":"someone"}}}"#);
        assert!(!dir.join("template.json").exists(), "not before the call is over");
        unsafe { cleanup(h) };
        assert_eq!(std::fs::read_to_string(dir.join("template.json")).unwrap(), r#"{"example_party":{"joinable":true}}"#);

        // A handle used again: its first call is over when it is given its next URL.
        let h = 0x7E57_0002;
        start(h, "https://api.example.test/config/v2/kv");
        answer(h, br#"{"kvs":{"motd":"hello"},"kick_before_hint":"2020-01-01T00:00:00Z"}"#);
        let login = CString::new("https://api.example.test/users/v1/login").unwrap();
        unsafe { setopt(h, OPT_URL, login.as_ptr() as usize, 0) };
        assert_eq!(std::fs::read_to_string(dir.join("kv.json")).unwrap(), r#"{"motd":"hello"}"#);
        // Sign-in holds no title data: its answer isn't even held.
        answer(h, br#"{"access_token":"made-up"}"#);
        assert!(crate::sys::lock(&CALLS).by_handle.get(&h).is_some_and(|c| !c.harvest && c.got.is_empty()));
        unsafe { cleanup(h) };

        // Another host isn't watched.
        let h = 0x7E57_0003;
        start(h, "https://other.example.test/config/v2/kv");
        answer(h, br#"{"kvs":{"motd":"other"}}"#);
        unsafe { cleanup(h) };
        assert_eq!(std::fs::read_to_string(dir.join("kv.json")).unwrap(), r#"{"motd":"hello"}"#);

        // curl_easy_reset ends the handle's call.
        let h = 0x7E57_0004;
        start(h, "https://api.example.test/session/v1/regions");
        answer(h, br#"{"regions":[{"region_id":"eu","ping_host":"x"}],"cursor":0}"#);
        assert!(!dir.join("regions.json").exists());
        unsafe { reset(h) };
        assert_eq!(std::fs::read_to_string(dir.join("regions.json")).unwrap(), r#"[{"region_id":"eu"}]"#);
        unsafe { cleanup(h) };

        // A POST to a read-only route isn't taken; CURLOPT_HTTPGET makes the handle's call a GET again.
        let h = 0x7E57_0005;
        unsafe { setopt(h, OPT_POST, 1, 0) };
        start(h, "https://api.example.test/config/v2/kv");
        answer(h, br#"{"kvs":{"motd":"posted"}}"#);
        unsafe { cleanup(h) };
        assert_eq!(std::fs::read_to_string(dir.join("kv.json")).unwrap(), r#"{"motd":"hello"}"#);
        let h = 0x7E57_0006;
        unsafe {
            setopt(h, OPT_POST, 1, 0);
            setopt(h, OPT_HTTPGET, 1, 0);
        }
        start(h, "https://api.example.test/config/v2/kv");
        assert_eq!(method(h), Some("GET"));
        answer(h, br#"{"kvs":{"motd":"again"}}"#);
        unsafe { cleanup(h) };
        assert_eq!(std::fs::read_to_string(dir.join("kv.json")).unwrap(), r#"{"motd":"again"}"#);

        // A handle used again with only a new method: the GET that went out is over first,
        // and the PATCH that follows (same URL) is its own call.
        let h = 0x7E57_0007;
        start(h, "https://api.example.test/session/v1/template");
        answer(h, br#"{"templates":{"example_match":{"num_teams":2}}}"#);
        let patch = CString::new("PATCH").unwrap();
        custom(h, Some(&patch));
        assert_eq!(std::fs::read_to_string(dir.join("template.json")).unwrap(), r#"{"example_match":{"num_teams":2}}"#);
        assert_eq!(method(h), Some("PATCH"));
        answer(h, br#"{"templates":{"example_other":{}}}"#);
        unsafe { cleanup(h) };
        assert_eq!(std::fs::read_to_string(dir.join("template.json")).unwrap(), r#"{"example_match":{"num_teams":2}}"#, "a PATCH isn't taken");

        // Turning a method option off goes back to the method the others make.
        let h = 0x7E57_0008;
        let delete = CString::new("delete").unwrap();
        custom(h, Some(&delete));
        assert_eq!(method(h), Some("DELETE"));
        custom(h, None);
        assert_eq!(method(h), Some("GET"));
        for (opt, m) in [(OPT_POST, "POST"), (OPT_NOBODY, "HEAD"), (OPT_UPLOAD, "PUT")] {
            unsafe { setopt(h, opt, 1, 0) };
            assert_eq!(method(h), Some(m));
            unsafe { setopt(h, opt, 0, 0) };
            assert_eq!(method(h), Some("GET"));
        }
        unsafe { setopt(h, OPT_UPLOAD, 1, 0) };
        custom(h, Some(&patch));
        assert_eq!(method(h), Some("PATCH"), "a custom request wins");
        unsafe { cleanup(h) };

        let mut names: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        assert_eq!(names, ["kv.json", "regions.json", "template.json"]);

        crate::rallyhere::harvest::TEST.with(|t| *t.borrow_mut() = None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
