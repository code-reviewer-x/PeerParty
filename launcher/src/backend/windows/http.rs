//! HTTPS GET over WinHTTP (Windows' own client: its proxy settings, its certificate
//! checks), for GitHub's API and a release's small checksum file (update.rs), and a game's
//! data files from the sources the player named (sources.rs).

use std::ffi::c_void;
use std::fmt;
use windows_sys::Win32::Networking::WinHttp::*;

struct H(*mut c_void);
impl Drop for H {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { WinHttpCloseHandle(self.0) };
        }
    }
}

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn err(what: &str) -> String {
    let e = std::io::Error::last_os_error();
    match e.raw_os_error().and_then(winhttp_words) {
        Some(words) => format!("{what}: {words}"),
        None => format!("{what}: {e}"),
    }
}

/// WinHTTP's own errors, which the system's messages don't describe.
fn winhttp_words(code: i32) -> Option<String> {
    let words = match code as u32 {
        ERROR_WINHTTP_TIMEOUT => "no answer in time",
        ERROR_WINHTTP_NAME_NOT_RESOLVED => "the host name wasn't found",
        ERROR_WINHTTP_CANNOT_CONNECT => "couldn't connect",
        ERROR_WINHTTP_CONNECTION_ERROR => "the connection was cut",
        ERROR_WINHTTP_INVALID_SERVER_RESPONSE => "not an HTTP answer",
        ERROR_WINHTTP_SECURE_FAILURE | ERROR_WINHTTP_SECURE_INVALID_CA | ERROR_WINHTTP_SECURE_CERT_CN_INVALID | ERROR_WINHTTP_SECURE_CERT_DATE_INVALID => "its certificate isn't trusted",
        ERROR_WINHTTP_REDIRECT_FAILED => "redirected where it may not go",
        _ => return None,
    };
    Some(format!("{words} (WinHTTP {code})"))
}

/// Why a GET gave nothing: the server's answer was another status than 200, or there was
/// no usable answer at all.
#[derive(Debug, PartialEq)]
pub enum GetError {
    Status(u32),
    Failed(String),
}

impl fmt::Display for GetError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            GetError::Status(code) => write!(f, "HTTP {code}"),
            GetError::Failed(why) => f.write_str(why),
        }
    }
}

impl From<String> for GetError {
    fn from(s: String) -> Self {
        GetError::Failed(s)
    }
}

impl From<&str> for GetError {
    fn from(s: &str) -> Self {
        GetError::Failed(s.into())
    }
}

/// How long a GET may take, and whether it goes out bare.
pub struct Limits {
    /// Finding the host and connecting to it, each (WinHTTP's resolve and connect timeouts).
    pub connect_ms: i32,
    /// Sending the request and each wait for the answer (its send and receive timeouts).
    pub answer_ms: i32,
    /// No cookies, no authentication of any kind (not even Windows' own sign-in to an
    /// intranet site), never redirected from HTTPS to HTTP.
    pub anonymous: bool,
}

/// The update check's.
const UPDATE: Limits = Limits { connect_ms: 10_000, answer_ms: 15_000, anonymous: false };

pub fn get(url: &str, accept: &str, max: usize) -> Result<Vec<u8>, String> {
    fetch_from(url, accept, max, &UPDATE).map(|(body, _)| body).map_err(|e| e.to_string())
}

/// An `https://` URL's host (an IPv6 address without its brackets), port (443 unless
/// given) and path with its query (`/` when it has none). A user name or password in it is
/// refused: nothing is ever signed in to.
pub fn split_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url.strip_prefix("https://").ok_or("only https")?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    let path = path.split('#').next().unwrap_or_default();
    let path = if path.starts_with('/') { path.to_string() } else { format!("/{path}") };
    if authority.contains('@') {
        return Err("a user name or password in the address".into());
    }
    let (host, port) = match authority.strip_prefix('[') {
        Some(v6) => {
            let (host, after) = v6.split_once(']').ok_or("an unclosed [ in the address")?;
            (host, after.strip_prefix(':'))
        }
        None => match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        },
    };
    if host.is_empty() {
        return Err("no host in the address".into());
    }
    let port = match port {
        None => INTERNET_DEFAULT_HTTPS_PORT as u16,
        Some(p) => p.parse::<u16>().ok().filter(|&p| p != 0).ok_or_else(|| format!("a bad port {p:?}"))?,
    };
    Ok((host.to_string(), port, path))
}

fn set_u32(handle: *mut c_void, option: u32, value: u32) -> bool {
    unsafe { WinHttpSetOption(handle, option, (&value as *const u32).cast(), 4) != 0 }
}

/// The address a request's answer came from: the one asked, or where it was redirected.
fn final_url(req: *mut c_void) -> Option<String> {
    let mut buf = vec![0u16; 4096];
    let mut len = (buf.len() * 2) as u32;
    if unsafe { WinHttpQueryOption(req, WINHTTP_OPTION_URL, buf.as_mut_ptr().cast(), &mut len) } == 0 {
        return None;
    }
    buf.truncate(len as usize / 2);
    let s = String::from_utf16_lossy(&buf);
    Some(s.trim_end_matches(char::from(0)).to_string())
}

/// GET `url` (HTTPS only), its answer when the status is 200 and it is at most `max` bytes,
/// with the address it came from (WinHTTP follows redirects, never from HTTPS to HTTP).
pub fn fetch_from(url: &str, accept: &str, max: usize, limits: &Limits) -> Result<(Vec<u8>, String), GetError> {
    let (host, port, path) = split_url(url)?;
    unsafe {
        let agent = w(&format!("PeerParty/{}", env!("CARGO_PKG_VERSION")));
        let session = H(WinHttpOpen(agent.as_ptr(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, std::ptr::null(), std::ptr::null(), 0));
        if session.0.is_null() {
            return Err(err("WinHttpOpen").into());
        }
        WinHttpSetTimeouts(session.0, limits.connect_ms, limits.connect_ms, limits.answer_ms, limits.answer_ms);
        let conn = H(WinHttpConnect(session.0, w(&host).as_ptr(), port, 0));
        if conn.0.is_null() {
            return Err(err("WinHttpConnect").into());
        }
        let req = H(WinHttpOpenRequest(conn.0, w("GET").as_ptr(), w(&path).as_ptr(), std::ptr::null(), std::ptr::null(), std::ptr::null(), WINHTTP_FLAG_SECURE));
        if req.0.is_null() {
            return Err(err("WinHttpOpenRequest").into());
        }
        // Each option is a promise to the player (no cookies, no sign-in): a request that
        // can't keep it isn't sent.
        if limits.anonymous
            && !(set_u32(req.0, WINHTTP_OPTION_DISABLE_FEATURE, WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION)
                && set_u32(req.0, WINHTTP_OPTION_AUTOLOGON_POLICY, WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH)
                && set_u32(req.0, WINHTTP_OPTION_REDIRECT_POLICY, WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP))
        {
            return Err(err("WinHttpSetOption").into());
        }
        let headers = w(&format!("Accept: {accept}\r\nCache-Control: no-cache\r\n"));
        if WinHttpSendRequest(req.0, headers.as_ptr(), u32::MAX, std::ptr::null(), 0, 0, 0) == 0 || WinHttpReceiveResponse(req.0, std::ptr::null_mut()) == 0 {
            return Err(err("the request failed").into());
        }
        let mut code = 0u32;
        let mut len = 4u32;
        WinHttpQueryHeaders(req.0, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, std::ptr::null(), (&mut code as *mut u32).cast(), &mut len, std::ptr::null_mut());
        if code != 200 {
            return Err(GetError::Status(code));
        }
        let mut out = Vec::new();
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let mut n = 0u32;
            if WinHttpReadData(req.0, buf.as_mut_ptr().cast(), buf.len() as u32, &mut n) == 0 {
                return Err(err("reading the answer").into());
            }
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n as usize]);
            if out.len() > max {
                return Err("the answer is too long".into());
            }
        }
        let from = final_url(req.0).unwrap_or_else(|| url.to_string());
        Ok((out, from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_split_into_host_port_and_path() {
        let split = |u: &str| split_url(u).map(|(h, p, path)| (h, p, path));
        assert_eq!(split("https://api.example.invalid/repos/x/releases/latest"), Ok(("api.example.invalid".into(), 443, "/repos/x/releases/latest".into())));
        assert_eq!(split("https://data.example.invalid"), Ok(("data.example.invalid".into(), 443, "/".into())));
        assert_eq!(split("https://127.0.0.1:8443/a/b.json"), Ok(("127.0.0.1".into(), 8443, "/a/b.json".into())));
        assert_eq!(split("https://[::1]:8443/a"), Ok(("::1".into(), 8443, "/a".into())));
        assert_eq!(split("https://[::1]/a"), Ok(("::1".into(), 443, "/a".into())));
        assert_eq!(split("https://h.example.invalid?x=1"), Ok(("h.example.invalid".into(), 443, "/?x=1".into())));
        assert_eq!(split("https://h.example.invalid/p#frag"), Ok(("h.example.invalid".into(), 443, "/p".into())));
        for bad in ["http://h.example.invalid/", "ftp://h.example.invalid/", "h.example.invalid/x", "https:///x", "https://:443/x", "https://h.example.invalid:0/", "https://h.example.invalid:99999/", "https://h.example.invalid:x/", "https://[::1/x"] {
            assert!(split_url(bad).is_err(), "{bad}");
        }
        assert_eq!(split_url("https://user:secret@h.example.invalid/x").unwrap_err(), "a user name or password in the address");
        assert_eq!(GetError::Status(404).to_string(), "HTTP 404");
        assert_eq!(winhttp_words(12029).as_deref(), Some("couldn't connect (WinHTTP 12029)"));
        assert_eq!(winhttp_words(5), None, "the system's own messages describe the rest");
    }
}
