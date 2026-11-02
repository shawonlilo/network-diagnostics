//! nd-core — Network Diagnostics engine.
//!
//! Proxy checking (HTTP / SOCKS5 / SOCKS4), anonymity grading, target-site
//! compatibility tests, optional GeoIP enrichment, and domain health checks
//! (A / MX / SPF / DMARC over raw DNS). Pure `std` — no external crates, so
//! the same code builds unchanged for desktop, mobile, CLI and Docker.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Proxy endpoints
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyProtocol {
    Http,
    Socks5,
    Socks4,
}

impl ProxyProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProxyProtocol::Http => "http",
            ProxyProtocol::Socks5 => "socks5",
            ProxyProtocol::Socks4 => "socks4",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyEndpoint {
    pub host: String,
    pub port: u16,
    /// `None` means auto-detect: try HTTP, then SOCKS5, then SOCKS4.
    pub protocol: Option<ProxyProtocol>,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ProxyEndpoint {
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn display(&self, proto: &ProxyProtocol) -> String {
        match (&self.username, &self.password) {
            (Some(u), Some(p)) => format!(
                "{}://{}:{}@{}:{}",
                proto.as_str(),
                u,
                p,
                self.host,
                self.port
            ),
            _ => format!("{}://{}:{}", proto.as_str(), self.host, self.port),
        }
    }
}

/// Parse one proxy line. Accepted forms:
/// `host:port`, `proto://host:port`, `proto://user:pass@host:port`,
/// `host:port:user:pass`. Returns `None` for blanks/comments/garbage.
pub fn parse_proxy_line(line: &str) -> Option<ProxyEndpoint> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut rest = line;
    let mut protocol: Option<ProxyProtocol> = None;
    if let Some(idx) = rest.find("://") {
        protocol = match rest[..idx].to_ascii_lowercase().as_str() {
            "http" | "https" => Some(ProxyProtocol::Http),
            "socks5" => Some(ProxyProtocol::Socks5),
            "socks4" | "socks4a" => Some(ProxyProtocol::Socks4),
            _ => return None,
        };
        rest = &rest[idx + 3..];
    }
    let (mut username, mut password) = (None, None);
    let mut hostport = rest;
    if let Some(at) = rest.rfind('@') {
        let cred = &rest[..at];
        hostport = &rest[at + 1..];
        if let Some(c) = cred.find(':') {
            username = Some(cred[..c].to_string());
            password = Some(cred[c + 1..].to_string());
        } else {
            username = Some(cred.to_string());
        }
    }
    let parts: Vec<&str> = hostport.split(':').collect();
    if parts.len() < 2 {
        return None;
    }
    // Exactly 4 parts = host:port:user:pass. Any other trailing fields
    // (some lists append :Country or similar metadata) are ignored.
    let (host, port) = (parts[0], parts[1].parse::<u16>().ok()?);
    if parts.len() == 4 && username.is_none() {
        username = Some(parts[2].to_string());
        password = Some(parts[3].to_string());
    }
    if host.is_empty() || port == 0 {
        return None;
    }
    Some(ProxyEndpoint {
        host: host.to_string(),
        port,
        protocol,
        username,
        password,
    })
}

/// Parse a whole list, de-duplicated by host:port:protocol:user.
pub fn parse_proxy_list(text: &str) -> Vec<ProxyEndpoint> {
    let mut out: Vec<ProxyEndpoint> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for line in text.lines() {
        if let Some(ep) = parse_proxy_line(line) {
            let key = format!(
                "{}|{:?}|{}",
                ep.authority(),
                ep.protocol,
                ep.username.clone().unwrap_or_default()
            );
            if seen.insert(key) {
                out.push(ep);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn base64_encode(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Split `http://host[:port]/path` into (host, port, path). HTTP only —
/// this engine grades proxies at the protocol level; TLS targets are tested
/// with CONNECT tunnels instead of full TLS handshakes.
pub fn parse_http_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "only http:// URLs supported for judge/target GET".to_string())?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rfind(':') {
        Some(i) => (
            authority[..i].to_string(),
            authority[i + 1..].parse::<u16>().map_err(|_| "bad port".to_string())?,
        ),
        None => (authority.to_string(), 80),
    };
    Ok((host, port, path))
}

fn is_https(url: &str) -> bool {
    url.to_ascii_lowercase().starts_with("https://")
}

fn split_https_url(url: &str) -> Result<(String, u16), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| "not https".to_string())?;
    let authority = rest.split('/').next().unwrap_or("");
    Ok(match authority.rfind(':') {
        Some(i) => (
            authority[..i].to_string(),
            authority[i + 1..].parse::<u16>().map_err(|_| "bad port".to_string())?,
        ),
        None => (authority.to_string(), 443),
    })
}

fn resolve_tcp(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, String> {
    let addrs: Vec<_> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("dns: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err("dns: no address".to_string());
    }
    let mut last = String::from("connect failed");
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => {
                let _ = s.set_read_timeout(Some(timeout));
                let _ = s.set_write_timeout(Some(timeout));
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Err(e) => last = e.to_string(),
        }
    }
    Err(last)
}

/// Read a full HTTP/1.0-style response (server closes the connection).
/// Returns (status, body).
fn read_response(stream: &mut TcpStream) -> Result<(u16, String), String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > 512 * 1024 {
                    break;
                }
            }
            Err(e) => {
                if buf.is_empty() {
                    return Err(e.to_string());
                }
                break;
            }
        }
    }
    if buf.is_empty() {
        return Err("empty response".to_string());
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("bad http response")?;
    let body = match text.find("\r\n\r\n") {
        Some(i) => text[i + 4..].to_string(),
        None => String::new(),
    };
    Ok((status, body))
}

fn send_get(stream: &mut TcpStream, host_header: &str, path: &str) -> Result<(u16, String), String> {
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {host_header}\r\nUser-Agent: nd-check/0.1\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    read_response(stream)
}

/// Direct (no proxy) HTTP GET. Returns (status, body).
pub fn direct_fetch(url: &str, timeout: Duration) -> Result<(u16, String), String> {
    let (host, port, path) = parse_http_url(url)?;
    let mut stream = resolve_tcp(&host, port, timeout)?;
    send_get(&mut stream, &host, &path)
}

// ---------------------------------------------------------------------------
// Judge echo + anonymity grading
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct JudgeEcho {
    pub origin: Option<String>,
    pub via: Option<String>,
    pub x_forwarded_for: Option<String>,
}

/// Minimal JSON string-field extraction (judge payloads are simple echoes).
fn json_str(body: &str, key: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let needle = format!("\"{}\"", key.to_ascii_lowercase());
    let mut search_from = 0usize;
    while let Some(pos) = lower[search_from..].find(&needle) {
        let at = search_from + pos + needle.len();
        let rest = &body[at..];
        let rest_l = &lower[at..];
        if let Some(colon) = rest_l.find(':') {
            let after = rest[colon + 1..].trim_start();
            if let Some(stripped) = after.strip_prefix('"') {
                if let Some(end) = stripped.find('"') {
                    return Some(stripped[..end].to_string());
                }
            }
        }
        search_from = at;
    }
    None
}

pub fn parse_judge(body: &str) -> JudgeEcho {
    JudgeEcho {
        origin: json_str(body, "origin"),
        via: json_str(body, "via"),
        x_forwarded_for: json_str(body, "x-forwarded-for"),
    }
}

/// Grade anonymity from a judge echo.
/// transparent = the judge saw your real IP in X-Forwarded-For;
/// anonymous   = proxy headers present, real IP hidden;
/// elite       = no proxy headers at all;
/// unknown     = judge gave us nothing to grade.
pub fn grade_anonymity(echo: &JudgeEcho, real_ip: Option<&str>) -> &'static str {
    let xff = echo.x_forwarded_for.as_deref().unwrap_or("");
    if !xff.is_empty() {
        if let Some(real) = real_ip {
            if !real.is_empty() && xff.contains(real) {
                return "transparent";
            }
        }
        return "anonymous";
    }
    if echo.via.as_deref().map(|v| !v.is_empty()).unwrap_or(false) {
        return "anonymous";
    }
    if echo.origin.is_some() {
        return "elite";
    }
    "unknown"
}

// ---------------------------------------------------------------------------
// Protocol-level proxy fetches. Each returns (status, body, latency).
// ---------------------------------------------------------------------------

fn http_proxy_fetch(
    ep: &ProxyEndpoint,
    url: &str,
    timeout: Duration,
) -> Result<(u16, String, Duration), String> {
    let (host, _port, _path) = parse_http_url(url)?;
    let start = Instant::now();
    let mut stream = resolve_tcp(&ep.host, ep.port, timeout)?;
    let mut req = format!(
        "GET {url} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: nd-check/0.1\r\nConnection: close\r\n"
    );
    if let (Some(u), p) = (&ep.username, &ep.password) {
        let cred = format!("{}:{}", u, p.clone().unwrap_or_default());
        req.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64_encode(cred.as_bytes())
        ));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let (status, body) = read_response(&mut stream)?;
    Ok((status, body, start.elapsed()))
}

/// HTTP-proxy CONNECT tunnel (for https targets). Success = tunnel up.
fn http_proxy_connect(
    ep: &ProxyEndpoint,
    dest_host: &str,
    dest_port: u16,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let mut stream = resolve_tcp(&ep.host, ep.port, timeout)?;
    let mut req = format!(
        "CONNECT {dest_host}:{dest_port} HTTP/1.1\r\nHost: {dest_host}:{dest_port}\r\nConnection: close\r\n"
    );
    if let (Some(u), p) = (&ep.username, &ep.password) {
        let cred = format!("{}:{}", u, p.clone().unwrap_or_default());
        req.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64_encode(cred.as_bytes())
        ));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    // Read just the status line.
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                    break;
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("bad CONNECT response")?;
    if (200..300).contains(&status) {
        Ok(stream)
    } else {
        Err(format!("CONNECT refused: {status}"))
    }
}

fn read_exact(stream: &mut TcpStream, n: usize) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

fn socks5_tunnel(
    ep: &ProxyEndpoint,
    dest_host: &str,
    dest_port: u16,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let mut stream = resolve_tcp(&ep.host, ep.port, timeout)?;
    let has_auth = ep.username.is_some();
    if has_auth {
        stream.write_all(&[0x05, 0x02, 0x00, 0x02]).map_err(|e| e.to_string())?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).map_err(|e| e.to_string())?;
    }
    let greet = read_exact(&mut stream, 2)?;
    if greet[0] != 0x05 {
        return Err("socks5: bad greeting".to_string());
    }
    if greet[1] == 0x02 {
        let u = ep.username.clone().unwrap_or_default();
        let p = ep.password.clone().unwrap_or_default();
        let mut auth = vec![0x01, u.len() as u8];
        auth.extend_from_slice(u.as_bytes());
        auth.push(p.len() as u8);
        auth.extend_from_slice(p.as_bytes());
        stream.write_all(&auth).map_err(|e| e.to_string())?;
        let resp = read_exact(&mut stream, 2)?;
        if resp[1] != 0x00 {
            return Err("socks5: auth failed".to_string());
        }
    } else if greet[1] == 0xFF {
        return Err("socks5: no acceptable auth method".to_string());
    }
    // CONNECT with domain name (atyp 3) so the proxy resolves DNS.
    let mut req = vec![0x05, 0x01, 0x00, 0x03, dest_host.len() as u8];
    req.extend_from_slice(dest_host.as_bytes());
    req.extend_from_slice(&dest_port.to_be_bytes());
    stream.write_all(&req).map_err(|e| e.to_string())?;
    let head = read_exact(&mut stream, 4)?;
    if head[1] != 0x00 {
        return Err(format!("socks5: connect refused (rep {})", head[1]));
    }
    match head[3] {
        0x01 => {
            let _ = read_exact(&mut stream, 6)?;
        }
        0x03 => {
            let len = read_exact(&mut stream, 1)?[0] as usize;
            let _ = read_exact(&mut stream, len + 2)?;
        }
        0x04 => {
            let _ = read_exact(&mut stream, 18)?;
        }
        _ => return Err("socks5: bad address type".to_string()),
    }
    Ok(stream)
}

fn socks4_tunnel(
    ep: &ProxyEndpoint,
    dest_host: &str,
    dest_port: u16,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let mut stream = resolve_tcp(&ep.host, ep.port, timeout)?;
    let ip: Option<[u8; 4]> = dest_host
        .parse::<std::net::Ipv4Addr>()
        .ok()
        .map(|v| v.octets());
    let mut req = vec![0x04, 0x01];
    req.extend_from_slice(&dest_port.to_be_bytes());
    match ip {
        Some(octets) => req.extend_from_slice(&octets),
        None => req.extend_from_slice(&[0, 0, 0, 1]), // SOCKS4a marker
    }
    req.push(0x00); // empty userid
    if ip.is_none() {
        req.extend_from_slice(dest_host.as_bytes());
        req.push(0x00);
    }
    stream.write_all(&req).map_err(|e| e.to_string())?;
    let resp = read_exact(&mut stream, 8)?;
    if resp[1] != 90 {
        return Err(format!("socks4: request rejected ({})", resp[1]));
    }
    Ok(stream)
}

fn tunneled_fetch(
    ep: &ProxyEndpoint,
    proto: &ProxyProtocol,
    url: &str,
    timeout: Duration,
) -> Result<(u16, String, Duration), String> {
    let (host, port, path) = parse_http_url(url)?;
    let start = Instant::now();
    let mut stream = match proto {
        ProxyProtocol::Socks5 => socks5_tunnel(ep, &host, port, timeout)?,
        ProxyProtocol::Socks4 => socks4_tunnel(ep, &host, port, timeout)?,
        ProxyProtocol::Http => return http_proxy_fetch(ep, url, timeout),
    };
    let (status, body) = send_get(&mut stream, &host, &path)?;
    Ok((status, body, start.elapsed()))
}

// ---------------------------------------------------------------------------
// Checking
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CheckOptions {
    /// Judge endpoint that echoes origin IP + headers (default httpbin /get).
    pub judge_url: String,
    /// Optional site the user actually needs (target-compatibility test).
    pub target_url: Option<String>,
    /// Your own IP as seen by the judge directly (for transparent grading).
    pub real_ip: Option<String>,
    pub timeout: Duration,
    pub threads: usize,
    /// Look up exit-IP country/ISP via ip-api.com (off by default).
    pub geo: bool,
}

impl Default for CheckOptions {
    fn default() -> Self {
        CheckOptions {
            judge_url: "http://httpbin.org/get".to_string(),
            target_url: None,
            real_ip: None,
            timeout: Duration::from_secs(10),
            threads: 50,
            geo: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProxyResult {
    pub proxy: String,
    pub host: String,
    pub port: u16,
    pub protocol: Option<String>,
    pub alive: bool,
    pub latency_ms: Option<u128>,
    pub exit_ip: Option<String>,
    pub anonymity: Option<String>,
    pub country: Option<String>,
    pub isp: Option<String>,
    pub ip_type: Option<String>, // residential / datacenter / unknown
    pub target_ok: Option<bool>,
    pub target_status: Option<u16>,
    pub error: Option<String>,
}

fn geo_lookup(ip: &str, timeout: Duration) -> (Option<String>, Option<String>, Option<String>) {
    let url = format!(
        "http://ip-api.com/json/{ip}?fields=status,country,isp,proxy,hosting"
    );
    if let Ok((200, body)) = direct_fetch(&url, timeout) {
        let country = json_str(&body, "country");
        let isp = json_str(&body, "isp");
        let lower = body.to_ascii_lowercase();
        let ip_type = if lower.contains("\"hosting\":true") || lower.contains("\"proxy\":true") {
            Some("datacenter".to_string())
        } else if lower.contains("\"status\":\"success\"") {
            Some("residential".to_string())
        } else {
            None
        };
        return (country, isp, ip_type);
    }
    (None, None, None)
}

/// Test the target through an already-working protocol.
fn target_test(
    ep: &ProxyEndpoint,
    proto: &ProxyProtocol,
    target: &str,
    timeout: Duration,
) -> (bool, Option<u16>) {
    if is_https(target) {
        // Tunnel establishment is the compatibility signal (no TLS in core).
        let dest = split_https_url(target);
        return match dest {
            Ok((h, p)) => match proto {
                ProxyProtocol::Http => (
                    http_proxy_connect(ep, &h, p, timeout).is_ok(),
                    None,
                ),
                ProxyProtocol::Socks5 => (socks5_tunnel(ep, &h, p, timeout).is_ok(), None),
                ProxyProtocol::Socks4 => (socks4_tunnel(ep, &h, p, timeout).is_ok(), None),
            },
            Err(_) => (false, None),
        };
    }
    match tunneled_fetch(ep, proto, target, timeout) {
        Ok((status, _, _)) => {
            // Any real HTTP answer means the site is reachable through the
            // proxy — 401/403 are auth/permission answers, not blocks of the
            // proxy itself (same rule as the original gab checker).
            ((200..=499).contains(&status), Some(status))
        }
        Err(_) => (false, None),
    }
}

/// Check one proxy end-to-end.
pub fn check_proxy(ep: &ProxyEndpoint, opts: &CheckOptions) -> ProxyResult {
    let mut result = ProxyResult {
        proxy: ep.authority(),
        host: ep.host.clone(),
        port: ep.port,
        protocol: None,
        alive: false,
        latency_ms: None,
        exit_ip: None,
        anonymity: None,
        country: None,
        isp: None,
        ip_type: None,
        target_ok: None,
        target_status: None,
        error: None,
    };
    let candidates: Vec<ProxyProtocol> = match &ep.protocol {
        Some(p) => vec![p.clone()],
        None => vec![
            ProxyProtocol::Http,
            ProxyProtocol::Socks5,
            ProxyProtocol::Socks4,
        ],
    };
    let mut last_err: Option<String> = None;
    for proto in &candidates {
        match tunneled_fetch(ep, proto, &opts.judge_url, opts.timeout) {
            Ok((status, body, latency)) => {
                if !(200..300).contains(&status) {
                    last_err = Some(format!("judge returned {status}"));
                    continue;
                }
                let echo = parse_judge(&body);
                result.alive = true;
                result.protocol = Some(proto.as_str().to_string());
                result.latency_ms = Some(latency.as_millis());
                result.exit_ip = echo.origin.clone();
                result.anonymity = Some(
                    grade_anonymity(&echo, opts.real_ip.as_deref()).to_string(),
                );
                if opts.geo {
                    if let Some(ip) = &result.exit_ip {
                        let ip = ip.split(',').next().unwrap_or(ip).trim().to_string();
                        let (c, i, t) = geo_lookup(&ip, opts.timeout);
                        result.country = c;
                        result.isp = i;
                        result.ip_type = t;
                    }
                }
                if let Some(target) = &opts.target_url {
                    let (ok, st) = target_test(ep, proto, target, opts.timeout);
                    result.target_ok = Some(ok);
                    result.target_status = st;
                }
                return result;
            }
            Err(e) => last_err = Some(e),
        }
    }
    result.error = last_err;
    result
}

/// Check a whole list with a small thread pool. Results sorted:
/// alive first, target-compatible first, then fastest.
pub fn check_all(list: &[ProxyEndpoint], opts: &CheckOptions) -> Vec<ProxyResult> {
    let opts = Arc::new(opts.clone());
    let queue = Arc::new(list.to_vec());
    let index = Arc::new(AtomicUsize::new(0));
    let results = Arc::new(Mutex::new(Vec::new()));
    let workers = opts.threads.max(1).min(list.len().max(1));
    let mut handles = Vec::new();
    for _ in 0..workers {
        let (queue, index, results, opts) = (
            queue.clone(),
            index.clone(),
            results.clone(),
            opts.clone(),
        );
        handles.push(std::thread::spawn(move || loop {
            let i = index.fetch_add(1, Ordering::SeqCst);
            if i >= queue.len() {
                break;
            }
            let r = check_proxy(&queue[i], &opts);
            results.lock().unwrap().push(r);
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    let mut out = results.lock().unwrap().clone();
    out.sort_by(|a, b| {
        b.alive
            .cmp(&a.alive)
            .then(b.target_ok.cmp(&a.target_ok))
            .then(a.latency_ms.cmp(&b.latency_ms))
    });
    out
}

// ---------------------------------------------------------------------------
// JSON output (manual — no serde in core)
// ---------------------------------------------------------------------------

pub fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn jstr(v: &Option<String>) -> String {
    match v {
        Some(s) => format!("\"{}\"", escape_json(s)),
        None => "null".to_string(),
    }
}

fn jbool(v: &Option<bool>) -> String {
    match v {
        Some(b) => b.to_string(),
        None => "null".to_string(),
    }
}

fn jnum<T: std::fmt::Display>(v: &Option<T>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "null".to_string(),
    }
}

pub fn result_to_json(r: &ProxyResult) -> String {
    format!(
        "{{\"proxy\":\"{}\",\"protocol\":{},\"alive\":{},\"latency_ms\":{},\"exit_ip\":{},\"anonymity\":{},\"country\":{},\"isp\":{},\"ip_type\":{},\"target_ok\":{},\"target_status\":{},\"error\":{}}}",
        escape_json(&r.proxy),
        jstr(&r.protocol),
        r.alive,
        jnum(&r.latency_ms),
        jstr(&r.exit_ip),
        jstr(&r.anonymity),
        jstr(&r.country),
        jstr(&r.isp),
        jstr(&r.ip_type),
        jbool(&r.target_ok),
        jnum(&r.target_status),
        jstr(&r.error),
    )
}

pub fn results_to_json(results: &[ProxyResult]) -> String {
    let items: Vec<String> = results.iter().map(result_to_json).collect();
    format!("[\n{}\n]", items.join(",\n"))
}

// ---------------------------------------------------------------------------
// Domain health — raw DNS wire queries (A / MX / TXT), SPF + DMARC extraction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct DomainHealth {
    pub domain: String,
    pub a_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub spf: Option<String>,
    pub dmarc: Option<String>,
    pub resolver: String,
    pub error: Option<String>,
}

impl DomainHealth {
    pub fn has_mx(&self) -> bool {
        !self.mx_records.is_empty()
    }
    /// One-line human verdict, plain words first.
    pub fn verdict(&self) -> String {
        let mut parts = Vec::new();
        parts.push(if self.a_records.is_empty() {
            "no A record (site unreachable by name)"
        } else {
            "A record ok"
        });
        parts.push(if self.has_mx() { "mail (MX) ok" } else { "no MX (cannot receive mail)" });
        parts.push(if self.spf.is_some() { "SPF ok" } else { "SPF missing" });
        parts.push(if self.dmarc.is_some() { "DMARC ok" } else { "DMARC missing" });
        parts.join(" · ")
    }
    pub fn to_json(&self) -> String {
        let arr = |v: &[String]| -> String {
            let items: Vec<String> =
                v.iter().map(|s| format!("\"{}\"", escape_json(s))).collect();
            format!("[{}]", items.join(","))
        };
        format!(
            "{{\"domain\":\"{}\",\"a_records\":{},\"mx_records\":{},\"spf\":{},\"dmarc\":{},\"resolver\":\"{}\",\"error\":{}}}",
            escape_json(&self.domain),
            arr(&self.a_records),
            arr(&self.mx_records),
            jstr(&self.spf),
            jstr(&self.dmarc),
            escape_json(&self.resolver),
            jstr(&self.error),
        )
    }
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn decode_name(packet: &[u8], mut offset: usize) -> (String, usize) {
    let mut labels: Vec<String> = Vec::new();
    let mut jumped = false;
    let mut next = offset;
    let mut guard = 0;
    loop {
        guard += 1;
        if offset >= packet.len() || guard > 64 {
            break;
        }
        let len = packet[offset];
        if len == 0 {
            if !jumped {
                next = offset + 1;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= packet.len() {
                break;
            }
            let ptr = (((len & 0x3F) as usize) << 8) | packet[offset + 1] as usize;
            if !jumped {
                next = offset + 2;
            }
            jumped = true;
            offset = ptr;
            continue;
        }
        let start = offset + 1;
        let end = start + len as usize;
        if end > packet.len() {
            break;
        }
        labels.push(String::from_utf8_lossy(&packet[start..end]).to_string());
        offset = end;
        if !jumped {
            next = offset;
        }
    }
    (labels.join("."), next)
}

pub enum RData {
    A(String),
    Mx(u16, String),
    Txt(String),
    Other,
}

fn dns_query(resolver: &str, name: &str, qtype: u16, timeout: Duration) -> Result<Vec<RData>, String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    socket.set_read_timeout(Some(timeout)).map_err(|e| e.to_string())?;
    socket.connect(resolver).map_err(|e| format!("dns connect: {e}"))?;
    let id: u16 = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0x1234))
        ^ (name.len() as u16).wrapping_mul(257);
    let mut packet: Vec<u8> = Vec::new();
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00]); // RD set
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&encode_name(name));
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    socket.send(&packet).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 4096];
    let n = socket.recv(&mut buf).map_err(|e| format!("dns recv: {e}"))?;
    parse_answers(&buf[..n])
}

/// Parse the answer section of a DNS response packet.
pub fn parse_answers(buf: &[u8]) -> Result<Vec<RData>, String> {
    if buf.len() < 12 {
        return Err("dns: short response".to_string());
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut offset = 12;
    for _ in 0..qd {
        let (_, next) = decode_name(buf, offset);
        offset = next + 4;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        if offset >= buf.len() {
            break;
        }
        let (_, next) = decode_name(buf, offset);
        offset = next;
        if offset + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let rdlen = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        let rdata_start = offset + 10;
        if rdata_start + rdlen > buf.len() {
            break;
        }
        let rdata = &buf[rdata_start..rdata_start + rdlen];
        out.push(match rtype {
            1 if rdlen == 4 => RData::A(format!(
                "{}.{}.{}.{}",
                rdata[0], rdata[1], rdata[2], rdata[3]
            )),
            15 if rdlen > 2 => {
                let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
                let (exchange, _) = decode_name(buf, rdata_start + 2);
                RData::Mx(pref, exchange)
            }
            16 => {
                let mut s = String::new();
                let mut i = 0;
                while i < rdata.len() {
                    let l = rdata[i] as usize;
                    i += 1;
                    if i + l > rdata.len() {
                        break;
                    }
                    s.push_str(&String::from_utf8_lossy(&rdata[i..i + l]));
                    i += l;
                }
                RData::Txt(s)
            }
            _ => RData::Other,
        });
        offset = rdata_start + rdlen;
    }
    Ok(out)
}

/// Full domain health check against a resolver (`host:port`, default 8.8.8.8:53).
pub fn domain_health(domain: &str, resolver: &str, timeout: Duration) -> DomainHealth {
    let mut health = DomainHealth {
        domain: domain.to_string(),
        resolver: resolver.to_string(),
        ..Default::default()
    };
    match dns_query(resolver, domain, 1, timeout) {
        Ok(records) => {
            for r in records {
                if let RData::A(ip) = r {
                    health.a_records.push(ip);
                }
            }
        }
        Err(e) => health.error = Some(e),
    }
    if let Ok(records) = dns_query(resolver, domain, 15, timeout) {
        let mut mx: Vec<(u16, String)> = records
            .into_iter()
            .filter_map(|r| match r {
                RData::Mx(p, host) => Some((p, host)),
                _ => None,
            })
            .collect();
        mx.sort();
        health.mx_records = mx.into_iter().map(|(_, h)| h).collect();
    }
    if let Ok(records) = dns_query(resolver, domain, 16, timeout) {
        for r in records {
            if let RData::Txt(t) = r {
                if t.to_ascii_lowercase().starts_with("v=spf1") {
                    health.spf = Some(t);
                }
            }
        }
    }
    let dmarc_name = format!("_dmarc.{domain}");
    if let Ok(records) = dns_query(resolver, &dmarc_name, 16, timeout) {
        for r in records {
            if let RData::Txt(t) = r {
                if t.to_ascii_lowercase().starts_with("v=dmarc1") {
                    health.dmarc = Some(t);
                }
            }
        }
    }
    health
}

// ---------------------------------------------------------------------------
// Tests — DNS parsing is verified with canned wire packets because some
// sandboxes block UDP entirely; the packet format is identical either way.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build_response(qname: &str, qtype: u16, answers: &[Vec<u8>]) -> Vec<u8> {
        let mut pkt: Vec<u8> = Vec::new();
        pkt.extend_from_slice(&0x1234u16.to_be_bytes());
        pkt.extend_from_slice(&0x8180u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&encode_name(qname));
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        for a in answers {
            pkt.extend_from_slice(a);
        }
        pkt
    }

    fn answer(rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut a = vec![0xC0, 0x0C]; // name = pointer to question
        a.extend_from_slice(&rtype.to_be_bytes());
        a.extend_from_slice(&1u16.to_be_bytes());
        a.extend_from_slice(&300u32.to_be_bytes());
        a.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        a.extend_from_slice(rdata);
        a
    }

    #[test]
    fn parses_a_record() {
        let pkt = build_response("test.example", 1, &[answer(1, &[93, 184, 216, 34])]);
        let recs = parse_answers(&pkt).unwrap();
        assert!(matches!(&recs[0], RData::A(ip) if ip == "93.184.216.34"));
    }

    #[test]
    fn parses_mx_record() {
        let mut rdata = 10u16.to_be_bytes().to_vec();
        rdata.extend_from_slice(&encode_name("mail.test.example"));
        let pkt = build_response("test.example", 15, &[answer(15, &rdata)]);
        let recs = parse_answers(&pkt).unwrap();
        assert!(matches!(&recs[0], RData::Mx(10, host) if host == "mail.test.example"));
    }

    #[test]
    fn parses_txt_record() {
        let txt = b"v=spf1 include:_spf.example.net -all";
        let mut rdata = vec![txt.len() as u8];
        rdata.extend_from_slice(txt);
        let pkt = build_response("test.example", 16, &[answer(16, &rdata)]);
        let recs = parse_answers(&pkt).unwrap();
        assert!(matches!(&recs[0], RData::Txt(t) if t.starts_with("v=spf1")));
    }

    #[test]
    fn proxy_line_forms() {
        assert!(parse_proxy_line("1.2.3.4:8080").is_some());
        assert_eq!(
            parse_proxy_line("socks5://1.2.3.4:1080").unwrap().protocol,
            Some(ProxyProtocol::Socks5)
        );
        let with_auth = parse_proxy_line("http://user:pass@1.2.3.4:3128").unwrap();
        assert_eq!(with_auth.username.as_deref(), Some("user"));
        let colon_form = parse_proxy_line("1.2.3.4:8080:user:pass").unwrap();
        assert_eq!(colon_form.password.as_deref(), Some("pass"));
        assert!(parse_proxy_line("# comment").is_none());
        assert!(parse_proxy_line("not a proxy").is_none());
    }

    #[test]
    fn anonymity_grades() {
        let base = JudgeEcho {
            origin: Some("9.9.9.9".to_string()),
            ..Default::default()
        };
        assert_eq!(grade_anonymity(&base, Some("1.1.1.1")), "elite");
        let mut anon = base.clone();
        anon.via = Some("1.1 proxy".to_string());
        assert_eq!(grade_anonymity(&anon, Some("1.1.1.1")), "anonymous");
        let mut trans = base.clone();
        trans.x_forwarded_for = Some("1.1.1.1".to_string());
        assert_eq!(grade_anonymity(&trans, Some("1.1.1.1")), "transparent");
    }
}

// ---------------------------------------------------------------------------
// Proxy sources — public free lists, fetched at runtime from the user's own
// machine. This project ships a catalog of URLs only; it never bundles or
// redistributes proxy data. Every source is credited in SOURCES.md.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SourceDef {
    pub name: &'static str,
    pub homepage: &'static str,
    pub note: &'static str,
    /// (protocol label, file URL). Label "mixed" = auto-detect per line.
    pub files: &'static [(&'static str, &'static str)],
}

#[derive(Debug, Clone)]
pub struct SourceReport {
    pub source: String,
    pub url: String,
    pub lines: usize,
    pub parsed: usize,
    pub error: Option<String>,
}

impl SourceReport {
    pub fn to_json(&self) -> String {
        format!(
            "{{\"source\":\"{}\",\"url\":\"{}\",\"lines\":{},\"parsed\":{},\"error\":{}}}",
            escape_json(&self.source),
            escape_json(&self.url),
            self.lines,
            self.parsed,
            jstr(&self.error),
        )
    }
}

/// The built-in catalog. Every URL below was verified live (HTTP 200)
/// on 2026-11-02. Sources publish these files for free programmatic use.
pub fn default_sources() -> Vec<SourceDef> {
    vec![
        SourceDef {
            name: "TheSpeedX/PROXY-List",
            homepage: "https://github.com/TheSpeedX/PROXY-List",
            note: "large raw list, refreshed ~daily (the original checker's source)",
            files: &[
                ("http", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"),
                ("socks4", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt"),
                ("socks5", "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"),
            ],
        },
        SourceDef {
            name: "monosans/proxy-list",
            homepage: "https://github.com/monosans/proxy-list",
            note: "MIT, re-checked hourly, sorted fastest first",
            files: &[
                ("http", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"),
                ("socks4", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt"),
                ("socks5", "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt"),
            ],
        },
        SourceDef {
            name: "ProxyScrape (free API)",
            homepage: "https://github.com/proxyscrape/free-proxy-list",
            note: "official free v4 API, all protocols, refreshed every minute",
            files: &[(
                "mixed",
                "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text",
            )],
        },
        SourceDef {
            name: "stormsia/proxy-list",
            homepage: "https://github.com/stormsia/proxy-list",
            note: "republished every 15 min with ASN metadata; known for ISP/residential entries",
            files: &[(
                "mixed",
                "https://raw.githubusercontent.com/stormsia/proxy-list/main/working_proxies.txt",
            )],
        },
        SourceDef {
            name: "hproxy-com/free-proxy-list",
            homepage: "https://github.com/hproxy-com/free-proxy-list",
            note: "aggregates 100+ public sources, re-tested around the clock",
            files: &[(
                "mixed",
                "https://raw.githubusercontent.com/hproxy-com/free-proxy-list/main/all.txt",
            )],
        },
        SourceDef {
            name: "proxifly/free-proxy-list",
            homepage: "https://github.com/proxifly/free-proxy-list",
            note: "validated every 5 minutes, 100+ countries (GPL-3.0 data; fetched at runtime, never bundled)",
            files: &[
                ("http", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt"),
                ("https", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/https/data.txt"),
                ("socks4", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt"),
                ("socks5", "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt"),
            ],
        },
        SourceDef {
            name: "jetkai/proxy-list",
            homepage: "https://github.com/jetkai/proxy-list",
            note: "hourly, online-at-test-time entries",
            files: &[
                ("http", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt"),
                ("https", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt"),
                ("socks4", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt"),
                ("socks5", "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt"),
            ],
        },
        SourceDef {
            name: "databay-labs/free-proxy-list",
            homepage: "https://github.com/databay-labs/free-proxy-list",
            note: "10k+ endpoints, HTTPS-validated, by-country files available",
            files: &[
                ("http", "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/http.txt"),
                ("https", "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/https.txt"),
                ("socks4", "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks4.txt"),
                ("socks5", "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks5.txt"),
            ],
        },
        SourceDef {
            name: "iplocate/free-proxy-list",
            homepage: "https://github.com/iplocate/free-proxy-list",
            note: "revalidated every 30 min; highest measured live rate in independent tests",
            files: &[
                ("http", "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/http.txt"),
                ("https", "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/https.txt"),
                ("socks4", "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks4.txt"),
                ("socks5", "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt"),
            ],
        },
        SourceDef {
            name: "roosterkid/openproxylist",
            homepage: "https://github.com/roosterkid/openproxylist",
            note: "hourly updates",
            files: &[
                ("https", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS.txt"),
                ("socks4", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4.txt"),
                ("socks5", "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5.txt"),
            ],
        },
        SourceDef {
            name: "clarketm/proxy-list",
            homepage: "https://github.com/clarketm/proxy-list",
            note: "long-running classic HTTP list",
            files: &[(
                "http",
                "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list.txt",
            )],
        },
        SourceDef {
            name: "hookzof/socks5_list",
            homepage: "https://github.com/hookzof/socks5_list",
            note: "SOCKS5 specialist, auto-updated",
            files: &[(
                "socks5",
                "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
            )],
        },
        SourceDef {
            name: "proxmint/free-proxy-list",
            homepage: "https://github.com/proxmint/free-proxy-list",
            note: "every entry re-tested by a real request every 30 min",
            files: &[
                ("http", "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/http.txt"),
                ("socks4", "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/socks4.txt"),
                ("socks5", "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/socks5.txt"),
            ],
        },
        SourceDef {
            name: "relayglass/free-proxy-list",
            homepage: "https://github.com/relayglass/free-proxy-list",
            note: "checked every 5 minutes against its own test server",
            files: &[
                ("http", "https://raw.githubusercontent.com/relayglass/free-proxy-list/main/protocol/http/http.txt"),
                ("https", "https://raw.githubusercontent.com/relayglass/free-proxy-list/main/protocol/https/https.txt"),
                ("socks5", "https://raw.githubusercontent.com/relayglass/free-proxy-list/main/protocol/socks5/socks5.txt"),
            ],
        },
        SourceDef {
            name: "zloi-user/hideip.me",
            homepage: "https://github.com/zloi-user/hideip.me",
            note: "hideip.me lists mirrored to GitHub (added by project owner)",
            files: &[
                ("http", "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt"),
                ("https", "https://raw.githubusercontent.com/zloi-user/hideip.me/main/https.txt"),
                ("socks4", "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks4.txt"),
                ("socks5", "https://raw.githubusercontent.com/zloi-user/hideip.me/main/socks5.txt"),
            ],
        },
        SourceDef {
            name: "vakhov/fresh-proxy-list",
            homepage: "https://github.com/vakhov/fresh-proxy-list",
            note: "fresh list in txt/json/csv (added by project owner)",
            files: &[
                ("http", "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt"),
                ("https", "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/https.txt"),
                ("socks4", "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks4.txt"),
                ("socks5", "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/socks5.txt"),
            ],
        },
        SourceDef {
            name: "mmpx12/proxy-list",
            homepage: "https://github.com/mmpx12/proxy-list",
            note: "per-protocol files (added by project owner; Tor exit list intentionally not used — Tor exits are not proxies)",
            files: &[
                ("http", "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt"),
                ("https", "https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt"),
                ("socks4", "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt"),
                ("socks5", "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt"),
            ],
        },
        // NOTE: gfpcom/free-proxy-list is credited in SOURCES.md but is not
        // a fetch source — its sources/*.txt files are a registry of
        // upstream URLs, not proxy data (verified 2026-11-02).
        SourceDef {
            name: "Zaeem20/FREE_PROXIES_LIST",
            homepage: "https://github.com/Zaeem20/FREE_PROXIES_LIST",
            note: "per-protocol files (added by project owner)",
            files: &[
                ("http", "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt"),
                ("https", "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/https.txt"),
                ("socks4", "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks4.txt"),
                ("socks5", "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt"),
            ],
        },
    ]
}

/// Fetch a URL as text. The lists live behind HTTPS CDNs, and nd-core is
/// deliberately dependency-free (no TLS stack), so fetching shells out to
/// the system `curl` — present on Windows 10+, macOS and virtually all
/// Linux. Checking itself never uses curl; it speaks raw proxy protocols.
pub fn fetch_url(url: &str, timeout: Duration) -> Result<String, String> {
    let secs = timeout.as_secs().max(5).to_string();
    let output = std::process::Command::new("curl")
        .args([
            "-fsSL",
            "--max-time",
            &secs,
            "-A",
            "nd-check/0.2 (+https://github.com/)",
            url,
        ])
        .output()
        .map_err(|e| format!("curl unavailable: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "fetch failed ({})",
            output.status.code().unwrap_or(-1)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Parse one source file, forcing the file's protocol when lines carry none.
pub fn merge_source_text(text: &str, protocol_label: &str) -> Vec<ProxyEndpoint> {
    let forced = match protocol_label {
        "http" | "https" => Some(ProxyProtocol::Http),
        "socks5" => Some(ProxyProtocol::Socks5),
        "socks4" => Some(ProxyProtocol::Socks4),
        _ => None,
    };
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(mut ep) = parse_proxy_line(line) {
            if ep.protocol.is_none() {
                ep.protocol = forced.clone();
            }
            out.push(ep);
        }
    }
    out
}

/// Fetch every file of every source, merge and de-duplicate
/// (the same proxy appears in many lists — dedupe is half the value).
pub fn fetch_sources(
    defs: &[SourceDef],
    timeout: Duration,
) -> (Vec<ProxyEndpoint>, Vec<SourceReport>) {
    let mut merged: Vec<ProxyEndpoint> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut reports = Vec::new();
    for def in defs {
        for (label, url) in def.files {
            let mut report = SourceReport {
                source: def.name.to_string(),
                url: url.to_string(),
                lines: 0,
                parsed: 0,
                error: None,
            };
            match fetch_url(url, timeout) {
                Ok(text) => {
                    report.lines = text.lines().count();
                    let eps = merge_source_text(&text, label);
                    report.parsed = eps.len();
                    for ep in eps {
                        let key = format!("{}|{:?}", ep.authority(), ep.protocol);
                        if seen.insert(key) {
                            merged.push(ep);
                        }
                    }
                }
                Err(e) => report.error = Some(e),
            }
            reports.push(report);
        }
    }
    (merged, reports)
}

pub fn reports_to_json(reports: &[SourceReport]) -> String {
    let items: Vec<String> = reports.iter().map(|r| r.to_json()).collect();
    format!("[\n{}\n]", items.join(",\n"))
}

/// Render endpoints back to canonical list text (for the app textarea).
pub fn endpoints_to_text(list: &[ProxyEndpoint]) -> String {
    list.iter()
        .map(|ep| match &ep.protocol {
            Some(p) => format!("{}://{}", p.as_str(), ep.authority()),
            None => ep.authority(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod source_tests {
    use super::*;

    #[test]
    fn catalog_is_populated_and_https() {
        let defs = default_sources();
        assert!(defs.len() >= 15, "expected at least 15 sources");
        for d in &defs {
            assert!(!d.files.is_empty(), "{} has no files", d.name);
            for (_, url) in d.files {
                assert!(url.starts_with("https://"), "{} not https", url);
            }
        }
    }

    #[test]
    fn merge_forces_protocol_and_skips_garbage() {
        let text = "1.2.3.4:8080\n# comment\nnonsense line\nsocks5://5.6.7.8:1080\n";
        let eps = merge_source_text(text, "http");
        assert_eq!(eps.len(), 2);
        assert_eq!(eps[0].protocol, Some(ProxyProtocol::Http)); // forced
        assert_eq!(eps[1].protocol, Some(ProxyProtocol::Socks5)); // kept
        let mixed = merge_source_text("9.9.9.9:3128\n", "mixed");
        assert_eq!(mixed[0].protocol, None); // auto-detect later
    }

    #[test]
    fn endpoints_render_with_protocol() {
        let eps = merge_source_text("1.2.3.4:8080\n", "socks4");
        assert_eq!(endpoints_to_text(&eps), "socks4://1.2.3.4:8080");
    }
}
