//! Bearer token and size limits for the loopback control channel.
//!
//! Personal, same-machine use: one shared token, no per-tool capabilities.
//! The token never belongs in a log line or a reply. Stdio MCP does not use it.

use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::{Value, json};

/// First request on a TCP control connection. Nothing else is dispatched before it succeeds.
pub const AUTH_METHOD: &str = "auth";
/// Encoded JSON request line, including its newline.
pub const MAX_REQUEST_BYTES: usize = 1 << 20;
/// Encoded JSON reply, including its newline.
pub const MAX_RESPONSE_BYTES: usize = 8 << 20;
/// Accepted TCP connections at once, per listener.
pub const MAX_CONNECTIONS: usize = 16;
/// JSON-RPC array messages on stdio MCP, and `batch` tool steps.
pub const MAX_BATCH_STEPS: usize = 256;
/// Idle read and write timeout on a control socket.
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);

const TOKEN_BYTES: usize = 32;
const TOKEN_HEX_LEN: usize = TOKEN_BYTES * 2;

/// How the desktop listener obtained its token. Only [`ServerToken::Generated`] is meant to be shown,
/// and only once, on stderr. Debug output never includes the secret.
pub enum ServerToken {
    /// Fresh token, not stored. The app prints it once on stderr.
    Generated(String),
    /// `--control-token` or `EFFECTCRAFT_CONTROL_TOKEN`. Do not print it.
    Supplied(String),
    /// Read or created at `path` (mode `0600` on Unix). Print the path, not the token.
    File { token: String, path: PathBuf },
}

impl std::fmt::Debug for ServerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerToken::Generated(_) => f.write_str("Generated"),
            ServerToken::Supplied(_) => f.write_str("Supplied"),
            ServerToken::File { path, .. } => write!(f, "File({})", path.display()),
        }
    }
}

impl ServerToken {
    pub fn token(&self) -> &str {
        match self {
            ServerToken::Generated(token) | ServerToken::Supplied(token) => token,
            ServerToken::File { token, .. } => token,
        }
    }
}

/// One framed read from a control or stdio stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineRead {
    Eof,
    Line,
    TooLong,
}

/// Read one line, and never keep more than `maximum + 1` bytes of it.
pub fn read_bounded_line(reader: &mut impl BufRead, line: &mut String, maximum: usize) -> std::io::Result<LineRead> {
    line.clear();
    let mut limited = std::io::Read::take(reader, (maximum as u64).saturating_add(1));
    let n = limited.read_line(line)?;
    if n == 0 {
        Ok(LineRead::Eof)
    } else if n > maximum {
        Ok(LineRead::TooLong)
    } else {
        Ok(LineRead::Line)
    }
}

/// 256-bit token as 64 hexadecimal characters, from the OS CSPRNG.
pub fn generate_token() -> Result<String, String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).map_err(|e| format!("cannot generate control token: {e}"))?;
    let mut token = String::with_capacity(TOKEN_HEX_LEN);
    for byte in bytes {
        token.push(hex_digit(byte >> 4));
        token.push(hex_digit(byte & 0x0f));
    }
    Ok(token)
}

fn hex_digit(n: u8) -> char {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    match HEX.get(usize::from(n)) {
        Some(&c) => char::from(c),
        None => '0',
    }
}

/// The form [`generate_token`] emits. Uppercase hex is accepted and stored lowercase.
pub fn validate_token(token: &str) -> Result<(), String> {
    if token.len() != TOKEN_HEX_LEN || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("control token must contain exactly 64 hexadecimal characters".into());
    }
    Ok(())
}

/// Compare fixed-width tokens without returning on the first differing byte.
/// Hex digits compare case-insensitively; the 256-bit value is unchanged.
pub fn token_matches(expected: &str, supplied: &str) -> bool {
    if expected.len() != TOKEN_HEX_LEN || supplied.len() != TOKEN_HEX_LEN {
        return false;
    }
    let expected = expected.as_bytes();
    let supplied = supplied.as_bytes();
    let mut different = 0u8;
    for i in 0..TOKEN_HEX_LEN {
        let a = expected.get(i).copied().unwrap_or(0).to_ascii_lowercase();
        let b = supplied.get(i).copied().unwrap_or(0).to_ascii_lowercase();
        different |= a ^ b;
    }
    different == 0
}

/// Check the first TCP frame. The reply never contains the token.
pub fn authentication_reply(line: &str, expected_token: &str) -> (Value, bool) {
    let line = line.trim();
    let req: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return (json!({"id": null, "ok": false, "error": "authentication required"}), false),
    };
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let supplied = req.get("params").and_then(|p| p.get("token")).and_then(Value::as_str).unwrap_or("");
    let ok = req.get("method").and_then(Value::as_str) == Some(AUTH_METHOD) && token_matches(expected_token, supplied);
    if ok {
        (json!({"id": id, "ok": true, "result": {"authenticated": true}}), true)
    } else {
        (json!({"id": id, "ok": false, "error": "authentication required"}), false)
    }
}

/// `127.0.0.1:9877` and `localhost` are accepted. Anything else is refused before connect or bind.
pub fn require_loopback(addr: &str) -> Result<(), String> {
    let mut saw = false;
    let sockets = addr.to_socket_addrs().map_err(|e| format!("resolve {addr}: {e}"))?;
    for socket in sockets {
        saw = true;
        if !socket.ip().is_loopback() {
            return Err(format!("control address must be loopback, got {socket}"));
        }
    }
    if saw { Ok(()) } else { Err(format!("cannot resolve {addr}")) }
}

fn read_token_file(path: &Path) -> Result<String, String> {
    let token = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let token = token.trim().to_owned();
    validate_token(&token)?;
    Ok(token.to_ascii_lowercase())
}

fn create_token_file(path: &Path, token: &str) -> Result<(), String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if let Err(e) = writeln!(file, "{token}") {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(format!("{}: {e}", path.display()));
    }
    Ok(())
}

/// Server credential. With neither a token nor a file, a fresh token is returned and not stored.
/// A missing token file is created; an existing one is read. Pass a token or a file, not both.
pub fn server_token(supplied: Option<&str>, token_file: Option<&Path>) -> Result<String, String> {
    if supplied.is_some() && token_file.is_some() {
        return Err("use either a control token or a control token file, not both".into());
    }
    if let Some(token) = supplied {
        validate_token(token)?;
        return Ok(token.to_ascii_lowercase());
    }
    let Some(path) = token_file else {
        return generate_token();
    };
    match read_token_file(path) {
        Ok(existing) => Ok(existing),
        Err(_) if !path.exists() => {
            let token = generate_token()?;
            match create_token_file(path, &token) {
                Ok(()) => Ok(token),
                // Another process created the file between the check and create_new.
                Err(_) if path.exists() => read_token_file(path),
                Err(e) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

/// Client credential. Clients never create a token.
pub fn client_token(supplied: Option<&str>, token_file: Option<&Path>) -> Result<String, String> {
    if supplied.is_some() && token_file.is_some() {
        return Err("use either a control token or a control token file, not both".into());
    }
    if let Some(token) = supplied {
        validate_token(token)?;
        return Ok(token.to_ascii_lowercase());
    }
    let Some(path) = token_file else {
        return Err("bridge mode needs --control-token, --control-token-file, EFFECTCRAFT_CONTROL_TOKEN, or EFFECTCRAFT_CONTROL_TOKEN_FILE".into());
    };
    read_token_file(path)
}

/// Flag or env. The explicit argument wins over the environment variable.
pub fn token_inputs(supplied: Option<String>, token_file: Option<PathBuf>) -> (Option<String>, Option<PathBuf>) {
    let supplied = supplied.filter(|s| !s.is_empty()).or_else(|| std::env::var("EFFECTCRAFT_CONTROL_TOKEN").ok().filter(|s| !s.is_empty()));
    let token_file = token_file.or_else(|| std::env::var_os("EFFECTCRAFT_CONTROL_TOKEN_FILE").map(PathBuf::from));
    (supplied, token_file)
}

/// Token the desktop listener will require. A missing file is created. With neither source, the
/// token is generated and not written; the app prints it once.
pub fn resolve_server_token(supplied: Option<String>, token_file: Option<PathBuf>) -> Result<ServerToken, String> {
    let (supplied, token_file) = token_inputs(supplied, token_file);
    if supplied.is_some() && token_file.is_some() {
        return Err("use either a control token or a control token file, not both".into());
    }
    if let Some(path) = token_file {
        let token = server_token(None, Some(&path))?;
        return Ok(ServerToken::File { token, path });
    }
    if let Some(token) = supplied {
        let token = server_token(Some(&token), None)?;
        return Ok(ServerToken::Supplied(token));
    }
    Ok(ServerToken::Generated(server_token(None, None)?))
}

/// Token the MCP bridge sends.
pub fn resolve_client_token(supplied: Option<String>, token_file: Option<PathBuf>) -> Result<String, String> {
    let (supplied, token_file) = token_inputs(supplied, token_file);
    client_token(supplied.as_deref(), token_file.as_deref())
}

/// Counts active connections and hands out a permit only while under the cap.
pub struct ConnectionLimiter {
    active: AtomicUsize,
    max: usize,
}

impl ConnectionLimiter {
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self { active: AtomicUsize::new(0), max })
    }

    pub fn try_acquire(self: &Arc<Self>) -> Option<ConnectionPermit> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.max {
                return None;
            }
            match self.active.compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Some(ConnectionPermit { limiter: Arc::clone(self) }),
                Err(actual) => current = actual,
            }
        }
    }
}

pub struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.limiter.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Nodelay plus idle timeouts, before a connection is served.
pub fn configure_stream(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(())
}

struct LimitedWriter {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Write for LimitedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("response exceeds {} bytes", self.maximum)));
        }
        self.bytes.try_reserve(buf.len()).map_err(|error| std::io::Error::other(format!("response allocation failed: {error}")))?;
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encode_with_limit(value: &Value, maximum: usize) -> Result<Vec<u8>, ()> {
    let mut writer = LimitedWriter { bytes: Vec::new(), maximum };
    serde_json::to_writer(&mut writer, value).map_err(|_| ())?;
    Ok(writer.bytes)
}

/// Write one JSON line. A reply that does not fit is replaced by a short error that keeps `id`.
pub fn write_reply(out: &mut impl Write, reply: &Value) -> std::io::Result<()> {
    let encoded = match encode_with_limit(reply, MAX_RESPONSE_BYTES.saturating_sub(1)) {
        Ok(bytes) => bytes,
        Err(()) => {
            let error = json!({
                "id": reply.get("id").cloned().unwrap_or(Value::Null),
                "ok": false,
                "error": format!("response exceeds {MAX_RESPONSE_BYTES} bytes; operation may have completed"),
            });
            match encode_with_limit(&error, MAX_RESPONSE_BYTES.saturating_sub(1)) {
                Ok(bytes) => bytes,
                Err(()) => b"{\"id\":null,\"ok\":false,\"error\":\"response budget exceeded\"}".to_vec(),
            }
        }
    };
    out.write_all(&encoded)?;
    out.write_all(b"\n")
}

/// Serve one loopback connection. `dispatch` runs only after `auth` succeeds.
/// `None` closes the connection without a further reply (the UI channel is gone).
pub fn serve_connection<F>(stream: TcpStream, token: &str, mut dispatch: F) -> std::io::Result<()>
where
    F: FnMut(&str) -> Option<Value>,
{
    if !matches!(stream.peer_addr(), Ok(addr) if addr.ip().is_loopback()) {
        return Ok(());
    }
    if configure_stream(&stream).is_err() {
        return Ok(());
    }
    let Ok(read) = stream.try_clone() else { return Ok(()) };
    let mut reader = std::io::BufReader::new(read);
    let mut out = stream;
    let mut line = String::new();
    let mut authenticated = false;
    loop {
        match read_bounded_line(&mut reader, &mut line, MAX_REQUEST_BYTES) {
            Ok(LineRead::Eof) | Err(_) => break,
            Ok(LineRead::TooLong) => {
                let reply = json!({
                    "id": null,
                    "ok": false,
                    "error": format!("request exceeds {MAX_REQUEST_BYTES} bytes"),
                });
                let _ = write_reply(&mut out, &reply);
                let _ = out.flush();
                break;
            }
            Ok(LineRead::Line) if line.trim().is_empty() => continue,
            Ok(LineRead::Line) => {}
        }
        if !authenticated {
            let (reply, ok) = authentication_reply(&line, token);
            authenticated = ok;
            if write_reply(&mut out, &reply).is_err() || out.flush().is_err() || !authenticated {
                break;
            }
            continue;
        }
        match dispatch(line.trim()) {
            Some(reply) => {
                if write_reply(&mut out, &reply).is_err() || out.flush().is_err() {
                    break;
                }
            }
            None => break,
        }
    }
    Ok(())
}

/// Accept loopback connections on `listener`, capping how many are served at once.
pub fn run_listener<F>(listener: TcpListener, token: String, dispatch: F) -> Result<(), String>
where
    F: Fn(&str) -> Option<Value> + Send + Sync + 'static,
{
    validate_token(&token)?;
    let dispatch = Arc::new(dispatch);
    let limiter = ConnectionLimiter::new(MAX_CONNECTIONS);
    let token = Arc::new(token);
    for mut stream in listener.incoming().flatten() {
        let Some(permit) = limiter.try_acquire() else {
            let _ = configure_stream(&stream);
            let _ = write_reply(&mut stream, &json!({"id": null, "ok": false, "error": "connection limit reached"}));
            let _ = stream.flush();
            continue;
        };
        let token = Arc::clone(&token);
        let dispatch = Arc::clone(&dispatch);
        std::thread::spawn(move || {
            let _permit = permit;
            let _ = serve_connection(stream, &token, |line| dispatch(line));
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn debug_output_omits_the_token() {
        let token = generate_token().unwrap();
        for source in [ServerToken::Generated(token.clone()), ServerToken::Supplied(token.clone())] {
            assert!(!format!("{source:?}").contains(&token));
        }
    }

    #[test]
    fn generated_tokens_are_valid_and_distinct() {
        let a = generate_token().unwrap();
        let b = generate_token().unwrap();
        validate_token(&a).unwrap();
        assert_ne!(a, b);
        assert!(token_matches(&a, &a));
        assert!(token_matches(&a, &a.to_ascii_uppercase()));
        assert!(!token_matches(&a, &b));
        assert!(!token_matches(&a, "short"));
    }

    #[test]
    fn unauthenticated_and_wrong_token_are_rejected_without_echoing_the_secret() {
        let token = generate_token().unwrap();
        let (reply, authenticated) = authentication_reply("{\"id\":1,\"method\":\"ui.inspect\",\"params\":{}}\n", &token);
        assert!(!authenticated);
        assert_eq!(reply["error"], "authentication required");
        assert!(reply.get("result").is_none());
        assert!(!reply.to_string().contains(&token));

        let wrong = "00".repeat(32);
        let line = json!({"id": 2, "method": AUTH_METHOD, "params": {"token": wrong}}).to_string();
        let (reply, authenticated) = authentication_reply(&line, &token);
        assert!(!authenticated);
        assert_eq!(reply["id"], 2);
        assert_eq!(reply["error"], "authentication required");
        assert!(!reply.to_string().contains(&token));
        assert!(!reply.to_string().contains(&wrong));

        let line = json!({"id": 3, "method": "engine.execute", "params": {"token": token}}).to_string();
        let (reply, authenticated) = authentication_reply(&line, &token);
        assert!(!authenticated);
        assert!(!reply.to_string().contains(&token));
    }

    #[test]
    fn matching_token_authenticates_regardless_of_hex_case() {
        let token = generate_token().unwrap();
        let line = json!({"id": 2, "method": AUTH_METHOD, "params": {"token": token.to_ascii_uppercase()}}).to_string();
        let (reply, authenticated) = authentication_reply(&format!("{line}\n"), &token);
        assert!(authenticated);
        assert_eq!(reply["result"]["authenticated"], true);
        assert!(!reply.to_string().contains(&token));
    }

    #[test]
    fn token_file_round_trips_and_is_private() {
        let path = std::env::temp_dir().join(format!("effectcraft-control-token-{}-{}.txt", std::process::id(), generate_token().unwrap()));
        let server = server_token(None, Some(&path)).unwrap();
        let client = client_token(None, Some(&path)).unwrap();
        assert_eq!(server, client);
        assert!(token_matches(&server, &client));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn missing_client_token_does_not_invent_one() {
        let err = client_token(None, None).unwrap_err();
        assert!(err.contains("EFFECTCRAFT_CONTROL_TOKEN"), "{err}");
    }

    #[test]
    fn bounded_reader_rejects_an_oversized_line() {
        let input = format!("{}\n", "x".repeat(MAX_REQUEST_BYTES + 1));
        let mut reader = std::io::Cursor::new(input);
        let mut line = String::new();
        assert_eq!(read_bounded_line(&mut reader, &mut line, MAX_REQUEST_BYTES).unwrap(), LineRead::TooLong);
    }

    #[test]
    fn connection_limiter_releases_capacity() {
        let limiter = ConnectionLimiter::new(1);
        let permit = limiter.try_acquire().unwrap();
        assert!(limiter.try_acquire().is_none());
        drop(permit);
        assert!(limiter.try_acquire().is_some());
    }

    #[test]
    fn oversized_reply_is_one_error_line_and_keeps_the_id() {
        let reply = json!({"id": 7, "ok": true, "result": "x".repeat(MAX_RESPONSE_BYTES)});
        let mut out = Vec::new();
        write_reply(&mut out, &reply).unwrap();
        assert!(out.len() < 1024);
        assert_eq!(out.iter().filter(|&&byte| byte == b'\n').count(), 1);
        let error: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(error["id"], 7);
        assert_eq!(error["ok"], false);
        assert!(error["error"].as_str().unwrap().contains("operation may have completed"));
    }

    #[test]
    fn loopback_addresses_only() {
        require_loopback("127.0.0.1:9").unwrap();
        require_loopback("[::1]:9").unwrap();
        let err = require_loopback("203.0.113.5:9").unwrap_err();
        assert!(err.contains("loopback"), "{err}");
        let err = require_loopback("0.0.0.0:9").unwrap_err();
        assert!(err.contains("loopback"), "{err}");
    }

    fn read_json(stream: &mut TcpStream) -> Value {
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    #[test]
    fn tcp_rejects_unauthenticated_and_wrong_token_before_dispatch() {
        const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        const WRONG: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen_thread = Arc::clone(&seen);
        let server = std::thread::spawn(move || {
            for _ in 0..3 {
                let (stream, _) = listener.accept().unwrap();
                let seen_thread = Arc::clone(&seen_thread);
                serve_connection(stream, TOKEN, |line| {
                    seen_thread.lock().unwrap().push(line.to_string());
                    Some(json!({"id": 9, "ok": true, "result": {"ran": true}}))
                })
                .unwrap();
            }
        });

        let mut stream = TcpStream::connect(addr).unwrap();
        writeln!(stream, r#"{{"id":1,"method":"engine.execute","params":{{"command":"comp.new"}}}}"#).unwrap();
        let reply = read_json(&mut stream);
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"], "authentication required");
        assert!(reply.get("result").is_none());
        assert!(!reply.to_string().contains(TOKEN));
        let _ = writeln!(stream, r#"{{"id":2,"method":"engine.execute"}}"#);
        drop(stream);

        let mut stream = TcpStream::connect(addr).unwrap();
        writeln!(stream, "{}", json!({"id": 3, "method": "auth", "params": {"token": WRONG}})).unwrap();
        let reply = read_json(&mut stream);
        assert_eq!(reply["id"], 3);
        assert_eq!(reply["error"], "authentication required");
        assert!(!reply.to_string().contains(TOKEN));
        assert!(!reply.to_string().contains(WRONG));
        let _ = writeln!(stream, r#"{{"id":4,"method":"engine.execute"}}"#);
        drop(stream);

        let mut stream = TcpStream::connect(addr).unwrap();
        writeln!(stream, "{}", json!({"id": 5, "method": "auth", "params": {"token": TOKEN.to_ascii_uppercase()}})).unwrap();
        let reply = read_json(&mut stream);
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["result"]["authenticated"], true);
        assert!(!reply.to_string().contains(TOKEN));
        writeln!(stream, r#"{{"id":6,"method":"engine.execute","params":{{"command":"comp.new"}}}}"#).unwrap();
        let reply = read_json(&mut stream);
        assert_eq!(reply["result"]["ran"], true);
        drop(stream);

        server.join().unwrap();
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "{seen:?}");
        assert!(seen[0].contains("engine.execute"));
        assert!(!seen[0].contains(TOKEN));
    }

    #[test]
    fn tcp_rejects_an_oversized_line_before_dispatch() {
        let seen = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let flag = Arc::clone(&seen);
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve_connection(stream, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", |_| {
                flag.store(true, Ordering::Relaxed);
                Some(json!({"ok": true}))
            })
            .unwrap();
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        stream.write_all(&vec![b'x'; MAX_REQUEST_BYTES + 1]).unwrap();
        let reply = read_json(&mut stream);
        assert_eq!(reply["ok"], false);
        assert!(reply["error"].as_str().unwrap().contains("request exceeds"));
        drop(stream);
        server.join().unwrap();
        assert!(!seen.load(Ordering::Relaxed));
    }

    #[test]
    fn tcp_connection_limit_rejects_the_extra_client() {
        const TOKEN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let _ = run_listener(listener, TOKEN.into(), |_| Some(json!({"ok": true, "result": null})));
        });
        let mut held = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            let stream = TcpStream::connect(addr).unwrap();
            held.push(stream);
        }
        let mut extra = TcpStream::connect(addr).unwrap();
        extra.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let reply = read_json(&mut extra);
        assert_eq!(reply["error"], "connection limit reached");
        drop(held);
    }
}
