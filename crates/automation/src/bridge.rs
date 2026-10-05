//! Blocking client for the desktop app's JSON-lines control channel (`docs/control-protocol.md`).
//! One persistent loopback connection. The first line is `auth`; methods follow only after it succeeds.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde_json::{Value, json};

use crate::control_auth::{self, AUTH_METHOD, LineRead, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, read_bounded_line};
use crate::{Error, Result};

/// Slightly longer than the app's own 60 s per-request timeout, so its error reply wins.
const READ_TIMEOUT: Duration = Duration::from_secs(65);

pub struct BridgeClient {
    addr: String,
    token: String,
    conn: Option<(BufReader<TcpStream>, TcpStream)>,
    next_id: u64,
}

impl std::fmt::Debug for BridgeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeClient").field("addr", &self.addr).finish_non_exhaustive()
    }
}

impl BridgeClient {
    /// `addr`: a port (`9877`) or `host:port` on loopback (`127.0.0.1`, `localhost`, `[::1]`).
    /// `token` is 64 hexadecimal characters. It is not logged.
    pub fn new(addr: &str, token: &str) -> Result<Self> {
        control_auth::validate_token(token).map_err(Error::BadArgs)?;
        let addr = if addr.parse::<u16>().is_ok() { format!("127.0.0.1:{addr}") } else { addr.to_string() };
        control_auth::require_loopback(&addr).map_err(Error::BadArgs)?;
        Ok(Self { addr, token: token.to_ascii_lowercase(), conn: None, next_id: 1 })
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    fn connect(&mut self) -> Result<(BufReader<TcpStream>, TcpStream)> {
        control_auth::require_loopback(&self.addr).map_err(Error::BadArgs)?;
        let mut last = Error::Bridge(format!("cannot resolve {}", self.addr));
        let sockets = self.addr.to_socket_addrs().map_err(|e| Error::Bridge(format!("{}: {e}", self.addr)))?;
        for sa in sockets {
            if !sa.ip().is_loopback() {
                last = Error::BadArgs(format!("control address must be loopback, got {sa}"));
                continue;
            }
            match TcpStream::connect_timeout(&sa, Duration::from_secs(5)) {
                Ok(mut stream) => {
                    stream.set_read_timeout(Some(READ_TIMEOUT)).ok();
                    stream.set_write_timeout(Some(control_auth::IO_TIMEOUT)).ok();
                    stream.set_nodelay(true).ok();
                    let read = stream.try_clone().map_err(|e| Error::Bridge(e.to_string()))?;
                    let mut reader = BufReader::new(read);
                    let id = self.next_id;
                    self.next_id = self.next_id.saturating_add(1);
                    authenticate(&mut reader, &mut stream, &self.token, id)?;
                    return Ok((reader, stream));
                }
                Err(e) => {
                    last = Error::Bridge(format!("cannot connect to {} ({e}); start the app with `effectcraft --control <port>`", self.addr));
                }
            }
        }
        Err(last)
    }

    /// Call a control method; returns the reply's `result`, or the app's `error` as [`Error::App`].
    /// Authenticates on connect, before the method is sent.
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);
        let line = json!({"id": id, "method": method, "params": params}).to_string();
        if line.len() > MAX_REQUEST_BYTES {
            return Err(Error::BadArgs(format!("request exceeds {MAX_REQUEST_BYTES} bytes")));
        }
        let mut last = Error::Bridge("not attempted".into());
        for attempt in 0..2 {
            if self.conn.is_none() {
                self.conn = Some(self.connect()?);
            }
            let Some((reader, writer)) = self.conn.as_mut() else { continue };
            let res = roundtrip(reader, writer, &line, method);
            match res {
                Ok(Ok(v)) if v.get("ok").and_then(Value::as_bool) == Some(true) => {
                    return Ok(v.get("result").cloned().unwrap_or(Value::Null));
                }
                Ok(Ok(v)) => return Err(Error::App(v.get("error").and_then(Value::as_str).unwrap_or("error").to_string())),
                Ok(Err(e)) => {
                    // Stale connection (app restarted): reconnect, authenticate, and resend once.
                    self.conn = None;
                    last = e;
                    if attempt == 1 {
                        break;
                    }
                }
                Err(e) => {
                    // Timeout or an oversized reply: the app may have run the request. Do not resend.
                    self.conn = None;
                    return Err(e);
                }
            }
        }
        Err(last)
    }
}

fn write_line(writer: &mut TcpStream, line: &str) -> std::io::Result<()> {
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn authenticate(reader: &mut impl BufRead, writer: &mut TcpStream, token: &str, id: u64) -> Result<()> {
    let line = json!({"id": id, "method": AUTH_METHOD, "params": {"token": token}}).to_string();
    write_line(writer, &line).map_err(|e| Error::Bridge(e.to_string()))?;
    let mut reply = String::new();
    match read_bounded_line(reader, &mut reply, MAX_RESPONSE_BYTES).map_err(|e| Error::Bridge(e.to_string()))? {
        LineRead::Line => {}
        LineRead::Eof => return Err(Error::Bridge("control channel closed before authentication".into())),
        LineRead::TooLong => return Err(Error::Bridge("authentication reply exceeds the response budget".into())),
    }
    let v: Value = serde_json::from_str(reply.trim()).map_err(|_| Error::Bridge("bad authentication reply".into()))?;
    if v.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(())
    } else {
        // Fixed text: a hostile peer must not be able to echo the token back into an error string.
        Err(Error::Bridge("authentication required".into()))
    }
}

/// `Ok(Ok(v))` is a parsed reply. `Ok(Err(_))` is a dead connection (safe to resend once).
/// `Err(_)` is a timeout or an oversized reply (never resent).
fn roundtrip(reader: &mut BufReader<TcpStream>, writer: &mut TcpStream, line: &str, method: &str) -> Result<std::result::Result<Value, Error>> {
    if let Err(e) = write_line(writer, line) {
        return Ok(Err(Error::Bridge(e.to_string())));
    }
    let mut buf = String::new();
    match read_bounded_line(reader, &mut buf, MAX_RESPONSE_BYTES) {
        Ok(LineRead::Line) => {}
        Ok(LineRead::Eof) => return Ok(Err(Error::Bridge("connection closed by the app".into()))),
        Ok(LineRead::TooLong) => {
            return Err(Error::Bridge(format!("bridge response exceeds {MAX_RESPONSE_BYTES} bytes; operation may have completed")));
        }
        Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
            return Err(Error::Bridge(format!("no reply to `{method}` within {}s (is the app window running?)", READ_TIMEOUT.as_secs())));
        }
        Err(e) => return Ok(Err(Error::Bridge(e.to_string()))),
    }
    serde_json::from_str(buf.trim()).map(Ok).map_err(|e| Error::Bridge(format!("bad reply: {e}")))
}
