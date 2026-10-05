//! Localhost JSON-lines control server (one request per line, one reply per line).
//! Loopback only. The first line must be `auth` with the bearer token (`SECURITY.md`).

use std::net::TcpListener;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

use effectcraft_automation::control_auth;
use effectcraft_ui_egui::ControlRequest;
use serde_json::{Value, json};

pub fn start(port: u16, token: String, ctx: egui::Context) -> Receiver<ControlRequest> {
    let (tx, rx) = channel::<ControlRequest>();
    if let Err(e) = control_auth::validate_token(&token) {
        eprintln!("effectcraft: control server not started: {e}");
        return rx;
    }
    let listener = match TcpListener::bind(("127.0.0.1", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("effectcraft: control server failed to bind 127.0.0.1:{port}: {e}");
            return rx;
        }
    };
    eprintln!("effectcraft: control server listening on 127.0.0.1:{port}");
    std::thread::spawn(move || {
        let _ = control_auth::run_listener(listener, token, move |line| handle_line(line, &tx, &ctx));
    });
    rx
}

fn handle_line(line: &str, tx: &Sender<ControlRequest>, ctx: &egui::Context) -> Option<Value> {
    let msg = match serde_json::from_str::<Value>(line) {
        Ok(msg) => msg,
        Err(e) => return Some(json!({"ok": false, "error": format!("bad JSON: {e}")})),
    };
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("").to_string();
    let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
    let (req, rrx) = ControlRequest::new(method, params);
    if tx.send(req).is_err() {
        return None;
    }
    ctx.request_repaint();
    let mut r = rrx.recv_timeout(Duration::from_secs(60)).unwrap_or_else(|_| json!({"ok": false, "error": "timeout"}));
    if let Some(o) = r.as_object_mut() {
        o.insert("id".into(), id);
    }
    Some(r)
}

#[cfg(test)]
fn serve(stream: std::net::TcpStream, token: &str, tx: Sender<ControlRequest>, ctx: egui::Context) {
    let _ = control_auth::serve_connection(stream, token, |line| handle_line(line, &tx, &ctx));
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc::{Receiver, channel};
    use std::time::Duration;

    use effectcraft_ui_egui::ControlRequest;
    use serde_json::{Value, json};

    use super::serve;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    struct Harness {
        stream: TcpStream,
        reader: std::io::BufReader<TcpStream>,
        rx: Receiver<ControlRequest>,
        server: std::thread::JoinHandle<()>,
    }

    fn harness() -> Harness {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = channel::<ControlRequest>();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            serve(stream, TOKEN, tx, egui::Context::default());
        });
        let stream = TcpStream::connect(addr).unwrap();
        stream.set_nodelay(true).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let reader = std::io::BufReader::new(stream.try_clone().unwrap());
        Harness { stream, reader, rx, server }
    }

    fn read_reply(reader: &mut std::io::BufReader<TcpStream>) -> Value {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }

    #[test]
    fn unauthenticated_method_is_not_dispatched() {
        let mut h = harness();
        writeln!(h.stream, r#"{{"id":1,"method":"ui.inspect","params":{{}}}}"#).unwrap();
        let reply = read_reply(&mut h.reader);
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"], "authentication required");
        assert!(reply.get("result").is_none());
        assert!(h.rx.try_recv().is_err(), "method ran before auth");
        drop(h.reader);
        drop(h.stream);
        h.server.join().unwrap();
    }

    #[test]
    fn wrong_token_is_rejected_and_not_echoed() {
        let mut h = harness();
        let wrong = "ff".repeat(32);
        writeln!(h.stream, "{}", json!({"id": 4, "method": "auth", "params": {"token": wrong}})).unwrap();
        let reply = read_reply(&mut h.reader);
        assert_eq!(reply["id"], 4);
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"], "authentication required");
        assert!(!reply.to_string().contains(TOKEN));
        assert!(!reply.to_string().contains(&wrong));
        assert!(h.rx.try_recv().is_err());
        let _ = writeln!(h.stream, r#"{{"id":5,"method":"ui.inspect"}}"#);
        std::thread::sleep(Duration::from_millis(50));
        assert!(h.rx.try_recv().is_err());
        drop(h.reader);
        drop(h.stream);
        h.server.join().unwrap();
    }

    #[test]
    fn authenticated_method_is_dispatched() {
        let Harness { mut stream, mut reader, rx, server } = harness();
        let handler = std::thread::spawn(move || {
            let req = rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(req.method, "ui.inspect");
            req.reply.send(json!({"ok": true, "result": {"tool": "selection"}})).unwrap();
        });
        writeln!(stream, "{}", json!({"id": 1, "method": "auth", "params": {"token": TOKEN}})).unwrap();
        let reply = read_reply(&mut reader);
        assert_eq!(reply["ok"], true);
        assert!(!reply.to_string().contains(TOKEN));
        writeln!(stream, "{}", json!({"id": 2, "method": "ui.inspect", "params": {}})).unwrap();
        let reply = read_reply(&mut reader);
        assert_eq!(reply["id"], 2);
        assert_eq!(reply["result"]["tool"], "selection");
        drop(reader);
        drop(stream);
        handler.join().unwrap();
        server.join().unwrap();
    }
}
