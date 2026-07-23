use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

#[test]
fn real_dashboard_returns_typed_503_without_graph_path_or_content() {
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);

    let home = tempfile::TempDir::new().unwrap();
    let secret_marker = "J011-DO-NOT-EXPOSE-CONTENT";
    let graph = home.path().join("J011-DO-NOT-EXPOSE-PATH.json");
    std::fs::write(&graph, format!("{{ corrupt {secret_marker}")).unwrap();
    let mut child = Command::new(bin())
        .args(["dashboard", "--bind", &address.to_string()])
        .env("HOME", home.path())
        .env("IW_GRAPH_FILE", &graph)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn real dashboard server");

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = loop {
        match std::net::TcpStream::connect(address) {
            Ok(stream) => break stream,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => panic!("dashboard did not start: {error}"),
        }
    };
    stream
        .write_all(b"GET /api/graph HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();

    assert!(response.starts_with("HTTP/1.1 503"), "{response}");
    assert!(response.contains(r#""error":"graph_unreadable""#));
    assert!(!response.contains(secret_marker));
    assert!(!response.contains("J011-DO-NOT-EXPOSE-PATH"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains(secret_marker));
    assert!(!stderr.contains("J011-DO-NOT-EXPOSE-PATH"));
}
