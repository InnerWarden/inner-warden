//! The one request the hook makes to the Active Defence agent on its host
//! (see `host_decide`): a POST over TLS to this host's loopback, bounded as a
//! whole, held to the key the agent publishes.
//!
//! The connection is believed only when the certificate the server presents
//! carries the public key whose SHA-256 is in the key file, and the server
//! proves it holds that key in the handshake. No certificate authority is
//! consulted. Outside a jail the key file is [`AGENT_TLS_SPKI_PATH`], a file
//! of root's that no other account can write; inside one it is only the copy
//! the launcher read from there with the host's real owners and handed in
//! read-only ([`JAIL_SPKI_PIN_PATH`]). With no key, or one that cannot be
//! believed, nothing is sent. Against another account on the host that takes
//! the port while the agent is down, this is the defence; the agent inside
//! the jail controls what the hook reads, and a key it sees proves nothing
//! about it.
//!
//! [`AGENT_TLS_SPKI_PATH`]: innerwarden_agent_guard::identity::AGENT_TLS_SPKI_PATH
//! [`JAIL_SPKI_PIN_PATH`]: innerwarden_agent_guard::identity::JAIL_SPKI_PIN_PATH
//!
//! A failure of any kind (no key, no connection, a key that does not match,
//! a slow server, a broken answer) returns `None`, and the hook decides as it
//! did before it asked.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use innerwarden_agent_guard::identity::{
    parse_spki_pin, InstanceDecideRequest, MAX_INSTANCE_ANSWER_BYTES, MAX_SPKI_PIN_BYTES,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

/// The most bytes of a response head read.
const MAX_HEAD_BYTES: usize = 8 * 1024;

/// Ask the host about one command: the key from `key` at `path`, then
/// [`ask`]. `None` with no key: no request is made.
pub fn consult(
    url: &str,
    request: &InstanceDecideRequest,
    key: crate::host_decide::KeyFile,
    path: &Path,
    timeout: Duration,
) -> Option<(u16, Vec<u8>)> {
    let pin = match key {
        crate::host_decide::KeyFile::Jail => read_jail_pin(path),
        crate::host_decide::KeyFile::Host => read_pin(path),
    }?;
    let body = serde_json::to_vec(request).ok()?;
    ask(url, &body, timeout, &pin)
}

/// POST `body` as JSON to `url` (`https://127.0.0.1:<port><path>` only),
/// within `timeout` from connect to the end of the answer, believing only a
/// server whose key hashes to `pin`. The status and up to
/// [`MAX_INSTANCE_ANSWER_BYTES`] + 1 bytes of the body (more than the most an
/// answer may be, so a longer one is seen to be longer), or `None`.
pub fn ask(url: &str, body: &[u8], timeout: Duration, pin: &[u8; 32]) -> Option<(u16, Vec<u8>)> {
    let deadline = Instant::now() + timeout;
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
    };
    let (addr, path) = loopback_target(url)?;
    let tcp = TcpStream::connect_timeout(&addr, remaining()?).ok()?;
    let _ = tcp.set_nodelay(true);
    let connection = rustls::ClientConnection::new(
        Arc::new(client_config(*pin)?),
        ServerName::IpAddress(addr.ip().into()),
    )
    .ok()?;
    let mut stream = rustls::StreamOwned::new(connection, tcp);
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Accept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.sock.set_write_timeout(Some(remaining()?)).ok()?;
    stream.sock.set_read_timeout(Some(remaining()?)).ok()?;
    stream.write_all(head.as_bytes()).ok()?;
    stream.write_all(body).ok()?;
    stream.flush().ok()?;
    let mut seen = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        if let Parsed::Done(status, body) = parse_response(&seen, false) {
            return Some((status, body));
        }
        stream.sock.set_read_timeout(Some(remaining()?)).ok()?;
        let eof = match stream.read(&mut chunk) {
            Ok(0) => true,
            Ok(n) => {
                seen.extend_from_slice(&chunk[..n]);
                false
            }
            // A server that closes without saying so still ended its answer.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => true,
            Err(_) => return None,
        };
        if eof {
            return match parse_response(&seen, true) {
                Parsed::Done(status, body) => Some((status, body)),
                _ => None,
            };
        }
        if seen.len() > MAX_HEAD_BYTES + MAX_INSTANCE_ANSWER_BYTES + 64 {
            return match parse_response(&seen, true) {
                Parsed::Done(status, body) => Some((status, body)),
                _ => None,
            };
        }
    }
}

/// `https://127.0.0.1:<port><path>` and nothing else: the address and the
/// path, or `None`.
fn loopback_target(url: &str) -> Option<(SocketAddr, String)> {
    let rest = url.strip_prefix("https://127.0.0.1:")?;
    let split = rest.find('/')?;
    let port: u16 = rest[..split].parse().ok()?;
    let path = &rest[split..];
    if path.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    Some((
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        path.to_string(),
    ))
}

#[derive(Debug, PartialEq, Eq)]
enum Parsed {
    /// More bytes are needed.
    Incomplete,
    /// Not an HTTP response.
    Broken,
    /// The status and the body.
    Done(u16, Vec<u8>),
}

/// PURE. Read an HTTP/1.1 response from `seen` (`eof`: nothing more will
/// come). Any status but 200 is done as soon as the head is read, with no
/// body. A 200's body is read by its `Content-Length`, its chunks, or to the
/// end, and kept up to one byte more than an answer may hold.
fn parse_response(seen: &[u8], eof: bool) -> Parsed {
    let cap = MAX_INSTANCE_ANSWER_BYTES + 1;
    let Some(head_end) = find(seen, b"\r\n\r\n") else {
        return if eof || seen.len() > MAX_HEAD_BYTES {
            Parsed::Broken
        } else {
            Parsed::Incomplete
        };
    };
    if head_end > MAX_HEAD_BYTES {
        return Parsed::Broken;
    }
    let Ok(head) = std::str::from_utf8(&seen[..head_end]) else {
        return Parsed::Broken;
    };
    let mut lines = head.split("\r\n");
    let status = lines.next().and_then(|line| {
        let mut parts = line.splitn(3, ' ');
        let version = parts.next()?;
        let code = parts.next()?;
        (version.starts_with("HTTP/1.") && code.len() == 3)
            .then(|| code.parse::<u16>().ok())
            .flatten()
    });
    let Some(status) = status else {
        return Parsed::Broken;
    };
    if status != 200 {
        return Parsed::Done(status, Vec::new());
    }
    let mut length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let (name, value) = (name.trim(), value.trim());
        if name.eq_ignore_ascii_case("content-length") {
            match value.parse::<usize>() {
                Ok(n) => length = Some(n),
                Err(_) => return Parsed::Broken,
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.to_ascii_lowercase().contains("chunked");
        }
    }
    let body = &seen[head_end + 4..];
    if chunked {
        return match dechunk(body, cap) {
            Some((decoded, true)) => Parsed::Done(200, decoded),
            Some((decoded, false)) if eof || decoded.len() >= cap => {
                let mut decoded = decoded;
                decoded.truncate(cap);
                Parsed::Done(200, decoded)
            }
            Some(_) => Parsed::Incomplete,
            None => Parsed::Broken,
        };
    }
    let wanted = length.map_or(cap, |n| n.min(cap));
    if body.len() >= wanted {
        return Parsed::Done(200, body[..wanted].to_vec());
    }
    if eof {
        return Parsed::Done(200, body.to_vec());
    }
    Parsed::Incomplete
}

/// The bytes of a chunked body read so far (at most `cap`), and whether its
/// last chunk was read. `None` when it is not a chunked body.
fn dechunk(mut body: &[u8], cap: usize) -> Option<(Vec<u8>, bool)> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = find(body, b"\r\n") else {
            return Some((out, false));
        };
        let size_text = std::str::from_utf8(&body[..line_end]).ok()?;
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).ok()?;
        let data = &body[line_end + 2..];
        if size == 0 {
            return Some((out, true));
        }
        if data.len() < size + 2 {
            out.extend_from_slice(&data[..data.len().min(size)]);
            out.truncate(cap);
            return Some((out, false));
        }
        out.extend_from_slice(&data[..size]);
        if out.len() >= cap {
            out.truncate(cap);
            return Some((out, false));
        }
        body = &data[size + 2..];
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// PURE. Whether a certificate carries the key `pin` names: the SHA-256 of
/// its DER `SubjectPublicKeyInfo`.
pub fn spki_matches(certificate: &[u8], pin: &[u8; 32]) -> bool {
    let der = CertificateDer::from(certificate);
    let Ok(cert) = webpki::EndEntityCert::try_from(&der) else {
        return false;
    };
    let spki = cert.subject_public_key_info();
    Sha256::digest(spki.as_ref()).as_slice() == pin.as_slice()
}

/// Believes the one server whose key `pin` names, and checks the handshake's
/// signatures the way rustls does, so the server must hold that key.
#[derive(Debug)]
struct PinnedKey {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if spki_matches(end_entity.as_ref(), &self.pin) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client_config(pin: [u8; 32]) -> Option<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedKey {
        pin,
        provider: provider.clone(),
    });
    Some(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .ok()?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
    )
}

/// The key in `path`, when the file is root's (uid 0, as the host's real
/// owners are seen outside a jail) and neither it nor a directory above it
/// can be written by another account (the rule `contain` holds its sandbox
/// backend to, without the execute bit). The launcher reads the key with this
/// before it hands it into a jail.
#[cfg(unix)]
pub fn read_pin(path: &Path) -> Option<[u8; 32]> {
    use std::os::unix::fs::MetadataExt;
    let root = |uid: u32| uid == 0;
    let facts = crate::contain_io::backend_facts(path)?;
    if !crate::contain_io::root_file_trusted(&facts, &root) {
        return None;
    }
    let file = innerwarden_safe_io::open_no_follow(path).ok()?;
    let meta = file.metadata().ok()?;
    if !innerwarden_safe_io::is_regular_file(&meta)
        || !root(meta.uid())
        || meta.mode() & 0o022 != 0
        || meta.len() > MAX_SPKI_PIN_BYTES as u64
    {
        return None;
    }
    read_key_bytes(file)
}

#[cfg(not(unix))]
pub fn read_pin(_path: &Path) -> Option<[u8; 32]> {
    None
}

/// The key the launcher handed into the jail at `path`: one open, no link
/// followed, no wait on a FIFO, a regular file, no more than a key's bytes.
/// No owner is judged: inside the jail it is the launcher's word, as the
/// record beside it is, and the host's answer is still held to it in the
/// handshake.
pub fn read_jail_pin(path: &Path) -> Option<[u8; 32]> {
    let file = innerwarden_safe_io::open_no_follow(path).ok()?;
    let meta = file.metadata().ok()?;
    if !innerwarden_safe_io::is_regular_file(&meta) || meta.len() > MAX_SPKI_PIN_BYTES as u64 {
        return None;
    }
    read_key_bytes(file)
}

/// At most one byte more than a key, from an open file, as a key.
fn read_key_bytes(file: std::fs::File) -> Option<[u8; 32]> {
    let mut bytes = Vec::new();
    file.take(MAX_SPKI_PIN_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    parse_spki_pin(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::PublicKeyData;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread::JoinHandle;

    const ID: &str = "7f3a9c1e42b84d0e9a6c5f1b2d3e4a59";

    /// A certificate for 127.0.0.1 and its key, made for the test.
    fn certificate() -> (CertificateDer<'static>, PrivateKeyDer<'static>, [u8; 32]) {
        let made = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert = made.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(made.signing_key.serialize_der()));
        let pin: [u8; 32] = Sha256::digest(made.signing_key.subject_public_key_info()).into();
        (cert, key, pin)
    }

    /// A request read to the end its `content-length` names.
    fn whole_request(seen: &[u8]) -> bool {
        let Some(end) = find(seen, b"\r\n\r\n") else {
            return false;
        };
        let head = String::from_utf8_lossy(&seen[..end]);
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        seen.len() >= end + 4 + length
    }

    /// A TLS server on an ephemeral loopback port that reads ONE request in
    /// full, waits `delay`, and answers `response`. Its URL, the pin of its
    /// key, and the request it read (`None` when no handshake completed).
    fn server(
        response: Vec<u8>,
        delay: Duration,
    ) -> (String, [u8; 32], JoinHandle<Option<Vec<u8>>>) {
        let (cert, key, pin) = certificate();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().ok()?;
            tcp.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
            let connection = rustls::ServerConnection::new(Arc::new(config)).ok()?;
            let mut stream = rustls::StreamOwned::new(connection, tcp);
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            while !whole_request(&seen) {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => return (!seen.is_empty()).then_some(seen),
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
            std::thread::sleep(delay);
            let _ = stream.write_all(&response);
            let _ = stream.flush();
            stream.conn.send_close_notify();
            let _ = stream.flush();
            Some(seen)
        });
        (
            format!("https://127.0.0.1:{port}/api/agent/instance-decide"),
            pin,
            handle,
        )
    }

    fn ok_json(body: &serde_json::Value) -> Vec<u8> {
        let body = serde_json::to_vec(body).unwrap();
        let mut out = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(&body);
        out
    }

    fn answer_for(instance: &str) -> serde_json::Value {
        serde_json::json!({
            "v": 1, "instance_id": instance, "agent_type": "claude-code", "trust": "confined",
            "trust_source": "host", "verdict": "allow", "deciding_layer": "agent_type",
            "profile": "claude-code", "decision_id": "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
            "withheld": null, "signals_mismatch": false, "conflict": false, "incident_id": null,
        })
    }

    fn request() -> InstanceDecideRequest {
        innerwarden_agent_guard::identity::instance_decide_request(
            ID,
            Some("claude-code"),
            Some("s-1"),
            "curl http://203.0.113.9/x",
            &["bare_ip_fetch"],
            false,
        )
        .unwrap()
    }

    /// The request is posted whole to the route, as JSON, and the
    /// contract's answer for this instance is read.
    #[test]
    fn the_request_is_posted_to_the_route_and_the_answer_is_read() {
        let (url, pin, server) = server(ok_json(&answer_for(ID)), Duration::ZERO);
        let body = serde_json::to_vec(&request()).unwrap();
        let reply = ask(&url, &body, Duration::from_secs(5), &pin);
        let seen = server.join().unwrap().expect("a request");
        let text = String::from_utf8_lossy(&seen);
        assert!(
            text.starts_with("POST /api/agent/instance-decide HTTP/1.1\r\n"),
            "{text}"
        );
        assert!(
            text.to_ascii_lowercase()
                .contains("content-type: application/json"),
            "{text}"
        );
        let sent: InstanceDecideRequest =
            serde_json::from_slice(&seen[find(&seen, b"\r\n\r\n").unwrap() + 4..]).unwrap();
        assert_eq!(sent, request());
        let reply = crate::host_decide::read_reply(reply, Some(ID));
        assert!(
            matches!(reply, crate::host_decide::HostReply::Answer(_)),
            "{reply:?}"
        );
    }

    /// A server of the agent's own that holds the right key would still have
    /// to answer for this instance: an allow for another is not taken.
    #[test]
    fn a_forged_allow_for_another_instance_is_recorded_as_invalid() {
        let (url, pin, server) = server(
            ok_json(&answer_for("fedcba9876543210fedcba9876543210")),
            Duration::ZERO,
        );
        let reply = ask(&url, br#"{}"#, Duration::from_secs(5), &pin);
        server.join().unwrap();
        assert_eq!(
            crate::host_decide::read_reply(reply, Some(ID)),
            crate::host_decide::HostReply::Invalid
        );
    }

    /// A server whose key is not the published one gets no request through
    /// and gives no answer: the decision is today's, with no label.
    ///
    /// FAILS ON REVERT: believe any certificate in `PinnedKey` and the
    /// server's allow is read.
    #[test]
    fn a_certificate_the_key_file_does_not_name_gives_no_answer() {
        let (url, _pin, server) = server(ok_json(&answer_for(ID)), Duration::ZERO);
        let (_, _, other) = certificate();
        let reply = ask(&url, br#"{}"#, Duration::from_secs(5), &other);
        assert_eq!(reply, None);
        assert_eq!(
            server.join().unwrap(),
            None,
            "no request reached the server"
        );
        assert_eq!(
            crate::host_decide::read_reply(reply, Some(ID)),
            crate::host_decide::HostReply::None
        );
    }

    /// A host that answers late is not waited for past the bound.
    #[test]
    fn a_slow_host_is_withheld_within_the_bound() {
        let (url, pin, server) = server(ok_json(&answer_for(ID)), Duration::from_millis(1_500));
        let started = Instant::now();
        let reply = ask(&url, br#"{}"#, Duration::from_millis(400), &pin);
        let took = started.elapsed();
        assert_eq!(reply, None);
        assert!(took < Duration::from_millis(1_000), "{took:?}");
        let _ = server.join();
    }

    /// A `serve` of Community, or an older Active Defence, has no such route:
    /// its 404 is a status, and no answer.
    #[test]
    fn a_404_is_no_answer() {
        let (url, pin, server) = server(
            b"HTTP/1.1 404 Not Found\r\ncontent-length: 9\r\n\r\nnot found".to_vec(),
            Duration::ZERO,
        );
        let reply = ask(&url, br#"{}"#, Duration::from_secs(5), &pin);
        server.join().unwrap();
        assert_eq!(reply, Some((404, Vec::new())));
        assert_eq!(
            crate::host_decide::read_reply(reply, Some(ID)),
            crate::host_decide::HostReply::None
        );
    }

    /// With no key file, nothing is sent: not even a connection is opened.
    #[cfg(unix)]
    #[test]
    fn a_missing_key_file_sends_nothing() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let dir = tempfile::tempdir().unwrap();
        for key in [
            crate::host_decide::KeyFile::Jail,
            crate::host_decide::KeyFile::Host,
        ] {
            let reply = consult(
                &format!("https://127.0.0.1:{port}/api/agent/instance-decide"),
                &request(),
                key,
                &dir.path().join("agent-tls.spki"),
                Duration::from_millis(400),
            );
            assert_eq!(reply, None);
        }
        let accepted = AtomicUsize::new(0);
        if listener.accept().is_ok() {
            accepted.fetch_add(1, Ordering::SeqCst);
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "a connection was opened"
        );
    }

    /// A key file that is the user's own (anything of theirs could write it)
    /// is no key.
    #[cfg(unix)]
    #[test]
    fn a_key_file_of_the_users_own_is_no_key() {
        // SAFETY: geteuid takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(dir.path()).unwrap();
        let path = dir.join("agent-tls.spki");
        std::fs::write(
            &path,
            innerwarden_agent_guard::identity::spki_pin_line(&[7u8; 32]),
        )
        .unwrap();
        assert_eq!(read_pin(&path), None);
    }

    /// Inside the jail the launcher's copy is read with the record's rules:
    /// one open, no link, a regular file, bounded, and no owner judged (in
    /// the jail's user namespace an owner says nothing). The host's rule
    /// still refuses the same file.
    ///
    /// FAILS ON REVERT: hold the jail's copy to the host's owner rule, and
    /// a jail on a host whose bwrap is not setuid never asks.
    #[cfg(unix)]
    #[test]
    fn the_jails_copy_of_the_key_is_read_as_the_record_is() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(dir.path()).unwrap();
        let pin = [7u8; 32];
        let path = dir.join("agent-tls.spki");
        std::fs::write(
            &path,
            innerwarden_agent_guard::identity::spki_pin_line(&pin),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert_eq!(read_jail_pin(&path), Some(pin));
        // SAFETY: geteuid takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(read_pin(&path), None, "the host's file must be root's");
        }

        let link = dir.join("link.spki");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(read_jail_pin(&link), None, "a link is not followed");
        let fifo = dir.join("fifo.spki");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a valid C string and a mode.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert_eq!(read_jail_pin(&fifo), None, "a FIFO is not waited on");
        let long = dir.join("long.spki");
        std::fs::write(&long, "a".repeat(MAX_SPKI_PIN_BYTES + 1)).unwrap();
        assert_eq!(read_jail_pin(&long), None);
        let garbage = dir.join("garbage.spki");
        std::fs::write(&garbage, "not a key\n").unwrap();
        assert_eq!(read_jail_pin(&garbage), None);
        assert_eq!(read_jail_pin(&dir.join("absent.spki")), None);
        assert_eq!(read_jail_pin(&dir), None, "a folder is no key");
    }

    #[test]
    fn the_target_is_this_hosts_loopback_over_tls_only() {
        assert_eq!(
            loopback_target("https://127.0.0.1:8787/api/agent/instance-decide"),
            Some((
                "127.0.0.1:8787".parse().unwrap(),
                "/api/agent/instance-decide".to_string()
            ))
        );
        for other in [
            "http://127.0.0.1:8787/api/agent/instance-decide",
            "https://localhost:8787/api/agent/instance-decide",
            "https://10.0.0.5:8787/x",
            "https://127.0.0.1.evil.example:8787/x",
            "https://127.0.0.1:8787",
            "https://127.0.0.1:99999/x",
            "https://127.0.0.1:8787/x y",
        ] {
            assert_eq!(loopback_target(other), None, "{other}");
        }
    }

    #[test]
    fn a_response_is_read_by_its_length_its_chunks_or_its_end() {
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\n", false),
            Parsed::Incomplete
        );
        assert_eq!(parse_response(b"garbage\r\n\r\n", false), Parsed::Broken);
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", false),
            Parsed::Done(200, b"{}".to_vec())
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n{}", false),
            Parsed::Incomplete
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n{}", true),
            Parsed::Done(200, b"{}".to_vec())
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n", false),
            Parsed::Done(200, b"{}".to_vec())
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\n\r\n{}", true),
            Parsed::Done(200, b"{}".to_vec())
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 503 Busy\r\n\r\n", false),
            Parsed::Done(503, Vec::new())
        );
        let mut long = b"HTTP/1.1 200 OK\r\nContent-Length: 9000\r\n\r\n".to_vec();
        long.extend(std::iter::repeat_n(b'a', 5000));
        match parse_response(&long, false) {
            Parsed::Done(200, body) => assert_eq!(body.len(), MAX_INSTANCE_ANSWER_BYTES + 1),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_key_matches_only_its_own_certificate() {
        let (cert, _, pin) = certificate();
        assert!(spki_matches(cert.as_ref(), &pin));
        let (_, _, other) = certificate();
        assert!(!spki_matches(cert.as_ref(), &other));
        assert!(!spki_matches(b"not a certificate", &pin));
    }
}
