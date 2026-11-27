//! MCP tool pinning, two leftovers closed:
//!
//! 1. a server whose first session listed no tools leaves a listed mark in
//!    the record, so after a restart a tool it never listed is held, as for a
//!    server the record has pins for;
//! 2. whether an answer is the next page of a listing or a new listing is
//!    read from the client's request (a `cursor` or none), not from the
//!    `nextCursor` of the answer before it.

use innerwarden_agent_guard::mcp_proxy::jsonrpc::JsonRpcEnvelope;
use innerwarden_agent_guard::mcp_proxy::pins::{self, PinSession, TOOL_CHANGED_RULE};
use innerwarden_agent_guard::mcp_proxy::router::{route_message, Direction, PendingRequest};
use innerwarden_agent_guard::mcp_proxy::taint::TaintTracker;
use serde_json::{json, Value};

fn cmd() -> Vec<String> {
    vec!["npx".into(), "fs-server".into(), "/srv".into()]
}

fn listing(tools: Value) -> Value {
    json!({ "tools": tools })
}

fn page(tools: Value, next: &str) -> Value {
    json!({ "tools": tools, "nextCursor": next })
}

fn tool(name: &str, description: &str, property: &str) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": {property: {"type": "string"}}}
    })
}

fn names(changes: &[pins::ToolChange]) -> Vec<&str> {
    changes.iter().map(|c| c.tool.as_str()).collect()
}

/// Item 1: the first session heard an empty listing; after a restart the
/// server lists a tool. It was listed before, so the tool is new and held.
///
/// FAILS ON REVERT: read "listed before" from the pins alone again and the
/// restarted proxy pins the tool as first heard and lets it through.
#[test]
fn an_empty_first_listing_marks_the_server_as_listed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mcp-pins.json");
    let mut first = PinSession::new(Some(path.clone()), &cmd());
    assert!(first.check_listing(None, &listing(json!([]))).is_empty());
    let record = pins::load(&path).expect("record");
    let entry = &record.servers[first.server()];
    assert!(entry.listed, "the empty listing leaves the listed mark");
    assert!(entry.tools.is_empty());

    let mut restarted = PinSession::new(Some(path.clone()), &cmd());
    let changes = restarted.check_listing(
        Some(&json!(1)),
        &listing(json!([tool("send_mail", "Send an email.", "to")])),
    );
    assert_eq!(names(&changes), vec!["send_mail"], "{changes:?}");
    assert!(restarted.is_held("send_mail"));

    // The same in pages: held on its own page.
    let mut paged = PinSession::new(Some(path), &cmd());
    let changes = paged.check_listing(
        None,
        &page(json!([tool("fetch_url", "Fetch a page.", "url")]), "2"),
    );
    assert_eq!(names(&changes), vec!["fetch_url"], "{changes:?}");
}

/// Item 1, the record: an entry written before the mark existed was written
/// by a listing, so it reads as listed; a record that never saw the server
/// still pins the first listing as heard.
#[test]
fn an_entry_without_the_mark_reads_as_listed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mcp-pins.json");
    let id = pins::server_id(&cmd());
    let old = json!({"version": 1, "servers": {id.clone(): {"command": cmd(), "tools": {}}}});
    std::fs::write(&path, old.to_string()).expect("write");
    let mut s = PinSession::new(Some(path), &cmd());
    let changes = s.check_listing(None, &listing(json!([tool("a", "A tool.", "x")])));
    assert_eq!(names(&changes), vec!["a"]);

    let mut fresh = PinSession::new(None, &cmd());
    assert!(fresh
        .check_listing(None, &listing(json!([tool("a", "A tool.", "x")])))
        .is_empty());
}

/// Item 2: the first listing comes in pages; before its last page the client
/// asks for a new listing (no cursor). The answer is a new listing, not the
/// last page of the first: the first listing is over, so a tool no page of
/// it had is new in the session and held.
///
/// FAILS ON REVERT: read the answer by the `nextCursor` before it and the
/// new listing closes the first one, pinning `exfil` as first heard.
#[test]
fn a_request_without_a_cursor_starts_a_new_listing() {
    let mut s = PinSession::new(None, &cmd());
    s.note_list_request(Some(&json!(1)), None);
    assert!(s
        .check_listing(
            Some(&json!(1)),
            &page(json!([tool("read_file", "Read a file.", "path")]), "2")
        )
        .is_empty());
    s.note_list_request(Some(&json!(2)), Some(&json!({})));
    let changes = s.check_listing(
        Some(&json!(2)),
        &listing(json!([
            tool("read_file", "Read a file.", "path"),
            tool("exfil", "Send things away.", "url")
        ])),
    );
    assert_eq!(names(&changes), vec!["exfil"], "{changes:?}");
    assert!(s.is_held("exfil"));
    assert!(!s.is_held("read_file"));
}

/// Item 2: a request with a cursor continues the listing; one without starts
/// a new one, whole, whose rename check reads only what it lists.
///
/// FAILS ON REVERT: the new listing is taken as the last page of the paged
/// one, which listed `read_file`, so the rename is not seen.
#[test]
fn the_request_decides_what_the_answer_continues() {
    let mut s = PinSession::new(None, &cmd());
    // First listing, two pages asked for with a cursor: pinned as heard.
    s.note_list_request(Some(&json!("a")), None);
    assert!(s
        .check_listing(
            Some(&json!("a")),
            &page(json!([tool("read_file", "Read a file.", "path")]), "c1")
        )
        .is_empty());
    s.note_list_request(Some(&json!("b")), Some(&json!({"cursor": "c1"})));
    assert!(s
        .check_listing(
            Some(&json!("b")),
            &listing(json!([tool("list_dir", "List a folder.", "dir")]))
        )
        .is_empty());
    // A later listing starts in pages and is left; a new one is asked for.
    s.note_list_request(Some(&json!("c")), None);
    assert!(s
        .check_listing(
            Some(&json!("c")),
            &page(json!([tool("read_file", "Read a file.", "path")]), "c2")
        )
        .is_empty());
    s.note_list_request(Some(&json!("d")), None);
    let changes = s.check_listing(
        Some(&json!("d")),
        &listing(json!([
            tool("list_dir", "List a folder.", "dir"),
            tool("read_copy", "Copy out a file.", "path")
        ])),
    );
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert_eq!(changes[0].tool, "read_copy");
    assert_eq!(
        changes[0].fields,
        vec!["possible rename of `read_file` (same input schema)".to_string()]
    );
}

/// Item 2, through the router: the client's `tools/list` request is what the
/// pins read. Without a cursor the answer is a new listing.
///
/// FAILS ON REVERT of the router: the request is not noted, the answer is
/// read as the last page of the first listing and `exfil` passes.
#[test]
fn the_router_notes_the_request_for_the_pins() {
    let mut taint = TaintTracker::new().with_pins(PinSession::new(None, &cmd()));
    let message = |v: Value| -> JsonRpcEnvelope { serde_json::from_value(v).expect("envelope") };
    let asked = PendingRequest {
        method: "tools/list".into(),
        tool: None,
    };
    let request = |taint: &mut TaintTracker, id: u64, params: Value| {
        route_message(
            &message(json!({"jsonrpc": "2.0", "id": id, "method": "tools/list", "params": params})),
            Direction::ClientToServer,
            None,
            None,
            Some(taint),
        )
    };
    let answer = |taint: &mut TaintTracker, id: u64, result: Value| {
        route_message(
            &message(json!({"jsonrpc": "2.0", "id": id, "result": result})),
            Direction::ServerToClient,
            Some(&asked),
            None,
            Some(taint),
        )
    };
    request(&mut taint, 1, json!({}));
    let first = answer(
        &mut taint,
        1,
        page(json!([tool("read_file", "Read a file.", "path")]), "2"),
    );
    assert!(first
        .verdict
        .alerts
        .iter()
        .all(|a| a.rule != TOOL_CHANGED_RULE));
    request(&mut taint, 2, json!({}));
    let second = answer(
        &mut taint,
        2,
        listing(json!([tool("exfil", "Send things away.", "url")])),
    );
    assert!(
        second
            .verdict
            .alerts
            .iter()
            .any(|a| a.rule == TOOL_CHANGED_RULE && a.detail.contains("exfil")),
        "{:?}",
        second.verdict.alerts
    );
}
