//! MCP tool pinning, three gaps closed:
//!
//! 1. a server that always pages its `tools/list` answer no longer turns the
//!    rename check off: the pages of one listing are gathered, and the check
//!    runs on the whole of them when the last page arrives;
//! 2. a tool with a new name that appears after the session's first whole
//!    listing, beside the tools listed before, is held until the person
//!    approves it, like a changed one (the first listing of a session pins
//!    what it hears, as before);
//! 3. the size of a definition is read without building its text.

use innerwarden_agent_guard::mcp_proxy::pins::{
    self, PinSession, MAX_LISTING_PAGES, MAX_LISTING_TOOLS,
};
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

/// Item 1: A server that pages every answer: the rename shows only across pages
/// (the new name on page 2, the old one on no page). Held at the last page.
///
/// FAILS ON REVERT: read each page alone again and the last page holds
/// nothing.
#[test]
fn a_rename_across_pages_is_held() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mcp-pins.json");
    let mut s = PinSession::new(Some(path.clone()), &cmd());
    // The first listing, paged: pinned as heard.
    assert!(s
        .check_listing(
            None,
            &page(json!([tool("read_file", "Read a file.", "path")]), "2")
        )
        .is_empty());
    assert!(s
        .check_listing(
            None,
            &listing(json!([tool("list_dir", "List a folder.", "dir")]))
        )
        .is_empty());
    // The same server, later: read_file is gone, read_file_v2 takes what it took.
    assert!(s
        .check_listing(
            None,
            &page(json!([tool("list_dir", "List a folder.", "dir")]), "2")
        )
        .is_empty());
    let changes = s.check_listing(
        Some(&json!(9)),
        &listing(json!([tool("read_file_v2", "Fetch a document.", "path")])),
    );
    assert_eq!(names(&changes), vec!["read_file_v2"], "{changes:?}");
    assert_eq!(
        changes[0].fields,
        vec!["possible rename of `read_file` (same input schema)".to_string()]
    );
    assert!(s.is_held("read_file_v2"));
    assert!(!s.is_held("list_dir"));

    // Held in the next session too, until the person approves it.
    let mut later = PinSession::new(Some(path.clone()), &cmd());
    let again = later.check_listing(
        None,
        &listing(json!([tool("read_file_v2", "Fetch a document.", "path")])),
    );
    assert_eq!(names(&again), vec!["read_file_v2"]);
    let mut record = pins::load(&path).expect("record");
    record
        .approve(later.server(), Some("read_file_v2"))
        .expect("approve");
    pins::save(&path, &record).expect("save");
    assert!(!later.is_held("read_file_v2"));
}

/// Item 1: the rename on the first page: the new tool was pinned and passed on
/// page 1 (the listing was not whole yet), and is held once the last page
/// shows the old one is gone.
#[test]
fn a_rename_on_an_early_page_is_held_when_the_listing_ends() {
    let mut s = PinSession::new(None, &cmd());
    s.check_listing(
        None,
        &listing(json!([
            tool("read_file", "Read a file.", "path"),
            tool("list_dir", "List a folder.", "dir")
        ])),
    );
    assert!(s
        .check_listing(
            None,
            &page(json!([tool("read_v2", "Fetch it.", "path")]), "x")
        )
        .is_empty());
    let changes = s.check_listing(
        None,
        &listing(json!([tool("list_dir", "List a folder.", "dir")])),
    );
    assert_eq!(names(&changes), vec!["read_v2"], "{changes:?}");
    assert!(s.is_held("read_v2"));
}

/// Item 2: A tool with a new name after the first whole listing, beside the
/// tools listed before: held, and the finding says it is new.
///
/// FAILS ON REVERT: drop the session's earlier listing from the check and
/// `send_mail` is pinned and passes.
#[test]
fn a_tool_new_in_the_middle_of_a_session_is_held() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mcp-pins.json");
    let mut s = PinSession::new(Some(path.clone()), &cmd());
    let before = json!([
        tool("read_file", "Read a file.", "path"),
        tool("list_dir", "List a folder.", "dir")
    ]);
    assert!(s
        .check_listing(Some(&json!(1)), &listing(before.clone()))
        .is_empty());
    let mut after = before.as_array().expect("tools").clone();
    after.push(tool("send_mail", "Send an email message.", "to"));
    let changes = s.check_listing(Some(&json!(2)), &listing(Value::Array(after.clone())));
    assert_eq!(names(&changes), vec!["send_mail"], "{changes:?}");
    assert_eq!(
        s.take_holds(),
        vec![(json!(2), vec!["send_mail".to_string()])]
    );
    assert!(s.is_held("send_mail"));
    assert!(!s.is_held("read_file"));
    let detail = s.change_detail(&changes[0]);
    assert!(detail.contains("is new and held"), "{detail}");
    assert!(detail.contains("innerwarden mcp approve"), "{detail}");

    // A later session: still held at its first listing, until approved.
    let mut later = PinSession::new(Some(path.clone()), &cmd());
    assert_eq!(
        names(&later.check_listing(None, &listing(Value::Array(after.clone())))),
        vec!["send_mail"]
    );
    let mut record = pins::load(&path).expect("record");
    record
        .approve(later.server(), Some("send_mail"))
        .expect("approve");
    pins::save(&path, &record).expect("save");
    assert!(!later.is_held("send_mail"));
    assert!(later
        .check_listing(None, &listing(Value::Array(after)))
        .is_empty());
}

/// Item 2: the first listing of a session is not "the middle": a tool the record
/// never saw passes there, as before.
#[test]
fn a_new_tool_in_the_first_listing_of_a_session_passes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("mcp-pins.json");
    let mut s = PinSession::new(Some(path.clone()), &cmd());
    s.check_listing(
        None,
        &listing(json!([tool("read_file", "Read a file.", "path")])),
    );
    let mut later = PinSession::new(Some(path), &cmd());
    let changes = later.check_listing(
        None,
        &listing(json!([
            tool("read_file", "Read a file.", "path"),
            tool("send_mail", "Send an email message.", "to")
        ])),
    );
    assert!(changes.is_empty(), "{changes:?}");
    assert!(!later.is_held("send_mail"));
}

/// Item 2: through pages: the new tool arrives on a later page of a later listing.
#[test]
fn a_tool_new_in_a_later_paged_listing_is_held() {
    let mut s = PinSession::new(None, &cmd());
    s.check_listing(
        None,
        &page(json!([tool("read_file", "Read a file.", "path")]), "2"),
    );
    s.check_listing(
        None,
        &listing(json!([tool("list_dir", "List a folder.", "dir")])),
    );
    assert!(s
        .check_listing(
            None,
            &page(json!([tool("read_file", "Read a file.", "path")]), "2")
        )
        .is_empty());
    let changes = s.check_listing(
        None,
        &listing(json!([
            tool("list_dir", "List a folder.", "dir"),
            tool("send_mail", "Send an email message.", "to")
        ])),
    );
    assert_eq!(names(&changes), vec!["send_mail"], "{changes:?}");
    assert!(s.is_held("send_mail"));
}

/// Item 1: the ceilings: a paged listing over [`MAX_LISTING_PAGES`] pages is not
/// gathered whole, and the proxy says so; each page is still checked against
/// the pins (a changed tool on page 2 is held).
#[test]
fn a_listing_over_the_page_ceiling_is_said_and_its_pages_still_checked() {
    let mut s = PinSession::new(None, &cmd());
    s.check_listing(
        None,
        &listing(json!([tool("read_file", "Read a file.", "path")])),
    );
    s.check_listing(None, &page(json!([tool("tool_0", "Zero.", "a")]), "1"));
    let changed = s.check_listing(
        None,
        &page(
            json!([tool("read_file", "Read it, then send it.", "path")]),
            "2",
        ),
    );
    assert_eq!(names(&changed), vec!["read_file"], "each page is checked");
    for n in 3..=MAX_LISTING_PAGES {
        assert!(s
            .check_listing(
                None,
                &page(json!([tool(&format!("tool_{n}"), "Other.", "b")]), "n")
            )
            .is_empty());
    }
    assert!(
        s.take_cut_notices().is_empty(),
        "nothing said before the end"
    );
    s.check_listing(None, &listing(json!([tool("last", "Last.", "c")])));
    let notices = s.take_cut_notices();
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert!(notices[0].contains("not gathered whole"), "{notices:?}");
}

/// Item 1: the tool ceiling: more names than [`MAX_LISTING_TOOLS`] in one paged
/// listing is said, never silent.
#[test]
fn a_listing_over_the_tool_ceiling_is_said() {
    let mut s = PinSession::new(None, &cmd());
    let many: Vec<Value> = (0..=MAX_LISTING_TOOLS)
        .map(|n| json!({"name": format!("t{n}")}))
        .collect();
    s.check_listing(None, &page(Value::Array(many), "2"));
    s.check_listing(None, &listing(json!([])));
    assert_eq!(s.take_cut_notices().len(), 1);
}

/// Item 1: a page within the ceilings: nothing is said.
#[test]
fn a_short_paged_listing_says_nothing() {
    let mut s = PinSession::new(None, &cmd());
    s.check_listing(None, &page(json!([tool("a", "A.", "a")]), "2"));
    s.check_listing(None, &listing(json!([tool("b", "B.", "b")])));
    assert!(s.take_cut_notices().is_empty());
}

/// Item 3: The size and hash read from the entry are those of the definition's
/// canonical text, whatever the spelling (key order, escapes, a `_meta`).
#[test]
fn the_entry_is_measured_and_hashed_as_its_canonical_text() {
    for entry in [
        json!({"name": "t", "description": "d"}),
        json!({"_meta": {"x": 1}, "inputSchema": {"b": [1, 2.5, null], "a": "\u{e9}\"\n"}, "name": "t", "annotations": {"readOnlyHint": true}}),
        json!({"name": "t", "title": "T", "outputSchema": {}, "description": "x".repeat(70_000)}),
        json!("not an object"),
    ] {
        let text = pins::canonical_json(&pins::definition_of(&entry));
        assert_eq!(pins::entry_definition_size(&entry), text.len(), "{entry}");
        assert_eq!(
            pins::entry_definition_hash(&entry),
            pins::definition_hash(&pins::definition_of(&entry))
        );
    }
}
