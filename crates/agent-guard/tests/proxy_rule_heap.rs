//! What the ATR rules cost each `innerwarden proxy` in memory.
//!
//! An MCP client keeps one proxy per wrapped server open for its whole
//! session, so whatever the proxy's rules compile to is paid once per server
//! per client (see `RuleConditions` in `src/rules.rs`). The embedded corpus
//! compiles a rule the first time a surface it applies to is screened, so the
//! cost lands on the first `tools/list`, the first `tools/call` and the first
//! tool result. This test measures exactly that with a counting allocator:
//! the live heap those three messages leave behind once the rule engine is in
//! the path, which is the compiled regexes plus the search caches one ordinary
//! result warms.
//!
//! Measured on Linux x86_64 (MiB): 14.1 with the 71 files of ATR v0.4.0;
//! 36.7 with upstream ATR batch 1 as first proposed (nine rules, four of
//! them re-declared from `llm_io`, a surface the proxy never compiles), and
//! nothing measured it then; 21.9 with the six rules the review kept. A
//! change to the corpus that needs more than [`BUDGET_BYTES`] raises it here,
//! in the same change, and says why in its description.
//!
//! This file holds one test on purpose: the allocator counts every thread in
//! the binary, so a second test running alongside would be counted too.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use innerwarden_agent_guard::mcp_proxy::jsonrpc::envelope_of;
use innerwarden_agent_guard::mcp_proxy::router::{
    route_message, Direction, PendingRequest, ProxyDecision,
};
use innerwarden_agent_guard::rules::RuleEngine;
use serde_json::{json, Value};

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

// SAFETY: every call is forwarded to the system allocator unchanged; the
// wrapper only keeps a running count of the bytes it holds.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        System.alloc_zeroed(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.fetch_add(
            new_size as isize - layout.size() as isize,
            Ordering::Relaxed,
        );
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The live heap the proxy's ATR rules may leave behind after one message of
/// each kind: the shipped corpus measures 21.9 MiB, so about 2 MiB of room.
const BUDGET_BYTES: isize = 24 * 1024 * 1024;

/// Below this, the engine compiled almost nothing, and a pass would say
/// nothing about the corpus.
const FLOOR_BYTES: isize = 4 * 1024 * 1024;

fn live() -> isize {
    LIVE.load(Ordering::Relaxed)
}

/// About 12 KB of an ordinary tool result: prose, links, JSON and HTML.
fn ordinary_result() -> String {
    let mut text = String::new();
    let mut n = 0;
    while text.len() < 12 * 1024 {
        n += 1;
        text.push_str(&format!(
            "Section {n}. The build finished in {n}.{n} s; the release notes are at \
             https://docs.example.com/guide/{n}. {{\"id\": {n}, \"status\": \"ok\", \
             \"items\": [1, 2, 3]}} <p class=\"note\">Run the tests before merging and \
             update the changelog.</p>\n"
        ));
    }
    text
}

fn route(
    engine: Option<&RuleEngine>,
    msg: &Value,
    dir: Direction,
    pending: Option<&PendingRequest>,
) -> ProxyDecision {
    let env = envelope_of(msg).expect("a JSON-RPC envelope");
    route_message(&env, dir, pending, engine, None)
}

/// One `tools/list` answer, one `tools/call` and one tool result: every
/// surface the proxy screens with ATR rules.
fn first_messages(engine: Option<&RuleEngine>, result_text: &str) -> usize {
    let listing = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        {"name": "read_file", "description": "Reads a file from the workspace and returns its text.",
         "inputSchema": {"type": "object"}},
        {"name": "search", "description": "Searches the project documentation for a phrase.",
         "inputSchema": {"type": "object"}}]}});
    let call = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "docs/guide.md"}}});
    let result = json!({"jsonrpc": "2.0", "id": 2,
        "result": {"content": [{"type": "text", "text": result_text}]}});
    let list_req = PendingRequest {
        method: "tools/list".into(),
        tool: None,
    };
    let call_req = PendingRequest {
        method: "tools/call".into(),
        tool: Some("read_file".into()),
    };
    let decisions = [
        route(engine, &listing, Direction::ServerToClient, Some(&list_req)),
        route(engine, &call, Direction::ClientToServer, None),
        route(engine, &result, Direction::ServerToClient, Some(&call_req)),
    ];
    decisions.iter().map(|d| d.verdict.alerts.len()).sum()
}

#[test]
fn the_proxys_atr_rules_stay_within_their_heap_budget() {
    let text = ordinary_result();
    let engine = RuleEngine::load_embedded();
    // Everything the proxy sets up on first use without the rule engine
    // (structural analyzers, redaction patterns) is warmed first, so the
    // measured difference is the rules alone.
    first_messages(None, &text);
    first_messages(None, &text);

    let before = live();
    let alerts = first_messages(Some(&engine), &text);
    let after = live();
    let used = after - before;
    eprintln!(
        "ATR rules on the proxy surfaces: {:.2} MB live heap after the first messages",
        used as f64 / (1024.0 * 1024.0)
    );

    assert_eq!(alerts, 0, "the ordinary messages raised an alert");
    assert!(
        used >= FLOOR_BYTES,
        "only {used} bytes: the engine compiled almost nothing, so this measured nothing"
    );
    assert!(
        used <= BUDGET_BYTES,
        "the proxy's ATR rules hold {used} bytes after one message of each kind, over the \
         budget of {BUDGET_BYTES}. Every `innerwarden proxy` pays this; see the module doc."
    );
    drop(engine);
}
