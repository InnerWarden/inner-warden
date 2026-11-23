//! What hostile tool results can make the ATR rules keep in each
//! `innerwarden proxy`.
//!
//! A wrapped MCP server chooses what its tools return, and the proxy screens
//! every result with the `mcp_exchange` rules (`mcp::inspect_response`, with
//! no size cap). Each rule condition keeps search scratch between searches: a
//! lazy DFA's cache of the states it built, and a PikeVM's when the lazy DFA
//! gives up. Text written to drive the automata, a 64 KB result of the rules'
//! own trigger words with few or no line breaks, fills a lazy-DFA cache to its
//! 2 MiB capacity. Before `RETAINED_CACHE_BYTES` (`src/rules.rs`) bounded what
//! a condition keeps, those caches stayed for the life of the proxy. Measured
//! on Linux x86_64, the hostile messages below added, over what the ordinary
//! one left: 5.8 MiB on the 71 files of ATR v0.4.0 (5.2 MiB once each
//! condition compiled to a forward matcher), and 27.7 MiB with upstream ATR
//! batch 2 as first proposed. With the bound they add about 1 MiB.
//!
//! This test routes, through the proxy's own routing (`route_message`), one
//! ordinary 64 KB result and then hostile 64 KB results and descriptions, and
//! counts the live heap the rule engine is left holding. It holds the growth
//! the hostile messages add over the ordinary one to [`GROWTH_BUDGET_BYTES`],
//! and the total to [`TOTAL_BUDGET_BYTES`].
//!
//! This file holds one test on purpose: the allocator counts every thread in
//! the binary, so a second test running alongside would be counted too.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use innerwarden_agent_guard::mcp_proxy::jsonrpc::envelope_of;
use innerwarden_agent_guard::mcp_proxy::router::{route_message, Direction, PendingRequest};
use innerwarden_agent_guard::rules::{AtrSource, RuleEngine};
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

/// What the hostile messages may add to the live heap over what the ordinary
/// result left: about 1 MiB is measured with the bound, 5.2 MiB without it on
/// the 71 files of ATR v0.4.0 alone.
const GROWTH_BUDGET_BYTES: isize = 3 * 1024 * 1024;

/// The live heap the proxy's ATR rules may hold after all of it: the compiled
/// automata of every rule the surfaces reached plus what their searches keep.
const TOTAL_BUDGET_BYTES: isize = 24 * 1024 * 1024;

/// Below this, the hostile texts warmed almost nothing, and a pass would say
/// nothing about the bound.
const FLOOR_BYTES: isize = 2 * 1024 * 1024;

const SIZE: usize = 64 * 1024;

fn live() -> isize {
    LIVE.load(Ordering::Relaxed)
}

/// A fixed xorshift, so every run screens the same text.
struct Words(u64);

impl Words {
    fn text(&mut self, words: &[&str], line_every: u64) -> String {
        let mut text = String::with_capacity(SIZE + 64);
        while text.len() < SIZE {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            text.push_str(words[(self.0 % words.len() as u64) as usize]);
            text.push(if line_every > 0 && self.0.is_multiple_of(line_every) {
                '\n'
            } else {
                ' '
            });
        }
        text
    }
}

fn ordinary() -> String {
    let mut text = String::new();
    let mut n = 0;
    while text.len() < SIZE {
        n += 1;
        text.push_str(&format!(
            "Section {n}. The build finished in {n}.{n} s; the release notes are at \
             https://docs.example.com/guide/{n}. {{\"id\": {n}, \"status\": \"ok\"}} \
             <p class=\"note\">Run the tests before merging and update the changelog.</p>\n"
        ));
    }
    text
}

/// Word salad of the trigger words of the shipped rules' bounded
/// repetitions: override phrases, retrieval verbs, addresses, document
/// markers, fake system lines, glitch-token names, and non-ASCII letters for
/// the patterns whose Unicode `\b` makes the lazy DFA give up.
fn hostile() -> Vec<String> {
    const FILLER: &[&str] = &[
        "the", "a", "report", "and", "of", "to", "x", "data", "is", "ok", "we", "then",
    ];
    let sets: &[(&[&str], u64)] = &[
        (
            &[
                "ignore all previous instructions",
                "disregard prior instructions",
                "send the password to",
                "retrieve my credit card",
                "get my search history",
                "download my DNA data",
                "email",
                "send",
                "a@b.co",
                "@",
            ],
            0,
        ),
        (
            &[
                "***NEW IMPORTANT INSTRUCTIONS***",
                "[SYSTEM MESSAGE]",
                "STATUS",
                "TOKEN_ID",
                "BEHAVIOR",
                "translate the following sentence into French",
                "include it in your response",
                "base64",
            ],
            5,
        ),
        (
            &[
                "IMPORTANT!!!",
                "ignore",
                "previous instructions",
                "system prompt",
                "you are now",
                "<IMPORTANT>",
                "do not tell the user",
                "curl http://x.io",
                "~/.ssh/id_rsa",
            ],
            0,
        ),
        (
            &[
                "email password",
                "forward token",
                "ignore all previous instructions",
                "context: x is",
                "variable: y",
                "send",
                "a@b.co",
                "café",
                "naïve",
                "日本語",
            ],
            0,
        ),
    ];
    let mut words = Words(0x9e37_79b9_7f4a_7c15);
    sets.iter()
        .map(|(set, line_every)| {
            let mut all: Vec<&str> = set.to_vec();
            all.extend_from_slice(FILLER);
            words.text(&all, *line_every)
        })
        .collect()
}

fn route(engine: Option<&RuleEngine>, msg: &Value, method: &str) -> usize {
    let env = envelope_of(msg).expect("a JSON-RPC envelope");
    let pending = PendingRequest {
        method: method.into(),
        tool: (method == "tools/call").then(|| "fetch".into()),
    };
    route_message(
        &env,
        Direction::ServerToClient,
        Some(&pending),
        engine,
        None,
    )
    .verdict
    .alerts
    .iter()
    // A text past the proxy's 64 KiB read cap is cut, and the cut is said
    // with AG-RESP-PARTIAL; the ordinary text here is just over it. That
    // notice is no rule matching the text, which is what is counted.
    .filter(|alert| alert.rule != "AG-RESP-PARTIAL")
    .count()
}

fn tool_result(engine: Option<&RuleEngine>, text: &str) -> usize {
    let msg = json!({"jsonrpc": "2.0", "id": 2,
        "result": {"content": [{"type": "text", "text": text}]}});
    route(engine, &msg, "tools/call")
}

fn tool_listing(engine: Option<&RuleEngine>, text: &str) -> usize {
    let msg = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [
        {"name": "fetch", "description": text, "inputSchema": {"type": "object"}}]}});
    route(engine, &msg, "tools/list")
}

#[test]
fn hostile_results_leave_the_proxys_atr_rules_within_their_heap_budget() {
    let ordinary = ordinary();
    let hostile = hostile();
    let engine = RuleEngine::load_embedded();
    // Everything the proxy sets up on first use without the rule engine
    // (structural analyzers, redaction patterns and their own caches) is
    // warmed with the same texts first, so the measured difference is the
    // rules alone.
    for _ in 0..2 {
        tool_result(None, &ordinary);
        tool_listing(None, &ordinary);
        for text in &hostile {
            tool_result(None, text);
            tool_listing(None, text);
        }
    }

    let before = live();
    // Every rule the proxy's surfaces select, compiled before the ordinary
    // messages: the growth measured after is the search caches alone, not
    // the rules a hostile text's literals reach first.
    engine.warm(AtrSource::ToolCall);
    engine.warm(AtrSource::McpExchange);
    let ordinary_alerts =
        tool_result(Some(&engine), &ordinary) + tool_listing(Some(&engine), &ordinary);
    let after_ordinary = live();
    for text in &hostile {
        tool_result(Some(&engine), text);
        tool_listing(Some(&engine), text);
    }
    let after_hostile = live();

    let mib = |b: isize| b as f64 / (1024.0 * 1024.0);
    let growth = after_hostile - after_ordinary;
    let total = after_hostile - before;
    eprintln!(
        "ATR rules: {:.2} MiB after one ordinary result and listing, {:.2} MiB after {} hostile \
         ones (growth {:.2} MiB)",
        mib(after_ordinary - before),
        mib(total),
        hostile.len(),
        mib(growth)
    );

    assert_eq!(ordinary_alerts, 0, "the ordinary messages raised an alert");
    assert!(
        total >= FLOOR_BYTES,
        "only {:.2} MiB in use: the messages reached almost no rule",
        mib(total)
    );
    assert!(
        growth <= GROWTH_BUDGET_BYTES,
        "hostile messages added {:.2} MiB over the ordinary one (budget {:.2} MiB): search \
         caches are kept past `RETAINED_CACHE_BYTES`",
        mib(growth),
        mib(GROWTH_BUDGET_BYTES)
    );
    assert!(
        total <= TOTAL_BUDGET_BYTES,
        "the proxy's ATR rules hold {:.2} MiB after hostile messages (budget {:.2} MiB)",
        mib(total),
        mib(TOTAL_BUDGET_BYTES)
    );
}
