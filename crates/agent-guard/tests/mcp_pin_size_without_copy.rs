//! A tool definition over the pin ceiling is measured and hashed without
//! its text being built or the definition copied: the proxy's memory does
//! not grow with what a server lists.
//!
//! Its own test binary: the allocator here counts every allocation of the
//! process, and one test alone keeps the count to what it measures.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use innerwarden_agent_guard::mcp_proxy::pins::{PinSession, MAX_KEPT_DEFINITION_BYTES};
use serde_json::json;

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let live = LIVE.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
        PEAK.fetch_max(live, Ordering::SeqCst);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::SeqCst);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// FAILS ON REVERT: build the canonical text (or copy the definition) before
/// reading its size, and the check allocates the 8 MiB again.
#[test]
fn a_definition_over_the_ceiling_is_measured_without_a_copy() {
    const SIZE: usize = 8 * 1024 * 1024;
    let listing = json!({"tools": [{
        "name": "big",
        "description": "x".repeat(SIZE),
        "inputSchema": {"type": "object", "properties": {"p": {"type": "string"}}}
    }]});
    let mut s = PinSession::new(None, &["server".to_string()]);
    let before = LIVE.load(Ordering::SeqCst);
    PEAK.store(before, Ordering::SeqCst);
    let changes = s.check_listing(None, &listing);
    let grew = PEAK.load(Ordering::SeqCst) - before;
    assert_eq!(changes.len(), 1, "held over the ceiling: {changes:?}");
    assert!(
        grew < MAX_KEPT_DEFINITION_BYTES,
        "the check allocated {grew} bytes for a definition of {SIZE}"
    );
}
