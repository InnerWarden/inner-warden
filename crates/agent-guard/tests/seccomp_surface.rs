//! The public surface of `innerwarden_agent_guard::seccomp`, called from
//! outside the crate as any other program calls it. An integration test is
//! its own crate, so a name made private, or a signature changed, fails to
//! compile here; a test inside the module would still reach it.
//!
//! FAILS ON REVERT: make `filter`, `native_filter`, `Arch::native`,
//! `Arch::host` or `Arch::audit` private (or change one's signature), or
//! hand out bytes that are not whole 8-byte instructions.

use innerwarden_agent_guard::seccomp::{filter, native_filter, Arch, Rules};

#[test]
fn the_filter_surface_is_reachable_from_outside_the_crate() {
    let _: fn() -> Option<Arch> = Arch::native;
    let _: fn() -> Option<Arch> = Arch::host;
    let _: fn(Arch) -> u32 = Arch::audit;
    let _: fn(Arch, Rules) -> Vec<u8> = filter;
    let _: fn(Rules) -> Option<Vec<u8>> = native_filter;

    for arch in [Arch::X86_64, Arch::Aarch64] {
        for rules in [Rules::Identified, Rules::Terminal] {
            let bytes = filter(arch, rules);
            assert!(!bytes.is_empty() && bytes.len().is_multiple_of(8));
            // BPF_MAXINSNS: the kernel refuses a longer program.
            assert!(bytes.len() / 8 <= 4096, "{arch:?} {rules:?}");
            assert_eq!(bytes, filter(arch, rules), "the same bytes every time");
        }
        // The two rules are two programs.
        assert_ne!(
            filter(arch, Rules::Identified),
            filter(arch, Rules::Terminal)
        );
    }
    assert_ne!(
        filter(Arch::X86_64, Rules::Identified),
        filter(Arch::Aarch64, Rules::Identified)
    );
    assert_eq!(Arch::X86_64.audit(), 0xC000_003E);
    assert_eq!(Arch::Aarch64.audit(), 0xC000_00B7);

    // The native filter is `filter` for the architecture this build runs as.
    match Arch::native() {
        Some(arch) => {
            for rules in [Rules::Identified, Rules::Terminal] {
                assert_eq!(native_filter(rules), Some(filter(arch, rules)));
            }
        }
        None => assert_eq!(native_filter(Rules::Terminal), None),
    }
    if cfg!(target_os = "linux") {
        assert!(Arch::host().is_some(), "a Linux host this filter knows");
    } else {
        assert_eq!(Arch::host(), None, "no seccomp off Linux");
    }
}
