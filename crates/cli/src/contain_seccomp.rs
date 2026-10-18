//! The seccomp filter a Linux jail of `innerwarden contain` starts its programs
//! under, in the style of Flatpak: a short classic BPF program the launcher
//! hands to bubblewrap (`--seccomp FD`). bubblewrap sets `no_new_privs`, builds
//! the jail, drops its privileges and then applies the filter, to the jail's
//! first process and to the command, before the command runs; nothing in the
//! jail runs without it.
//!
//! Every jail refuses keystroke injection into a terminal (`TIOCSTI`,
//! `TIOCLINUX`): a jail run from your terminal shares it, and a program could
//! otherwise queue input your shell reads after the jail ends. An identified
//! jail (`--identity`) also refuses new user namespaces and joining other
//! namespaces, so nothing in it can build a namespace of its own. A call made
//! with another architecture's numbers, or through the x32 ABI, kills the
//! process: the numbers below would not name the same calls there.
//!
//! PURE: the program and its bytes are built for either architecture on any
//! host, so the tests run them through a small interpreter everywhere. The
//! I/O layer (`contain_io`) hands the bytes to bubblewrap.

// The I/O that uses this is Linux-only; the tests run everywhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

/// `AUDIT_ARCH_X86_64` (`EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`).
/// The libc crate does not define it.
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// `AUDIT_ARCH_AARCH64` (`EM_AARCH64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`).
/// The libc crate does not define it.
pub const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

/// The bit an x32 call sets in its number on x86_64 (`__X32_SYSCALL_BIT`).
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// The number a tracer writes over a call it skips (strace's fault injection,
/// a debugger). The kernel runs the filter on it and then returns `ENOSYS`
/// without calling anything, so it is let through rather than killed as the
/// x32 number it would otherwise look like.
pub const SKIPPED_CALL: u32 = u32::MAX;

/// `CLONE_NEWUSER`, in the low word of the flags of `clone` and `unshare`.
pub const CLONE_NEWUSER: u32 = 0x1000_0000;

/// `TIOCSTI`: push a byte into a terminal's input queue.
pub const TIOCSTI: u32 = 0x5412;

/// `TIOCLINUX`: the Linux console's subcommands, one of which pastes the
/// selection into the console's input.
pub const TIOCLINUX: u32 = 0x541C;

/// `EPERM`, the same on both architectures.
pub const EPERM: u32 = 1;

/// `ENOSYS`, the same on both architectures. `clone3` answers this, never
/// `EPERM`: glibc 2.34 and later tries `clone3` first for every thread and
/// every child and falls back to `clone` only on `ENOSYS`.
pub const ENOSYS: u32 = 38;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

// Offsets in `struct seccomp_data`: `int nr`, `__u32 arch`, `__u64
// instruction_pointer`, `__u64 args[6]`. Both architectures are little
// endian, so the low word of an argument is at its own offset.
const OFFSET_NR: u32 = 0;
const OFFSET_ARCH: u32 = 4;
const OFFSET_ARG0_LOW: u32 = 16;
const OFFSET_ARG1_LOW: u32 = 24;

// Classic BPF opcodes (`linux/bpf_common.h`).
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_JMP_JGE_K: u16 = 0x35;
const BPF_JMP_JSET_K: u16 = 0x45;
const BPF_RET_K: u16 = 0x06;

/// One classic BPF instruction, laid out as `struct sock_filter` (8 bytes:
/// `__u16 code`, `__u8 jt`, `__u8 jf`, `__u32 k`). Its own type, not
/// `libc::sock_filter`, so the program builds and is tested on any host; a
/// Linux test holds the two to the same layout.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Insn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

/// The architectures this build has the call numbers of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

/// The call numbers the filter names, per architecture (libc 0.2.190).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Numbers {
    pub clone: u32,
    pub unshare: u32,
    pub setns: u32,
    pub clone3: u32,
    pub ioctl: u32,
}

impl Arch {
    /// The architecture this binary runs as, when it is one of these and
    /// little endian. Elsewhere there is no filter to hand in.
    pub fn native() -> Option<Arch> {
        if cfg!(target_endian = "little") && cfg!(target_arch = "x86_64") {
            Some(Arch::X86_64)
        } else if cfg!(target_endian = "little") && cfg!(target_arch = "aarch64") {
            Some(Arch::Aarch64)
        } else {
            None
        }
    }

    /// The `arch` the kernel puts in `seccomp_data` for a call of this
    /// architecture.
    pub fn audit(self) -> u32 {
        match self {
            Arch::X86_64 => AUDIT_ARCH_X86_64,
            Arch::Aarch64 => AUDIT_ARCH_AARCH64,
        }
    }

    pub fn numbers(self) -> Numbers {
        match self {
            Arch::X86_64 => Numbers {
                clone: 56,
                unshare: 272,
                setns: 308,
                clone3: 435,
                ioctl: 16,
            },
            Arch::Aarch64 => Numbers {
                clone: 220,
                unshare: 97,
                setns: 268,
                clone3: 435,
                ioctl: 29,
            },
        }
    }
}

/// Which jail the filter is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rules {
    /// Every jail: no keystrokes pushed into a terminal.
    Terminal,
    /// An identified jail (`--identity`): the terminal rule, no new user
    /// namespace, no joining a namespace.
    Identified,
}

impl Rules {
    /// The filter a launch gets: the identified one with `--identity`, the
    /// terminal one otherwise.
    pub fn for_launch(identity: bool) -> Rules {
        if identity {
            Rules::Identified
        } else {
            Rules::Terminal
        }
    }
}

/// Where a jump lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum To {
    Next,
    At(Label),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Label {
    Flags,
    Ioctl,
    Allow,
    Eperm,
    Enosys,
    Kill,
}

/// One step of the program before its jumps are resolved.
#[derive(Debug, Clone, Copy)]
enum Step {
    Load(u32),
    Jump { code: u16, k: u32, yes: To, no: To },
    Mark(Label),
    Ret(u32),
}

fn jeq(k: u32, yes: To, no: To) -> Step {
    Step::Jump {
        code: BPF_JMP_JEQ_K,
        k,
        yes,
        no,
    }
}

/// The steps of the program, in the order the spec of the jail gives them:
/// the architecture or KILL; the number; on x86_64 an x32 number KILLs;
/// `clone3` answers `ENOSYS`; `setns` `EPERM`; `unshare` and `clone` with
/// `CLONE_NEWUSER` in the low word of their flags `EPERM`; `ioctl` with
/// `TIOCSTI` or `TIOCLINUX` in the low word of its command `EPERM`; every
/// other call is allowed. The terminal rules keep only the `ioctl` check.
fn steps(arch: Arch, rules: Rules) -> Vec<Step> {
    use Label::*;
    let n = arch.numbers();
    let mut s = vec![
        Step::Load(OFFSET_ARCH),
        jeq(arch.audit(), To::Next, To::At(Kill)),
        Step::Load(OFFSET_NR),
    ];
    if arch == Arch::X86_64 {
        s.push(jeq(SKIPPED_CALL, To::At(Allow), To::Next));
        s.push(Step::Jump {
            code: BPF_JMP_JGE_K,
            k: X32_SYSCALL_BIT,
            yes: To::At(Kill),
            no: To::Next,
        });
    }
    if rules == Rules::Identified {
        s.push(jeq(n.clone3, To::At(Enosys), To::Next));
        s.push(jeq(n.setns, To::At(Eperm), To::Next));
        s.push(jeq(n.unshare, To::At(Flags), To::Next));
        s.push(jeq(n.clone, To::At(Flags), To::Next));
    }
    s.push(jeq(n.ioctl, To::At(Ioctl), To::At(Allow)));
    if rules == Rules::Identified {
        s.push(Step::Mark(Flags));
        s.push(Step::Load(OFFSET_ARG0_LOW));
        s.push(Step::Jump {
            code: BPF_JMP_JSET_K,
            k: CLONE_NEWUSER,
            yes: To::At(Eperm),
            no: To::At(Allow),
        });
    }
    s.extend([
        Step::Mark(Ioctl),
        Step::Load(OFFSET_ARG1_LOW),
        jeq(TIOCSTI, To::At(Eperm), To::Next),
        jeq(TIOCLINUX, To::At(Eperm), To::At(Allow)),
        Step::Mark(Allow),
        Step::Ret(SECCOMP_RET_ALLOW),
        Step::Mark(Eperm),
        Step::Ret(SECCOMP_RET_ERRNO | EPERM),
    ]);
    if rules == Rules::Identified {
        s.push(Step::Mark(Enosys));
        s.push(Step::Ret(SECCOMP_RET_ERRNO | ENOSYS));
    }
    s.push(Step::Mark(Kill));
    s.push(Step::Ret(SECCOMP_RET_KILL_PROCESS));
    s
}

/// Resolve the labels into forward jump offsets. Every jump in [`steps`] is
/// forward to a label it defines, and the program is a few dozen
/// instructions, far inside the 255 an offset can hold; the tests run every
/// program and hold its bytes.
fn assemble(steps: &[Step]) -> Vec<Insn> {
    let mut at: Vec<(Label, usize)> = Vec::new();
    let mut count = 0usize;
    for step in steps {
        match step {
            Step::Mark(label) => at.push((*label, count)),
            _ => count += 1,
        }
    }
    let target = |label: Label| {
        at.iter()
            .find(|(l, _)| *l == label)
            .map_or(0, |(_, index)| *index)
    };
    let mut out = Vec::with_capacity(count);
    for step in steps {
        let here = out.len();
        let offset = |to: To| match to {
            To::Next => 0,
            To::At(label) => {
                let distance = target(label).saturating_sub(here + 1);
                debug_assert!(target(label) > here && distance <= 255, "{label:?}");
                u8::try_from(distance).unwrap_or(u8::MAX)
            }
        };
        match *step {
            Step::Mark(_) => {}
            Step::Load(k) => out.push(Insn {
                code: BPF_LD_W_ABS,
                jt: 0,
                jf: 0,
                k,
            }),
            Step::Jump { code, k, yes, no } => out.push(Insn {
                code,
                jt: offset(yes),
                jf: offset(no),
                k,
            }),
            Step::Ret(k) => out.push(Insn {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k,
            }),
        }
    }
    out
}

/// The filter for `arch` and `rules`.
pub fn program(arch: Arch, rules: Rules) -> Vec<Insn> {
    assemble(&steps(arch, rules))
}

/// The program as bubblewrap reads it from its descriptor: each instruction's
/// 8 bytes of `struct sock_filter`, in the host's (little endian) order.
pub fn to_bytes(program: &[Insn]) -> Vec<u8> {
    let mut out = Vec::with_capacity(program.len() * 8);
    for insn in program {
        out.extend_from_slice(&insn.code.to_le_bytes());
        out.push(insn.jt);
        out.push(insn.jf);
        out.extend_from_slice(&insn.k.to_le_bytes());
    }
    out
}

/// The bytes of this build's filter for a launch, `None` where this build has
/// no numbers for the architecture it runs as.
pub fn native_filter(identity: bool) -> Option<Vec<u8>> {
    let arch = Arch::native()?;
    Some(to_bytes(&program(arch, Rules::for_launch(identity))))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// What the program answered.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Verdict {
        Allow,
        Errno(u32),
        Kill,
    }

    /// One call as the kernel describes it to a filter.
    pub(crate) struct Call {
        pub arch: u32,
        pub nr: u32,
        pub args: [u64; 6],
    }

    impl Call {
        pub(crate) fn new(arch: Arch, nr: u32, args: &[u64]) -> Call {
            let mut all = [0u64; 6];
            all[..args.len()].copy_from_slice(args);
            Call {
                arch: arch.audit(),
                nr,
                args: all,
            }
        }

        /// `struct seccomp_data`, little endian, as the kernel lays it out.
        fn data(&self) -> [u8; 64] {
            let mut d = [0u8; 64];
            d[0..4].copy_from_slice(&self.nr.to_le_bytes());
            d[4..8].copy_from_slice(&self.arch.to_le_bytes());
            d[8..16].copy_from_slice(&0x7f00_dead_beefu64.to_le_bytes());
            for (i, arg) in self.args.iter().enumerate() {
                d[16 + 8 * i..24 + 8 * i].copy_from_slice(&arg.to_le_bytes());
            }
            d
        }
    }

    /// A classic BPF interpreter for the instructions a seccomp filter may
    /// use here, with the kernel's own checks: loads aligned and inside
    /// `seccomp_data`, jumps forward and inside the program, the last
    /// instruction a return. An instruction it does not know fails the test,
    /// so the program cannot grow an operation the tests never ran.
    pub(crate) fn run(program: &[Insn], call: &Call) -> Verdict {
        const SECCOMP_RET_DATA: u32 = 0x0000_ffff;
        assert!(!program.is_empty() && program.len() <= 4096);
        assert_eq!(program.last().unwrap().code, BPF_RET_K, "ends in a return");
        let data = call.data();
        let mut acc: u32 = 0;
        let mut pc = 0usize;
        loop {
            let insn = program
                .get(pc)
                .expect("the program counter left the program");
            let jump = |taken: bool| {
                let to = pc + 1 + usize::from(if taken { insn.jt } else { insn.jf });
                assert!(to < program.len(), "jump past the end at {pc}");
                to
            };
            pc = match insn.code {
                BPF_LD_W_ABS => {
                    let at = insn.k as usize;
                    assert!(at.is_multiple_of(4) && at + 4 <= data.len(), "load at {at}");
                    acc = u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
                    pc + 1
                }
                BPF_JMP_JEQ_K => jump(acc == insn.k),
                BPF_JMP_JGE_K => jump(acc >= insn.k),
                BPF_JMP_JSET_K => jump(acc & insn.k != 0),
                BPF_RET_K => {
                    return match insn.k & 0xffff_0000 {
                        SECCOMP_RET_ALLOW => Verdict::Allow,
                        SECCOMP_RET_ERRNO => Verdict::Errno(insn.k & SECCOMP_RET_DATA),
                        SECCOMP_RET_KILL_PROCESS => Verdict::Kill,
                        other => panic!("a return this filter never uses: {other:#x}"),
                    };
                }
                other => panic!("an instruction the interpreter does not know: {other:#x}"),
            };
        }
    }

    const ARCHES: [Arch; 2] = [Arch::X86_64, Arch::Aarch64];
    const SIGCHLD: u64 = 17;
    const CLONE_NEWNS: u64 = 0x0002_0000;
    const CLONE_FILES: u64 = 0x0000_0400;
    const TCGETS: u64 = 0x5401;

    fn identified(arch: Arch, nr: u32, args: &[u64]) -> Verdict {
        run(
            &program(arch, Rules::Identified),
            &Call::new(arch, nr, args),
        )
    }

    fn terminal(arch: Arch, nr: u32, args: &[u64]) -> Verdict {
        run(&program(arch, Rules::Terminal), &Call::new(arch, nr, args))
    }

    /// The identified jail's refusals, on both architectures, by the low word
    /// of the argument the kernel uses: a new user namespace by `unshare` or
    /// `clone`, joining a namespace, and both terminal commands, including
    /// `TIOCSTI` with high bits set (the kernel takes the command as a 32-bit
    /// `unsigned int`, CVE-2019-10063).
    ///
    /// FAILS ON REVERT: compare all 64 bits of the `ioctl` command (the
    /// `0x1_0000_5412` case passes), or drop the `JSET` on `CLONE_NEWUSER`
    /// (`unshare(CLONE_NEWUSER)` passes).
    #[test]
    fn the_identified_filter_refuses_new_user_namespaces_joins_and_keystrokes() {
        for arch in ARCHES {
            let n = arch.numbers();
            let user = u64::from(CLONE_NEWUSER);
            for (what, nr, args) in [
                ("unshare(CLONE_NEWUSER)", n.unshare, vec![user]),
                (
                    "unshare(CLONE_NEWUSER|CLONE_NEWNS)",
                    n.unshare,
                    vec![user | CLONE_NEWNS],
                ),
                (
                    "unshare with high bits",
                    n.unshare,
                    vec![0xffff_ffff_0000_0000 | user],
                ),
                (
                    "clone(CLONE_NEWUSER|SIGCHLD)",
                    n.clone,
                    vec![user | SIGCHLD],
                ),
                ("setns(fd, 0)", n.setns, vec![3, 0]),
                ("setns(fd, CLONE_NEWUSER)", n.setns, vec![3, user]),
                ("ioctl(TIOCSTI)", n.ioctl, vec![0, u64::from(TIOCSTI)]),
                ("ioctl(TIOCLINUX)", n.ioctl, vec![0, u64::from(TIOCLINUX)]),
                ("ioctl(0x1_0000_5412)", n.ioctl, vec![0, 0x1_0000_5412]),
                (
                    "ioctl(0xffff_ffff_0000_541c)",
                    n.ioctl,
                    vec![0, 0xffff_ffff_0000_541c],
                ),
            ] {
                assert_eq!(
                    identified(arch, nr, &args),
                    Verdict::Errno(EPERM),
                    "{arch:?} {what}"
                );
            }
        }
    }

    /// What the identified jail lets through: other namespaces (the kernel
    /// then asks for a capability the jail does not have), threads and
    /// children by `clone` without `CLONE_NEWUSER`, other terminal commands,
    /// a command whose low word is not one of the two, and calls it does not
    /// name.
    #[test]
    fn the_identified_filter_lets_everything_else_through() {
        for arch in ARCHES {
            let n = arch.numbers();
            for (what, nr, args) in [
                ("unshare(CLONE_NEWNS)", n.unshare, vec![CLONE_NEWNS]),
                ("unshare(CLONE_FILES)", n.unshare, vec![CLONE_FILES]),
                ("clone(SIGCHLD)", n.clone, vec![SIGCHLD]),
                (
                    "clone with CLONE_NEWUSER only in the high word",
                    n.clone,
                    vec![(u64::from(CLONE_NEWUSER) << 32) | SIGCHLD],
                ),
                ("ioctl(TCGETS)", n.ioctl, vec![0, TCGETS]),
                (
                    "ioctl with TIOCSTI only in the high word",
                    n.ioctl,
                    vec![0, u64::from(TIOCSTI) << 32],
                ),
                ("call 0", 0, vec![]),
                ("call 63", 63, vec![]),
                ("call 434", 434, vec![]),
            ] {
                assert_eq!(
                    identified(arch, nr, &args),
                    Verdict::Allow,
                    "{arch:?} {what}"
                );
            }
        }
    }

    /// `clone3` answers `ENOSYS`, never `EPERM`: glibc 2.34 and later falls
    /// back to `clone` only on `ENOSYS`, and every thread (the hook asks the
    /// host on one) and every child it starts goes through it first.
    ///
    /// FAILS ON REVERT: answer `clone3` with `EPERM`.
    #[test]
    fn clone3_answers_enosys_so_glibc_falls_back_to_clone() {
        for arch in ARCHES {
            assert_eq!(
                identified(arch, arch.numbers().clone3, &[0, 88]),
                Verdict::Errno(ENOSYS),
                "{arch:?}"
            );
        }
    }

    /// A call made with another architecture's numbers is killed: on x86_64
    /// the i386 ABI (`int 0x80`) and on aarch64 the 32-bit arm one name other
    /// calls by the same numbers. So is an x32 call on x86_64. The number a
    /// tracer writes over a skipped call is not one of these.
    ///
    /// FAILS ON REVERT: drop the architecture check (i386's `ioctl` passes),
    /// or the x32 check.
    #[test]
    fn another_architecture_and_x32_are_killed() {
        const AUDIT_ARCH_I386: u32 = 0x4000_0003;
        const AUDIT_ARCH_ARM: u32 = 0x4000_0028;
        for rules in [Rules::Identified, Rules::Terminal] {
            for (arch, foreign) in [
                (Arch::X86_64, AUDIT_ARCH_I386),
                (Arch::X86_64, AUDIT_ARCH_AARCH64),
                (Arch::Aarch64, AUDIT_ARCH_ARM),
                (Arch::Aarch64, AUDIT_ARCH_X86_64),
            ] {
                for nr in [0, 54, arch.numbers().ioctl] {
                    let call = Call {
                        arch: foreign,
                        nr,
                        args: [0, u64::from(TIOCSTI), 0, 0, 0, 0],
                    };
                    assert_eq!(
                        run(&program(arch, rules), &call),
                        Verdict::Kill,
                        "{rules:?} {arch:?} {foreign:#x} {nr}"
                    );
                }
            }
            let x86 = Arch::X86_64;
            for nr in [X32_SYSCALL_BIT, X32_SYSCALL_BIT | 16, X32_SYSCALL_BIT | 272] {
                let call = Call::new(x86, nr, &[u64::from(CLONE_NEWUSER), u64::from(TIOCSTI)]);
                assert_eq!(run(&program(x86, rules), &call), Verdict::Kill, "{nr:#x}");
            }
            let skipped = Call::new(x86, SKIPPED_CALL, &[]);
            assert_eq!(run(&program(x86, rules), &skipped), Verdict::Allow);
        }
    }

    /// The terminal rules, which every jail gets, plain ones included: only
    /// the two terminal commands are refused. A plain jail keeps what it
    /// could do before, user namespaces included.
    ///
    /// FAILS ON REVERT: give the plain jail the identified rules.
    #[test]
    fn the_terminal_filter_refuses_only_keystroke_injection() {
        for arch in ARCHES {
            let n = arch.numbers();
            for command in [u64::from(TIOCSTI), u64::from(TIOCLINUX), 0x1_0000_5412] {
                assert_eq!(
                    terminal(arch, n.ioctl, &[1, command]),
                    Verdict::Errno(EPERM),
                    "{arch:?} {command:#x}"
                );
            }
            for (what, nr, args) in [
                (
                    "unshare(CLONE_NEWUSER)",
                    n.unshare,
                    vec![u64::from(CLONE_NEWUSER)],
                ),
                (
                    "clone(CLONE_NEWUSER)",
                    n.clone,
                    vec![u64::from(CLONE_NEWUSER) | SIGCHLD],
                ),
                ("setns", n.setns, vec![3, 0]),
                ("clone3", n.clone3, vec![0, 88]),
                ("ioctl(TCGETS)", n.ioctl, vec![0, TCGETS]),
            ] {
                assert_eq!(terminal(arch, nr, &args), Verdict::Allow, "{arch:?} {what}");
            }
        }
        assert_eq!(Rules::for_launch(false), Rules::Terminal);
        assert_eq!(Rules::for_launch(true), Rules::Identified);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The four programs, byte for byte: what bubblewrap reads. Any change to
    /// the program shows here first, and the tests above say whether it
    /// still does what it says.
    #[test]
    fn golden_bytes_of_each_filter() {
        let golden = [
            (Arch::X86_64, Rules::Identified, GOLDEN_X86_64_IDENTIFIED),
            (Arch::Aarch64, Rules::Identified, GOLDEN_AARCH64_IDENTIFIED),
            (Arch::X86_64, Rules::Terminal, GOLDEN_X86_64_TERMINAL),
            (Arch::Aarch64, Rules::Terminal, GOLDEN_AARCH64_TERMINAL),
        ];
        let mut wrong = Vec::new();
        for (arch, rules, expected) in golden {
            let bytes = to_bytes(&program(arch, rules));
            assert_eq!(bytes.len() % 8, 0);
            let got = hex(&bytes);
            if got != expected.replace(char::is_whitespace, "") {
                let lines: Vec<&str> = (0..got.len() / 16)
                    .map(|i| &got[i * 16..i * 16 + 16])
                    .collect();
                wrong.push(format!("{arch:?} {rules:?}:\n{}", lines.join("\n")));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n\n"));
    }

    /// Every jump of every program is forward and lands on an instruction of
    /// it; the last instruction is a return.
    #[test]
    fn every_jump_lands_inside_the_program() {
        for arch in ARCHES {
            for rules in [Rules::Identified, Rules::Terminal] {
                let p = program(arch, rules);
                assert_eq!(p.last().map(|i| i.code), Some(BPF_RET_K));
                for (at, insn) in p.iter().enumerate() {
                    if insn.code & 0x07 == 0x05 {
                        for offset in [insn.jt, insn.jf] {
                            assert!(
                                at + 1 + usize::from(offset) < p.len(),
                                "{arch:?} {rules:?} {at}"
                            );
                        }
                    }
                }
            }
        }
    }

    /// The numbers and the layout are libc's for the architecture this test
    /// runs as.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_numbers_and_the_layout_are_libcs() {
        let arch = Arch::native().expect("a Linux build this filter knows");
        let n = arch.numbers();
        assert_eq!(libc::c_long::from(n.clone), libc::SYS_clone);
        assert_eq!(libc::c_long::from(n.unshare), libc::SYS_unshare);
        assert_eq!(libc::c_long::from(n.setns), libc::SYS_setns);
        assert_eq!(libc::c_long::from(n.clone3), libc::SYS_clone3);
        assert_eq!(libc::c_long::from(n.ioctl), libc::SYS_ioctl);
        assert_eq!(i64::from(CLONE_NEWUSER), i64::from(libc::CLONE_NEWUSER));
        assert_eq!(libc::c_ulong::from(TIOCSTI), libc::TIOCSTI);
        assert_eq!(libc::c_ulong::from(TIOCLINUX), libc::TIOCLINUX);
        assert_eq!(i64::from(EPERM), i64::from(libc::EPERM));
        assert_eq!(i64::from(ENOSYS), i64::from(libc::ENOSYS));
        assert_eq!(SECCOMP_RET_KILL_PROCESS, libc::SECCOMP_RET_KILL_PROCESS);
        assert_eq!(SECCOMP_RET_ERRNO, libc::SECCOMP_RET_ERRNO);
        assert_eq!(SECCOMP_RET_ALLOW, libc::SECCOMP_RET_ALLOW);
        assert_eq!(
            u32::from(BPF_LD_W_ABS),
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS
        );
        assert_eq!(
            u32::from(BPF_JMP_JEQ_K),
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K
        );
        assert_eq!(
            u32::from(BPF_JMP_JGE_K),
            libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K
        );
        assert_eq!(
            u32::from(BPF_JMP_JSET_K),
            libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K
        );
        assert_eq!(u32::from(BPF_RET_K), libc::BPF_RET | libc::BPF_K);
        assert_eq!(
            std::mem::size_of::<Insn>(),
            std::mem::size_of::<libc::sock_filter>()
        );
        assert_eq!(std::mem::size_of::<libc::seccomp_data>(), 64);
        let insn = Insn {
            code: 0x1234,
            jt: 5,
            jf: 6,
            k: 0x89ab_cdef,
        };
        let theirs = libc::sock_filter {
            code: insn.code,
            jt: insn.jt,
            jf: insn.jf,
            k: insn.k,
        };
        // SAFETY: both are plain `repr(C)` structs of the same size, read as
        // bytes only.
        let (ours, libcs) = unsafe {
            (
                std::slice::from_raw_parts((&insn as *const Insn).cast::<u8>(), 8).to_vec(),
                std::slice::from_raw_parts((&theirs as *const libc::sock_filter).cast::<u8>(), 8)
                    .to_vec(),
            )
        };
        assert_eq!(ours, libcs);
        assert_eq!(to_bytes(&[insn]), ours);
    }

    /// The variable that tells a re-run of this test binary which side of the
    /// child-process test it is.
    #[cfg(target_os = "linux")]
    const CHILD_VAR: &str = "IW_SECCOMP_FILTER_CHILD";

    /// The answers of one child, as `name=value` lines: `0` for a call that
    /// succeeded, the errno for one that failed.
    #[cfg(target_os = "linux")]
    fn child_answers(filtered: bool) -> Vec<String> {
        use std::ffi::CStr;

        let errno = || std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        let answer = |rc: libc::c_long| if rc == -1 { errno() } else { 0 };
        let mut out = Vec::new();
        if filtered {
            let bytes = native_filter(true).expect("a filter for this build");
            let (chunks, rest) = bytes.as_chunks::<8>();
            assert!(rest.is_empty());
            let filter: Vec<libc::sock_filter> = chunks
                .iter()
                .map(|c| libc::sock_filter {
                    code: u16::from_le_bytes([c[0], c[1]]),
                    jt: c[2],
                    jf: c[3],
                    k: u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
                })
                .collect();
            let prog = libc::sock_fprog {
                len: u16::try_from(filter.len()).unwrap(),
                filter: filter.as_ptr().cast_mut(),
            };
            // SAFETY: prctl with integer arguments, then with a pointer to a
            // program that lives until the call returns (the kernel copies it).
            unsafe {
                assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
                assert_eq!(
                    libc::prctl(
                        libc::PR_SET_SECCOMP,
                        libc::SECCOMP_MODE_FILTER,
                        &prog as *const libc::sock_fprog
                    ),
                    0,
                    "the filter loads: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
        let thread = std::thread::Builder::new()
            .spawn(|| 7)
            .map(|h| h.join().unwrap_or(0));
        out.push(format!(
            "thread={}",
            if thread.is_ok_and(|v| v == 7) { 0 } else { 1 }
        ));
        let child = std::process::Command::new("true")
            .stdin(std::process::Stdio::null())
            .status();
        out.push(format!(
            "command={}",
            if child.is_ok_and(|s| s.success()) {
                0
            } else {
                1
            }
        ));
        // A terminal of the child's own, made its controlling terminal, so the
        // kernel would take TIOCSTI from it (or answer EIO where the host
        // turned legacy TIOCSTI off): an EPERM is then the filter's.
        // SAFETY: the pty calls take a descriptor this child owns and a
        // buffer it owns; TIOCSTI reads one byte that outlives the call.
        unsafe {
            let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(master >= 0, "posix_openpt");
            assert_eq!(libc::grantpt(master), 0);
            assert_eq!(libc::unlockpt(master), 0);
            let mut name = [0 as libc::c_char; 128];
            assert_eq!(libc::ptsname_r(master, name.as_mut_ptr(), name.len()), 0);
            assert!(
                libc::setsid() > 0,
                "setsid: {}",
                std::io::Error::last_os_error()
            );
            let slave = libc::open(CStr::from_ptr(name.as_ptr()).as_ptr(), libc::O_RDWR);
            assert!(slave >= 0, "open the pty");
            libc::ioctl(slave, libc::TIOCSCTTY, 0);
            let byte: u8 = b'x';
            let at = &byte as *const u8;
            out.push(format!(
                "tiocsti={}",
                answer(libc::c_long::from(libc::ioctl(slave, libc::TIOCSTI, at)))
            ));
            out.push(format!(
                "tiocsti_high={}",
                answer(libc::syscall(libc::SYS_ioctl, slave, 0x1_0000_5412u64, at))
            ));
        }
        // SAFETY: each call takes plain integers or a null pointer the kernel
        // rejects. The new user namespace goes last: where it is not refused,
        // nothing after it runs in it.
        unsafe {
            out.push(format!(
                "setns={}",
                answer(libc::c_long::from(libc::setns(-1, 0)))
            ));
            out.push(format!(
                "clone3={}",
                answer(libc::syscall(
                    libc::SYS_clone3,
                    std::ptr::null::<u8>(),
                    0usize
                ))
            ));
            out.push(format!(
                "unshare_newuser={}",
                answer(libc::c_long::from(libc::unshare(libc::CLONE_NEWUSER)))
            ));
        }
        out
    }

    /// Run this test again in a child process (never a fork of the test
    /// harness): `filtered` installs the identified filter first.
    #[cfg(target_os = "linux")]
    fn answers_of_a_child(filtered: bool) -> std::collections::BTreeMap<String, i32> {
        let name = module_path!()
            .split_once("::")
            .map(|(_, rest)| format!("{rest}::a_child_under_the_filter_is_refused_what_it_says"))
            .unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([name.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD_VAR, if filtered { "filtered" } else { "control" })
            .stdin(std::process::Stdio::null())
            .output()
            .expect("run the child");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "child failed: {stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // libtest may print the test's name on the line the first answer
        // starts, so an answer is found anywhere on its line.
        stdout
            .lines()
            .filter_map(|l| l.split_once("answer ").map(|(_, answer)| answer))
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_string(), v.parse().unwrap()))
            .collect()
    }

    /// The filter on a real kernel, in a child process: after
    /// `no_new_privs` and the identified filter, a new user namespace and
    /// joining one are refused with EPERM, raw `clone3` answers ENOSYS,
    /// threads and child processes still start (glibc falls back to `clone`),
    /// and TIOCSTI on the child's own controlling terminal is refused, high
    /// bits or not. The same child without the filter shows the kernel's own
    /// answers, so each refusal above is the filter's.
    ///
    /// FAILS ON REVERT: answer `clone3` with EPERM (the thread and the
    /// command fail on glibc 2.34 and later), compare all 64 bits of the
    /// `ioctl` command (`tiocsti_high` reaches the kernel), drop the `JSET`.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_child_under_the_filter_is_refused_what_it_says() {
        if let Ok(side) = std::env::var(CHILD_VAR) {
            for line in child_answers(side == "filtered") {
                println!("answer {line}");
            }
            return;
        }
        let eperm = libc::EPERM;
        let filtered = answers_of_a_child(true);
        let control = answers_of_a_child(false);
        eprintln!("filtered: {filtered:?}\ncontrol: {control:?}");
        assert_eq!(filtered["unshare_newuser"], eperm, "{filtered:?}");
        assert_eq!(filtered["setns"], eperm, "{filtered:?}");
        assert_eq!(filtered["clone3"], libc::ENOSYS, "{filtered:?}");
        assert_eq!(filtered["thread"], 0, "a thread starts: {filtered:?}");
        assert_eq!(filtered["command"], 0, "a command starts: {filtered:?}");
        assert_eq!(filtered["tiocsti"], eperm, "{filtered:?}");
        assert_eq!(filtered["tiocsti_high"], eperm, "{filtered:?}");
        // Without the filter the kernel answers otherwise: a bad descriptor,
        // and TIOCSTI taken (or EIO where legacy TIOCSTI is off).
        assert_eq!(control["setns"], libc::EBADF, "{control:?}");
        for key in ["tiocsti", "tiocsti_high"] {
            assert!(
                control[key] == 0 || control[key] == libc::EIO,
                "{key} without the filter: {control:?}"
            );
        }
        assert_eq!((control["thread"], control["command"]), (0, 0));
    }

    // Each instruction is `code(2) jt jf k(4)`, little endian, one per line.
    const GOLDEN_X86_64_IDENTIFIED: &str = "
        2000000004000000
        150000103e0000c0
        2000000000000000
        15000b00ffffffff
        35000d0000000040
        15000b00b3010000
        1500090034010000
        1500020010010000
        1500010038000000
        1500020510000000
        2000000010000000
        4500040300000010
        2000000018000000
        1500020012540000
        150001001c540000
        060000000000ff7f
        0600000001000500
        0600000026000500
        0600000000000080";
    const GOLDEN_AARCH64_IDENTIFIED: &str = "
        2000000004000000
        1500000eb70000c0
        2000000000000000
        15000b00b3010000
        150009000c010000
        1500020061000000
        15000100dc000000
        150002051d000000
        2000000010000000
        4500040300000010
        2000000018000000
        1500020012540000
        150001001c540000
        060000000000ff7f
        0600000001000500
        0600000026000500
        0600000000000080";
    const GOLDEN_X86_64_TERMINAL: &str = "
        2000000004000000
        150000093e0000c0
        2000000000000000
        15000500ffffffff
        3500060000000040
        1500000310000000
        2000000018000000
        1500020012540000
        150001001c540000
        060000000000ff7f
        0600000001000500
        0600000000000080";
    const GOLDEN_AARCH64_TERMINAL: &str = "
        2000000004000000
        15000007b70000c0
        2000000000000000
        150000031d000000
        2000000018000000
        1500020012540000
        150001001c540000
        060000000000ff7f
        0600000001000500
        0600000000000080";
}
