//! The seccomp filter a Linux jail of `innerwarden contain` starts its programs
//! under, in the style of Flatpak: a short classic BPF program the launcher
//! hands to bubblewrap (`--seccomp FD`). bubblewrap sets `no_new_privs`, builds
//! the jail, drops its privileges and then applies the filter, to the jail's
//! first process and to the command, before the command runs; nothing in the
//! jail runs without it.
//!
//! Every jail refuses the two terminal commands that push input into a
//! terminal (`TIOCSTI`, `TIOCLINUX`): a jail run from your terminal shares it,
//! and a program could otherwise queue input your shell reads after the jail
//! ends. A plain jail applies that rule to every ABI the kernel runs for its
//! architecture, each by its own numbers (on x86_64 the native, x32 and i386
//! ones, on aarch64 the native and 32-bit arm ones), and lets every other call
//! through, so a 32-bit program runs in it as it did before the filter.
//!
//! An identified jail (`--identity`) also refuses new user namespaces and
//! joining other namespaces, so nothing in it can build a namespace of its
//! own. It ends a call made through any other ABI (another architecture's, or
//! x32): the numbers it names would not name the same calls there.
//!
//! PURE, and the one definition of these programs: [`filter`] gives the exact
//! bytes the launcher hands to bubblewrap, for either architecture, on any
//! host. So the programs are built and checked the same everywhere, and the
//! tests run them through a small interpreter on every OS. The launcher's I/O
//! (`contain_io` in the `innerwarden` binary) only puts the bytes on a pipe.
//!
//! The surface is small on purpose: [`Arch`] (with [`Arch::native`] and
//! [`Arch::host`]), [`Rules`], [`filter`] and [`native_filter`]. The
//! instructions behind them are private, so a change to the program shows
//! in the golden bytes below and nowhere else.

/// `AUDIT_ARCH_X86_64` (`EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`).
/// The libc crate does not define it.
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

/// `AUDIT_ARCH_AARCH64` (`EM_AARCH64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`).
/// The libc crate does not define it.
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

/// `AUDIT_ARCH_I386` (`EM_386 | __AUDIT_ARCH_LE`): a call an x86_64 kernel
/// runs through its i386 ABI (`int 0x80`, a 32-bit program).
const AUDIT_ARCH_I386: u32 = 0x4000_0003;

/// `AUDIT_ARCH_ARM` (`EM_ARM | __AUDIT_ARCH_LE`): a call an aarch64 kernel
/// runs for a 32-bit arm program.
const AUDIT_ARCH_ARM: u32 = 0x4000_0028;

/// The bit an x32 call sets in its number on x86_64 (`__X32_SYSCALL_BIT`).
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// x32's `ioctl` (514, with [`X32_SYSCALL_BIT`] set). Before Linux 5.4 the
/// native and x32 calls were run from one table: a native call of 514 ran
/// x32's `ioctl`, and an x32 call of 16 the native one. So on x86_64 every
/// filter takes 514 as an `ioctl` too.
const X32_IOCTL: u32 = 514;

/// `ioctl` in the i386 and the 32-bit arm tables alike.
const COMPAT_IOCTL: u32 = 54;

/// The number a tracer writes over a call it skips (strace's fault injection,
/// a debugger). The kernel runs the filter on it and then returns `ENOSYS`
/// without calling anything, so it is let through rather than killed as the
/// x32 number it would otherwise look like.
const SKIPPED_CALL: u32 = u32::MAX;

/// `CLONE_NEWUSER`, in the low word of the flags of `clone` and `unshare`.
const CLONE_NEWUSER: u32 = 0x1000_0000;

/// `TIOCSTI`: push a byte into a terminal's input queue.
const TIOCSTI: u32 = 0x5412;

/// `TIOCLINUX`: the Linux console's subcommands, one of which pastes the
/// selection into the console's input.
const TIOCLINUX: u32 = 0x541C;

/// `EPERM`, the same on both architectures.
const EPERM: u32 = 1;

/// `ENOSYS`, the same on both architectures. `clone3` answers this, never
/// `EPERM`: glibc 2.34 and later tries `clone3` first for every thread and
/// every child and falls back to `clone` only on `ENOSYS`.
const ENOSYS: u32 = 38;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

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
struct Insn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// The architectures this module has the call numbers of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

/// The call numbers the filter names, per architecture (libc 0.2.190).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Numbers {
    clone: u32,
    unshare: u32,
    setns: u32,
    clone3: u32,
    ioctl: u32,
}

impl Arch {
    /// The architecture this build runs as, when it is one of these and
    /// little endian. Elsewhere there is no filter to hand in. This is the
    /// one the launcher builds its filter for.
    pub fn native() -> Option<Arch> {
        if cfg!(target_endian = "little") && cfg!(target_arch = "x86_64") {
            Some(Arch::X86_64)
        } else if cfg!(target_endian = "little") && cfg!(target_arch = "aarch64") {
            Some(Arch::Aarch64)
        } else {
            None
        }
    }

    /// The architecture of the Linux kernel this runs on, as `uname` gives
    /// its machine, when it is one of these. It differs from [`Arch::native`]
    /// only for a build run under another architecture's emulation, where a
    /// jail runs without a filter (its start-up probe fails). `None` off
    /// Linux, where there is no seccomp.
    pub fn host() -> Option<Arch> {
        #[cfg(target_os = "linux")]
        {
            // SAFETY: `uname` fills the struct it is given, which lives until
            // it returns; `machine` is then a NUL-terminated string inside it.
            let machine = unsafe {
                let mut names: libc::utsname = std::mem::zeroed();
                if libc::uname(&mut names) != 0 {
                    return None;
                }
                std::ffi::CStr::from_ptr(names.machine.as_ptr())
                    .to_string_lossy()
                    .into_owned()
            };
            Arch::from_machine(&machine)
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    /// PURE. The architecture a Linux kernel's machine name (`uname -m`)
    /// names, when it is one of these: `x86_64`, and `aarch64` (or `arm64`,
    /// as some tools print it). A 32-bit kernel (`i686`, `armv7l`) is none
    /// of them.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn from_machine(machine: &str) -> Option<Arch> {
        match machine.trim() {
            "x86_64" => Some(Arch::X86_64),
            "aarch64" | "arm64" => Some(Arch::Aarch64),
            _ => None,
        }
    }

    /// The `arch` the kernel puts in `seccomp_data` for a call of this
    /// architecture (its `AUDIT_ARCH_*` value).
    pub fn audit(self) -> u32 {
        match self {
            Arch::X86_64 => AUDIT_ARCH_X86_64,
            Arch::Aarch64 => AUDIT_ARCH_AARCH64,
        }
    }

    /// The `arch` of a call this architecture's kernel runs for a 32-bit
    /// program, and that ABI's `ioctl` number.
    fn compat(self) -> (u32, u32) {
        match self {
            Arch::X86_64 => (AUDIT_ARCH_I386, COMPAT_IOCTL),
            Arch::Aarch64 => (AUDIT_ARCH_ARM, COMPAT_IOCTL),
        }
    }

    fn numbers(self) -> Numbers {
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
    /// Every jail: no keystrokes pushed into a terminal, by any ABI the
    /// kernel runs; every other call allowed.
    Terminal,
    /// An identified jail (`--identity`): the terminal rule, no new user
    /// namespace, no joining a namespace, and no call through another ABI.
    Identified,
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
    X32,
    Compat,
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
/// the architecture; the number; on x86_64 an x32 number; `clone3` answers
/// `ENOSYS`; `setns` `EPERM`; `unshare` and `clone` with `CLONE_NEWUSER` in
/// the low word of their flags `EPERM`; `ioctl` (on x86_64 also 514, see
/// [`X32_IOCTL`]) with `TIOCSTI` or `TIOCLINUX` in the low word of its
/// command `EPERM`; every other call is allowed.
///
/// The identified rules KILL a call of another architecture and an x32 one.
/// The terminal rules keep only the `ioctl` check, and run it on every ABI
/// the kernel has for the architecture, by that ABI's numbers: x32's
/// `ioctl` (and 16, which older kernels ran as the native one), and the
/// 32-bit `ioctl` of i386 or arm. Any other `arch` is KILLed.
fn steps(arch: Arch, rules: Rules) -> Vec<Step> {
    use Label::*;
    let n = arch.numbers();
    let identified = rules == Rules::Identified;
    let x86 = arch == Arch::X86_64;
    let mut s = vec![
        Step::Load(OFFSET_ARCH),
        jeq(
            arch.audit(),
            To::Next,
            To::At(if identified { Kill } else { Compat }),
        ),
        Step::Load(OFFSET_NR),
    ];
    if x86 {
        s.push(jeq(SKIPPED_CALL, To::At(Allow), To::Next));
        s.push(Step::Jump {
            code: BPF_JMP_JGE_K,
            k: X32_SYSCALL_BIT,
            yes: To::At(if identified { Kill } else { X32 }),
            no: To::Next,
        });
    }
    if identified {
        s.push(jeq(n.clone3, To::At(Enosys), To::Next));
        s.push(jeq(n.setns, To::At(Eperm), To::Next));
        s.push(jeq(n.unshare, To::At(Flags), To::Next));
        s.push(jeq(n.clone, To::At(Flags), To::Next));
    }
    if x86 {
        s.push(jeq(n.ioctl, To::At(Ioctl), To::Next));
        s.push(jeq(X32_IOCTL, To::At(Ioctl), To::At(Allow)));
    } else {
        s.push(jeq(n.ioctl, To::At(Ioctl), To::At(Allow)));
    }
    if identified {
        s.push(Step::Mark(Flags));
        s.push(Step::Load(OFFSET_ARG0_LOW));
        s.push(Step::Jump {
            code: BPF_JMP_JSET_K,
            k: CLONE_NEWUSER,
            yes: To::At(Eperm),
            no: To::At(Allow),
        });
    } else {
        if x86 {
            // The number is still in the accumulator.
            s.push(Step::Mark(X32));
            s.push(jeq(X32_SYSCALL_BIT | X32_IOCTL, To::At(Ioctl), To::Next));
            s.push(jeq(X32_SYSCALL_BIT | n.ioctl, To::At(Ioctl), To::At(Allow)));
        }
        // The `arch` is still in the accumulator.
        let (compat, compat_ioctl) = arch.compat();
        s.push(Step::Mark(Compat));
        s.push(jeq(compat, To::Next, To::At(Kill)));
        s.push(Step::Load(OFFSET_NR));
        s.push(jeq(compat_ioctl, To::At(Ioctl), To::At(Allow)));
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

/// The instructions of the filter for `arch` and `rules`.
fn program(arch: Arch, rules: Rules) -> Vec<Insn> {
    assemble(&steps(arch, rules))
}

/// The program as bubblewrap reads it from its descriptor: each instruction's
/// 8 bytes of `struct sock_filter`, little endian (both architectures are).
fn to_bytes(program: &[Insn]) -> Vec<u8> {
    let mut out = Vec::with_capacity(program.len() * 8);
    for insn in program {
        out.extend_from_slice(&insn.code.to_le_bytes());
        out.push(insn.jt);
        out.push(insn.jf);
        out.extend_from_slice(&insn.k.to_le_bytes());
    }
    out
}

/// PURE. The exact bytes of the filter for `arch` with `rules`: a whole
/// number of 8-byte `struct sock_filter` instructions, the program the
/// launcher hands to bubblewrap on a host of that architecture, and the
/// program as the kernel then holds it for the jail. The same on any host.
pub fn filter(arch: Arch, rules: Rules) -> Vec<u8> {
    to_bytes(&program(arch, rules))
}

/// The bytes of this build's filter with `rules` ([`filter`] for
/// [`Arch::native`]), `None` where this module has no numbers for the
/// architecture the build runs as.
pub fn native_filter(rules: Rules) -> Option<Vec<u8>> {
    Some(filter(Arch::native()?, rules))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the program answered.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Verdict {
        Allow,
        Errno(u32),
        Kill,
    }

    /// One call as the kernel describes it to a filter.
    struct Call {
        arch: u32,
        nr: u32,
        args: [u64; 6],
    }

    impl Call {
        fn new(arch: Arch, nr: u32, args: &[u64]) -> Call {
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
    fn run(program: &[Insn], call: &Call) -> Verdict {
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

    /// A call one of these architectures' kernels makes with another ABI's
    /// numbers: the i386 one (`int 0x80`) and x32 on x86_64, the 32-bit arm
    /// one on aarch64.
    fn foreign_call(arch: Arch, nr: u32, args: &[u64]) -> Call {
        let mut call = Call::new(arch, nr, args);
        call.arch = arch.compat().0;
        call
    }

    /// The identified jail ends a call made with another ABI's numbers: on
    /// x86_64 the i386 one and on aarch64 the 32-bit arm one name other calls
    /// by the same numbers, and so does x32. Each filter also ends a call of
    /// an architecture its kernel has no ABI for. The number a tracer writes
    /// over a skipped call is not one of these.
    ///
    /// FAILS ON REVERT: drop the architecture check (i386's `ioctl` passes),
    /// or the x32 check.
    #[test]
    fn the_identified_filter_ends_a_call_of_another_abi() {
        for (arch, foreign) in [
            (Arch::X86_64, AUDIT_ARCH_I386),
            (Arch::X86_64, AUDIT_ARCH_AARCH64),
            (Arch::Aarch64, AUDIT_ARCH_ARM),
            (Arch::Aarch64, AUDIT_ARCH_X86_64),
        ] {
            for nr in [0, COMPAT_IOCTL, 120, arch.numbers().ioctl] {
                let call = Call {
                    arch: foreign,
                    nr,
                    args: [0, u64::from(TIOCSTI), 0, 0, 0, 0],
                };
                assert_eq!(
                    run(&program(arch, Rules::Identified), &call),
                    Verdict::Kill,
                    "{arch:?} {foreign:#x} {nr}"
                );
            }
        }
        let x86 = Arch::X86_64;
        for nr in [
            X32_SYSCALL_BIT,
            X32_SYSCALL_BIT | 16,
            X32_SYSCALL_BIT | 272,
            X32_SYSCALL_BIT | X32_IOCTL,
        ] {
            let call = Call::new(x86, nr, &[u64::from(CLONE_NEWUSER), u64::from(TIOCSTI)]);
            assert_eq!(
                run(&program(x86, Rules::Identified), &call),
                Verdict::Kill,
                "{nr:#x}"
            );
        }
        // An architecture neither kernel runs a program of: no filter here
        // has its numbers.
        for rules in [Rules::Identified, Rules::Terminal] {
            for (arch, foreign) in [
                (Arch::X86_64, AUDIT_ARCH_AARCH64),
                (Arch::X86_64, AUDIT_ARCH_ARM),
                (Arch::Aarch64, AUDIT_ARCH_X86_64),
                (Arch::Aarch64, AUDIT_ARCH_I386),
                (Arch::Aarch64, 0),
            ] {
                let call = Call {
                    arch: foreign,
                    nr: 0,
                    args: [0; 6],
                };
                assert_eq!(
                    run(&program(arch, rules), &call),
                    Verdict::Kill,
                    "{rules:?} {arch:?} {foreign:#x}"
                );
            }
            let skipped = Call::new(x86, SKIPPED_CALL, &[]);
            assert_eq!(run(&program(x86, rules), &skipped), Verdict::Allow);
        }
    }

    /// The plain jail's rule holds on every ABI its kernel runs, and nothing
    /// else of a 32-bit program is touched: on x86_64 an i386 or x32
    /// `ioctl` with either terminal command is refused (x32's by its own
    /// number and by 16, which a kernel before 5.4 ran as the native one), on
    /// aarch64 a 32-bit arm one; their other calls, user namespaces
    /// included, are let through, so a 32-bit program runs as it did before
    /// the filter.
    ///
    /// FAILS ON REVERT: KILL another ABI in the terminal filter (i386's
    /// `getpid` is ended), or drop its `ioctl` check (i386's `TIOCSTI`
    /// passes), or drop either x32 number.
    #[test]
    fn the_terminal_filter_runs_32_bit_programs_under_the_keystroke_rule() {
        let refused = [u64::from(TIOCSTI), u64::from(TIOCLINUX), 0x1_0000_5412];
        for arch in ARCHES {
            let p = program(arch, Rules::Terminal);
            for command in refused {
                assert_eq!(
                    run(&p, &foreign_call(arch, COMPAT_IOCTL, &[0, command])),
                    Verdict::Errno(EPERM),
                    "{arch:?} 32-bit ioctl {command:#x}"
                );
            }
            // i386 and arm: 20 getpid, 11 execve, 120 clone, 310 / 337
            // unshare, 346 / 375 setns, 435 clone3; 16 is not their ioctl.
            for (nr, args) in [
                (COMPAT_IOCTL, vec![0, TCGETS]),
                (20, vec![]),
                (11, vec![]),
                (120, vec![u64::from(CLONE_NEWUSER) | SIGCHLD]),
                (310, vec![u64::from(CLONE_NEWUSER)]),
                (337, vec![u64::from(CLONE_NEWUSER)]),
                (346, vec![3, 0]),
                (375, vec![3, 0]),
                (435, vec![0, 88]),
                (16, vec![0, u64::from(TIOCSTI)]),
                (29, vec![0, u64::from(TIOCSTI)]),
                (SKIPPED_CALL, vec![]),
            ] {
                assert_eq!(
                    run(&p, &foreign_call(arch, nr, &args)),
                    Verdict::Allow,
                    "{arch:?} 32-bit call {nr}"
                );
            }
        }
        let x86 = program(Arch::X86_64, Rules::Terminal);
        for nr in [X32_SYSCALL_BIT | X32_IOCTL, X32_SYSCALL_BIT | 16] {
            for command in refused {
                assert_eq!(
                    run(&x86, &Call::new(Arch::X86_64, nr, &[0, command])),
                    Verdict::Errno(EPERM),
                    "x32 {nr:#x} {command:#x}"
                );
            }
            assert_eq!(
                run(&x86, &Call::new(Arch::X86_64, nr, &[0, TCGETS])),
                Verdict::Allow
            );
        }
        for nr in [
            X32_SYSCALL_BIT,
            X32_SYSCALL_BIT | 39,
            X32_SYSCALL_BIT | 272,
            X32_SYSCALL_BIT | 56,
        ] {
            let call = Call::new(
                Arch::X86_64,
                nr,
                &[u64::from(CLONE_NEWUSER), u64::from(TIOCSTI)],
            );
            assert_eq!(run(&x86, &call), Verdict::Allow, "x32 {nr:#x}");
        }
    }

    /// On x86_64 a native call of 514 is an `ioctl` to both filters: a kernel
    /// before 5.4 runs it as x32's `ioctl`, so `TIOCSTI` by 514 is refused
    /// like `TIOCSTI` by 16. Any other command by 514 is let through (a newer
    /// kernel answers it `ENOSYS`).
    ///
    /// FAILS ON REVERT: drop the 514 check (`TIOCSTI` by 514 passes).
    #[test]
    fn call_514_is_an_ioctl_to_both_filters_on_x86_64() {
        for rules in [Rules::Identified, Rules::Terminal] {
            let p = program(Arch::X86_64, rules);
            for command in [u64::from(TIOCSTI), u64::from(TIOCLINUX), 0x1_0000_5412] {
                assert_eq!(
                    run(&p, &Call::new(Arch::X86_64, X32_IOCTL, &[0, command])),
                    Verdict::Errno(EPERM),
                    "{rules:?} {command:#x}"
                );
            }
            assert_eq!(
                run(&p, &Call::new(Arch::X86_64, X32_IOCTL, &[0, TCGETS])),
                Verdict::Allow,
                "{rules:?}"
            );
        }
    }

    /// The terminal rules, which every jail gets, plain ones included: of
    /// the native calls only the two terminal commands are refused. A plain
    /// jail keeps what it could do before, user namespaces included (the
    /// test above holds the 32-bit ABIs to the same).
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
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The four programs, byte for byte, as [`filter`] gives them: what
    /// bubblewrap reads. Any change to the program shows here first, and the
    /// tests above say whether it still does what it says. These bytes are
    /// the same as when the builder lived in the `innerwarden` binary.
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
            let bytes = filter(arch, rules);
            assert_eq!(bytes, to_bytes(&program(arch, rules)));
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

    /// Every number the filters name, for both architectures, against the
    /// kernel's own tables, written out here and never computed from
    /// [`Arch::numbers`]: `arch/x86/entry/syscalls/syscall_64.tbl` (x86_64
    /// and x32), `include/uapi/asm-generic/unistd.h` (aarch64),
    /// `arch/x86/entry/syscalls/syscall_32.tbl` (i386) and
    /// `arch/arm/tools/syscall.tbl` (arm), and `include/uapi/linux/audit.h`
    /// with `include/uapi/linux/elf-em.h` for the `arch` values. CI runs the
    /// filter on a real kernel of each architecture (the Linux build job on
    /// x86_64, the arm64 job on aarch64: the child test below and the
    /// libc check); this test holds the numbers on every host, macOS and
    /// Windows included, where no kernel runs them, and for the architecture
    /// a host is not.
    ///
    /// FAILS ON REVERT: change any number in [`Arch::numbers`] (aarch64's
    /// `clone` to 120, its arm32 number, say), or either `arch` value.
    #[test]
    fn the_numbers_are_the_kernels_own_tables() {
        let x86 = Arch::X86_64.numbers();
        assert_eq!(
            (x86.clone, x86.unshare, x86.setns, x86.clone3, x86.ioctl),
            (56, 272, 308, 435, 16),
            "syscall_64.tbl"
        );
        let a64 = Arch::Aarch64.numbers();
        assert_eq!(
            (a64.clone, a64.unshare, a64.setns, a64.clone3, a64.ioctl),
            (220, 97, 268, 435, 29),
            "asm-generic/unistd.h"
        );
        assert_eq!((X32_SYSCALL_BIT, X32_IOCTL), (0x4000_0000, 514), "x32");
        assert_eq!(Arch::X86_64.compat(), (0x4000_0003, 54), "syscall_32.tbl");
        assert_eq!(Arch::Aarch64.compat(), (0x4000_0028, 54), "arm syscall.tbl");
        assert_eq!(
            Arch::X86_64.audit(),
            0xC000_003E,
            "EM_X86_64 62, 64-bit, LE"
        );
        assert_eq!(
            Arch::Aarch64.audit(),
            0xC000_00B7,
            "EM_AARCH64 183, 64-bit, LE"
        );
        assert_eq!(
            (CLONE_NEWUSER, TIOCSTI, TIOCLINUX, EPERM, ENOSYS),
            (0x1000_0000, 0x5412, 0x541C, 1, 38)
        );
    }

    /// A kernel's machine name names one of the two architectures or none:
    /// a 32-bit kernel, or another architecture, has no filter here.
    ///
    /// FAILS ON REVERT: read `arm64` as none (what macOS and some tools
    /// print for aarch64), or take a 32-bit machine as one of the two.
    #[test]
    fn a_machine_name_is_one_of_the_two_architectures_or_none() {
        for (machine, arch) in [
            ("x86_64", Some(Arch::X86_64)),
            ("x86_64\n", Some(Arch::X86_64)),
            ("aarch64", Some(Arch::Aarch64)),
            ("arm64", Some(Arch::Aarch64)),
            ("i686", None),
            ("i386", None),
            ("armv7l", None),
            ("aarch64_be", None),
            ("riscv64", None),
            ("x86-64", None),
            ("", None),
        ] {
            assert_eq!(Arch::from_machine(machine), arch, "{machine:?}");
        }
    }

    /// On Linux the host's architecture is what `uname -m` prints, and a
    /// build that is not emulated runs as it.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_host_is_the_kernels_own_machine() {
        let printed = std::process::Command::new("uname")
            .arg("-m")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("uname -m");
        let machine = String::from_utf8_lossy(&printed.stdout);
        assert_eq!(Arch::host(), Arch::from_machine(&machine), "{machine:?}");
        assert!(Arch::host().is_some(), "a Linux host this filter knows");
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

    /// The variable that tells a re-run of this test binary which child it
    /// is ([`child_side`]).
    #[cfg(target_os = "linux")]
    const CHILD_VAR: &str = "IW_SECCOMP_FILTER_CHILD";

    /// The value of [`CHILD_VAR`] for a child under `rules`, or under no
    /// filter (the control).
    #[cfg(target_os = "linux")]
    fn child_side(rules: Option<Rules>) -> &'static str {
        match rules {
            Some(Rules::Identified) => "identified",
            Some(Rules::Terminal) => "terminal",
            None => "control",
        }
    }

    /// The answers of one child, as `name=value` lines: `0` for a call that
    /// succeeded, the errno for one that failed. `rules`: the filter it
    /// installs first, if any.
    #[cfg(target_os = "linux")]
    fn child_answers(rules: Option<Rules>) -> Vec<String> {
        use std::ffi::CStr;

        let errno = || std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        let answer = |rc: libc::c_long| if rc == -1 { errno() } else { 0 };
        let mut out = Vec::new();
        if let Some(rules) = rules {
            let bytes = native_filter(rules).expect("a filter for this build");
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
        // rejects. The raw `clone` has no stack of its own, so a child it
        // makes goes on as a copy of this process (as after `fork`) and only
        // calls `_exit`. The new user namespace goes last: where it is not
        // refused, nothing after it runs in it.
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
            let flags = libc::c_long::from(libc::CLONE_NEWUSER | libc::SIGCHLD);
            let pid = libc::syscall(libc::SYS_clone, flags, 0usize, 0usize, 0usize, 0usize);
            if pid == 0 {
                libc::_exit(0);
            }
            out.push(format!("clone_newuser={}", answer(pid)));
            if pid > 0 {
                let mut status = 0;
                libc::waitpid(pid as libc::pid_t, &mut status, 0);
            }
            out.push(format!(
                "unshare_newuser={}",
                answer(libc::c_long::from(libc::unshare(libc::CLONE_NEWUSER)))
            ));
        }
        out
    }

    /// Whether this test process already runs under a seccomp filter (a
    /// container's, an emulator's): the control child then answers what
    /// that filter decides, not what the kernel does.
    #[cfg(target_os = "linux")]
    fn under_an_outer_filter() -> bool {
        std::fs::read_to_string("/proc/self/status").is_ok_and(|status| {
            status.lines().any(|l| {
                l.split_once(':')
                    .is_some_and(|(k, v)| k == "Seccomp" && v.trim() == "2")
            })
        })
    }

    /// Run this test binary again as a child process (never a fork of the
    /// test harness) that installs the filter with `rules` first, or none.
    /// Every child runs in [`a_child_under_the_filter_is_refused_what_it_says`],
    /// which answers as the child when [`CHILD_VAR`] is set.
    #[cfg(target_os = "linux")]
    fn answers_of_a_child(rules: Option<Rules>) -> std::collections::BTreeMap<String, i32> {
        let name = module_path!()
            .split_once("::")
            .map(|(_, rest)| format!("{rest}::a_child_under_the_filter_is_refused_what_it_says"))
            .unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([name.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD_VAR, child_side(rules))
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
    /// `no_new_privs` and the identified filter, a new user namespace (by
    /// `unshare` and by a raw `clone`) and joining one are refused with
    /// EPERM, raw `clone3` answers ENOSYS, threads and child processes still
    /// start (glibc falls back to `clone`), and TIOCSTI on the child's own
    /// controlling terminal is refused, high bits or not. The same child
    /// without the filter shows the kernel's own answers, so each refusal
    /// above is the filter's.
    ///
    /// Where this test already runs under a filter of its own (a default
    /// Docker container refuses `setns`), the control child answers that
    /// filter, so the comparison with the kernel's answer for `setns` is
    /// skipped and said; the terminal one, which no such filter refuses,
    /// still holds.
    ///
    /// FAILS ON REVERT: answer `clone3` with EPERM (the thread and the
    /// command fail on glibc 2.34 and later), compare all 64 bits of the
    /// `ioctl` command (`tiocsti_high` reaches the kernel), drop the `JSET`,
    /// name the wrong `clone` number (`clone_newuser` is made).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_child_under_the_filter_is_refused_what_it_says() {
        if let Ok(side) = std::env::var(CHILD_VAR) {
            let rules = [Some(Rules::Identified), Some(Rules::Terminal), None]
                .into_iter()
                .find(|rules| child_side(*rules) == side)
                .expect("a child this test knows");
            for line in child_answers(rules) {
                println!("answer {line}");
            }
            return;
        }
        let eperm = libc::EPERM;
        let filtered = answers_of_a_child(Some(Rules::Identified));
        let control = answers_of_a_child(None);
        eprintln!("filtered: {filtered:?}\ncontrol: {control:?}");
        assert_eq!(filtered["unshare_newuser"], eperm, "{filtered:?}");
        assert_eq!(filtered["clone_newuser"], eperm, "{filtered:?}");
        assert_eq!(filtered["setns"], eperm, "{filtered:?}");
        assert_eq!(filtered["clone3"], libc::ENOSYS, "{filtered:?}");
        assert_eq!(filtered["thread"], 0, "a thread starts: {filtered:?}");
        assert_eq!(filtered["command"], 0, "a command starts: {filtered:?}");
        assert_eq!(filtered["tiocsti"], eperm, "{filtered:?}");
        assert_eq!(filtered["tiocsti_high"], eperm, "{filtered:?}");
        // Without the filter the kernel answers otherwise: a bad descriptor,
        // and TIOCSTI taken (or EIO where legacy TIOCSTI is off).
        if under_an_outer_filter() {
            eprintln!(
                "this test runs under a seccomp filter of its own: the control's setns answer ({}) is that filter's, not compared with the kernel's",
                control["setns"]
            );
        } else {
            assert_eq!(control["setns"], libc::EBADF, "{control:?}");
        }
        for key in ["tiocsti", "tiocsti_high"] {
            assert!(
                control[key] == 0 || control[key] == libc::EIO,
                "{key} without the filter: {control:?}"
            );
        }
        assert_eq!((control["thread"], control["command"]), (0, 0));
    }

    /// The terminal filter, which every jail gets (a plain one included), on
    /// a real kernel in a child process: TIOCSTI on the child's own
    /// controlling terminal is refused, high bits or not, and nothing the
    /// identified filter adds is: a new user namespace (by `unshare` and by a
    /// raw `clone`), joining one and raw `clone3` answer exactly what the
    /// same child answers without a filter, and threads and child processes
    /// start. So the kernel loads the terminal program and runs it as the
    /// interpreter does, and a plain jail keeps what it could do before.
    ///
    /// FAILS ON REVERT: give the terminal rules the identified program
    /// (`setns` and `clone_newuser` are refused by the filter), drop the
    /// terminal program's `ioctl` check (`tiocsti` reaches the kernel), or
    /// compare all 64 bits of the command (`tiocsti_high` does).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_child_under_the_terminal_filter_is_refused_only_keystrokes() {
        let eperm = libc::EPERM;
        let terminal = answers_of_a_child(Some(Rules::Terminal));
        let control = answers_of_a_child(None);
        eprintln!("terminal: {terminal:?}\ncontrol: {control:?}");
        assert_eq!(terminal["tiocsti"], eperm, "{terminal:?}");
        assert_eq!(terminal["tiocsti_high"], eperm, "{terminal:?}");
        for key in ["unshare_newuser", "clone_newuser", "setns", "clone3"] {
            assert_eq!(
                terminal[key], control[key],
                "{key}: the terminal filter answers what the kernel does"
            );
        }
        assert_eq!(terminal["thread"], 0, "a thread starts: {terminal:?}");
        assert_eq!(terminal["command"], 0, "a command starts: {terminal:?}");
        for key in ["tiocsti", "tiocsti_high"] {
            assert!(
                control[key] == 0 || control[key] == libc::EIO,
                "{key} without the filter: {control:?}"
            );
        }
    }

    // Each instruction is `code(2) jt jf k(4)`, little endian, one per line.
    const GOLDEN_X86_64_IDENTIFIED: &str = "
        2000000004000000
        150000113e0000c0
        2000000000000000
        15000c00ffffffff
        35000e0000000040
        15000c00b3010000
        15000a0034010000
        1500030010010000
        1500020038000000
        1500030010000000
        1500020502020000
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
        150000073e0000c0
        2000000000000000
        15000b00ffffffff
        3500020000000040
        1500060010000000
        1500050802020000
        1500040002020040
        1500030610000040
        1500000703000040
        2000000000000000
        1500000336000000
        2000000018000000
        1500020012540000
        150001001c540000
        060000000000ff7f
        0600000001000500
        0600000000000080";
    const GOLDEN_AARCH64_TERMINAL: &str = "
        2000000004000000
        15000002b70000c0
        2000000000000000
        150003061d000000
        1500000728000040
        2000000000000000
        1500000336000000
        2000000018000000
        1500020012540000
        150001001c540000
        060000000000ff7f
        0600000001000500
        0600000000000080";
}
