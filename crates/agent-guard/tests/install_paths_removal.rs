//! Removing any place the installers write is a removal of the guard.
//!
//! Read 2026-11-19 from Pro's `scripts/web-install.sh` and
//! `scripts/install.sh` and Community's `iw-guard-install.sh` and
//! `.deb`/`.rpm` (`packaging/nfpm.yaml`): every file and folder they write.
//! Measured on main the same day: `rm -rf /usr/local/lib/innerwarden/` was
//! allowed, and so were `rm` and `mv` of the run-time folder, the systemd
//! units, the sudo rules, the audit rule, the boot setting of the kernel
//! layer, the launchd jobs on macOS and the licence text of the packages.
//! Each is now refused as the guard's own binaries and configuration were
//! (`find -delete` of each was already refused).

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation
}

fn removals(path: &str) -> [String; 4] {
    [
        format!("rm -rf {path}"),
        format!("rm -r {path}"),
        format!("find {path} -delete"),
        format!("mv {path} /tmp/old"),
    ]
}

/// FAILS ON REVERT: drop `INNERWARDEN_INSTALL_PATHS` and `rm` and `mv` of
/// each are allowed again (the guard's helper script only from a home with
/// no guard wired in it, as the tests run).
#[test]
fn removing_a_place_only_the_installers_write_is_refused() {
    for path in [
        "/usr/local/lib/innerwarden",
        "/usr/local/lib/innerwarden/",
        "/usr/local/lib/innerwarden/agent_command_guard.sh",
        "/run/innerwarden",
        "/etc/systemd/system/innerwarden-agent.service",
        "/etc/systemd/system/innerwarden-sensor.service",
        "/etc/systemd/system/innerwarden-license-refresh.timer",
        "/etc/systemd/system/innerwarden-allowlist-apply.path",
        "/etc/systemd/system/multi-user.target.wants/innerwarden-agent.service",
        "/etc/sudoers.d/innerwarden",
        "/etc/sudoers.d/innerwarden-block-ip",
        "/etc/audit/rules.d/innerwarden-shell-audit.rules",
        "/etc/default/grub.d/99-innerwarden-lsm.cfg",
        "/Library/LaunchDaemons/com.innerwarden.sensor.plist",
        "/Library/LaunchDaemons/com.innerwarden.agent.plist",
        "/usr/share/doc/innerwarden",
    ] {
        for line in removals(path) {
            assert_eq!(verdict(&line), "deny", "{line}");
        }
    }
}

/// The places that were already the guard's own stay refused.
#[test]
fn removing_the_guards_binaries_and_configuration_is_still_refused() {
    for path in [
        "/usr/local/bin/innerwarden",
        "/usr/local/bin/innerwarden-sensor",
        "/usr/local/bin/innerwarden-agent",
        "/usr/local/bin/innerwarden-ctl",
        "/usr/local/bin/innerwarden-watchdog",
        "/usr/local/bin/innerwarden-supervisor",
        "/usr/local/bin/innerwarden-config-sign",
        "/usr/local/bin/innerwarden-dns-guard",
        "/etc/innerwarden",
        "/etc/innerwarden/agent.toml",
        "/var/lib/innerwarden",
        "/var/log/innerwarden",
        "/sys/fs/bpf/innerwarden",
        "/usr/local/etc/innerwarden",
        "/usr/local/var/lib/innerwarden",
        "/usr/local/var/log/innerwarden",
        "~/.local/bin/innerwarden",
        "~/.npm-global/bin/innerwarden",
        "~/.config/innerwarden",
        "/usr/bin/innerwarden",
        "~/.local/bin/iw",
        "~/.local/bin/iw-guard",
    ] {
        for line in removals(path) {
            assert_eq!(verdict(&line), "deny", "{line}");
        }
    }
}

/// The other side: reading those places, or removing a neighbour that only
/// shares the name, is ordinary work.
#[test]
fn reading_an_install_place_or_removing_a_namesake_is_allowed() {
    for line in [
        "cat /usr/share/doc/innerwarden/copyright",
        "ls /etc/systemd/system/innerwarden-agent.service",
        "systemctl cat innerwarden-agent",
        "ls /usr/local/lib/innerwarden/",
        "cp /etc/systemd/system/innerwarden-agent.service /tmp/x",
        "rm -rf /tmp/innerwarden-test",
        "rm -rf ~/innerwarden/target",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}
