//! A `cd` to a path the line spells out sets where a later removal by
//! glob is judged, and a recursive change of owner, group or mode at the
//! root, a system directory or a home is refused. Measured 2026-11-21 on
//! main 003699c (analyze_command, no working directory), each allowed:
//!
//! * `cd / && rm -rf *`, `X=/; cd $X && rm -rf *`, `cd /etc; rm -rf ./*`,
//!   the same in a subshell, under `sh -c` and after `pushd`;
//! * `chown -R nobody /` (directly and through a variable), `chgrp -R`,
//!   `chmod -R 000 /bin`; `chmod -R 777 /` was only held for review.
//!
//! A `cd` the text does not resolve (a relative folder with no working
//! directory, a substitution) or one inside a subshell that has closed
//! leaves the removal as it was. Nothing here is executed: every line is
//! only screened.

use innerwarden_agent_guard::mcp::analyze_command;
use innerwarden_agent_guard::rules::RuleEngine;

fn verdict(command: &str) -> String {
    analyze_command(command, Some(&RuleEngine::load_embedded())).recommendation
}

/// FAILS ON REVERT: call `destructive_rm_in_place` in mcp.rs only when a
/// working context is known and each of these is allowed.
#[test]
fn a_cd_the_line_spells_out_sets_where_a_glob_removal_runs() {
    for line in [
        "cd / && rm -rf *",
        "X=/; cd $X && rm -rf *",
        "cd /etc; rm -rf ./*",
        "cd / ; rm -rf .",
        "cd /usr && rm -rf -- *",
        "cd /home/dev && rm -rf *",
        "cd / || exit; rm -rf *",
        "(cd / && rm -rf *)",
        "sh -c \"cd / && rm -rf *\"",
        "sudo sh -c \"cd /etc && rm -rf *\"",
        "pushd / && rm -rf *",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// FAILS ON REVERT: take `recursive_owner_change_of_system` out of
/// mcp.rs and each of these is allowed (the `chmod -R 777` ones held).
#[test]
fn a_recursive_owner_or_mode_change_of_the_system_is_refused() {
    for line in [
        "chown -R nobody /",
        "X=/; chown -R nobody $X",
        "chmod -R 777 /",
        "chown -R root:root /etc",
        "chgrp -R users /usr",
        "chmod -R 000 /bin",
        "chown -R nobody /sbin",
        "chown -R nobody /lib64",
        "chmod -R 777 /var",
        "chown -R nobody /boot",
        "chown -R nobody ~",
        "chown -R nobody /home/dev",
        "chown -R nobody:nobody $HOME",
        "sudo chown -R nobody /",
        "chmod -R a+w /etc/",
        "chown --recursive nobody /",
        "chmod -Rf 777 /usr",
        "cd / && chown -R nobody .",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// Project folders, folders the text does not resolve, and a `cd` whose
/// subshell has closed keep their verdict.
#[test]
fn project_folders_and_unresolved_cds_stay_allowed() {
    for line in [
        "cd build && rm -rf *",
        "cd \"$(mktemp -d)\" && rm -rf *",
        "cd target; rm -rf debug/*",
        "(cd /) ; rm -rf *",
        "cd /; cd tmp; rm -rf *",
        "cd /tmp && rm -rf *",
        "cd /x || exit 1 && rm -rf *",
        "cd /home/dev/app && rm -rf node_modules/*",
        "cd /srv/app/build && rm -rf *",
        "chown -R dev:dev ./build",
        "chown -R $(whoami) ~/project",
        "sudo chown -R dev:dev /home/dev/app",
        "chmod -R u+w target",
        "chmod -R 755 ./scripts",
        "chmod 644 /etc/hosts.bak",
        "sudo chown -R www-data /var/www/html",
        "chmod -R g+w /srv/app",
        "chown -R dev ~/.cache/pip",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// `find` handing every file of the root, a system directory or a home to
/// `chown`, `chgrp` or `chmod` (`-exec`, `-execdir`, `-ok`) is the same change
/// as `chown -R` (BI NEW-20261121-find-exec-chown-root-allowed). Measured
/// 2026-11-21 on the branch of #368, each allowed.
///
/// FAILS ON REVERT: take the `find` branch out of
/// `recursive_owner_change_of_system` (threats.rs) and each is allowed.
#[test]
fn find_handing_the_whole_system_to_an_owner_change_is_refused() {
    for line in [
        "find / -exec chown nobody {} +",
        "find / -execdir chown nobody {} \\;",
        "find / -ok chgrp nobody {} \\;",
        "find ~ -exec chown nobody {} +",
        "find /etc -type f -exec chown nobody {} \\;",
        "sudo find /home -exec chgrp staff {} +",
        "find / -exec sudo chown nobody {} +",
        "find / -name '*' -exec chown nobody {} +",
        "find /usr -okdir chown nobody {} \\;",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// A `find` that picks some files out, keeps to its starting point, or
/// starts in a project folder keeps its verdict.
#[test]
fn find_with_a_selection_or_in_a_project_stays_allowed() {
    for line in [
        "find build -exec chown me {} +",
        "find . -exec chmod 644 {} +",
        "find /tmp/x -exec chown me {} +",
        "find / -maxdepth 0 -exec chown nobody {} +",
        "find /srv/app -exec chgrp www-data {} +",
        "find /etc/nginx -name nginx.conf -exec chmod 644 {} +",
        "find . -name '*.sh' -exec sh -c 'chmod +x \"$1\"' sh {} \\;",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// Second review of this change (2026-11-21): global options before the
/// starting point, a starting point the line does not spell out, a test
/// that is not a literal name or path (an owner, a glob, a regex, a
/// negation, `-o`, `-prune`), and the program behind its launchers or in
/// a shell's `-c` line. Measured on the first version of this change,
/// before the fix: allowed, except the unread starting point (review).
/// `find / -user olduser -exec chown newuser {} +` was asserted allowed
/// above in the first version: an owner test leaves every file of that
/// owner in the whole system to the change.
#[test]
fn find_options_tests_and_launchers_do_not_free_a_whole_system_change() {
    for line in [
        "find -L / -exec chown nobody {} +",
        "find -H / -exec chown nobody {} +",
        "find -P / -exec chown nobody {} +",
        "find -O3 / -exec chown nobody {} +",
        "find / -user root -exec chown nobody {} +",
        "find / -user olduser -exec chown newuser {} +",
        "find / ! -name x -exec chown nobody {} +",
        "find / -not -name x -exec chown nobody {} +",
        "find / -regex '.*' -exec chown nobody {} +",
        "find / -name '?*' -exec chown nobody {} +",
        "find / -name zzz -o -exec chown nobody {} +",
        "find / -path /proc -prune -o -exec chown nobody {} +",
        "find / -exec nohup chown nobody {} +",
        "find / -exec timeout 9 chown nobody {} +",
        "find / -exec sudo -u root chown nobody {} +",
        "find / -exec sh -c 'chown nobody \"$1\"' sh {} +",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// Final review of this change (2026-11-21): a starting point the line does
/// not spell out keeps main's verdict (review): build scripts change the
/// mode of their own output folder this way. One the line resolves to the
/// root is refused. `-nouser`, `-nogroup` and `-empty` take no argument,
/// so the action after them is read.
#[test]
fn an_unread_starting_point_is_not_refused_but_a_resolved_root_is() {
    for line in [
        "find \"$OUT\" -name \"*.html\" -exec chmod 644 {} +",
        "find \"$BUILD\" -type f -exec chmod +x {} \\;",
        "find \"$1\" -type f -exec chmod 644 {} +",
    ] {
        assert_ne!(verdict(line), "deny", "{line}");
    }
    for line in [
        "X=/; find \"$X\" -exec chown nobody {} +",
        "X=/; find $X -type f -exec chown nobody {} +",
        "find / -nouser -exec chown nobody {} +",
        "find / -empty -exec chmod 777 {} +",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}
