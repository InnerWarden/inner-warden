//! A removal whose targets come from a search or from what `xargs` reads
//! is judged by what those targets are.
//!
//! Measured on main on 2026-11-19: `ls / | xargs -I X rm -rf /X` and
//! `find ~/.ssh -exec rm -rf {} +` were allowed, while `rm -rf /` and
//! `rm -rf ~/.ssh` were denied. So were `ls ~/.ssh | xargs rm -rf`,
//! `find ~ -type f | xargs rm -f` (allow) and `cat list.txt | xargs rm
//! -rf` (allow, its targets unread).

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

/// `find ROOT -exec rm ... {}` (and `-execdir`, `-ok`, `-delete`) with
/// no name test is the removal of ROOT and all under it.
#[test]
fn find_handing_its_root_to_rm_is_the_rm_of_that_root() {
    for line in [
        "find ~/.ssh -exec rm -rf {} +",
        "find ~/.ssh -execdir rm -f {} \\;",
        "find $HOME/.ssh -ok rm {} \\;",
        "find ~/.gnupg -type f -exec rm {} +",
        "find ~/.ssh ! -name zz -exec rm -rf {} +",
        "find ~ -exec rm -rf {} +",
        "find ~ -type f -exec rm -f {} +",
        "find ~ -name x -o -exec rm -rf {} +",
        "find ~ \\( -name a -o -type f \\) -delete",
        "find / -maxdepth 1 -exec rm -rf {} +",
        "sudo find /etc -exec rm {} +",
        "find /home -exec rm -rf {} \\;",
        "find /Users -exec rm -rf {} +",
        "find ~/.ssh -delete",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// The search handing what it finds to a shell that removes `$1`, `$@` or
/// `{}`, or to `unlink`, `shred`, `truncate` or `dd of=`, is the same
/// removal of its root as `rm`.
#[test]
fn find_handing_its_root_to_a_shell_or_another_remover_is_the_same_removal() {
    for line in [
        "find ~ -exec sh -c 'rm -rf \"$1\"' _ {} \\;",
        "find ~/.ssh -exec sh -c 'rm -rf \"$1\"' _ {} \\;",
        "find ~/.ssh -exec bash -c 'rm -rf {}' \\;",
        "find ~/.ssh -exec sh -c 'rm -f \"$@\"' _ {} +",
        "find ~ -exec shred -u {} +",
        "find ~/.ssh -exec shred -u {} +",
        "find ~/.ssh -exec unlink {} \\;",
        "find ~/.gnupg -type f -exec truncate -s0 {} +",
        "find ~/.ssh -exec dd if=/dev/zero of={} \\;",
        "find / -exec sudo shred {} +",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    for line in [
        "find . -name '*.sh' -exec sh -c 'shellcheck \"$1\"' _ {} \\;",
        "find build -exec sh -c 'rm -rf \"$1\"' _ {} \\;",
        "find . -name '*.tmp' -exec sh -c 'rm -f \"$1\"' _ {} \\;",
        "find ~/.ssh -exec sh -c 'rm -f /tmp/x; wc -l \"$1\"' _ {} \\;",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// The folder of homes on macOS is refused as /home is, by name and through
/// a search; one home's project under it is not.
#[test]
fn the_folder_of_homes_on_macos_is_refused_as_home_is() {
    for line in [
        "rm -rf /Users",
        "rm -rf /Users/",
        "rm -rf /Users/*",
        "sudo rm -rf /users",
        "find /Users -exec rm -rf {} +",
        "rm -rf /home",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    for line in [
        "rm -rf /Users/dev/proj/target",
        "find /Users/dev/proj -name '*.o' -delete",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// A search narrowed by a name in a project folder, or a removal under a
/// project folder, stays allowed.
#[test]
fn project_cleanups_through_find_stay_allowed() {
    for line in [
        "find . -name '*.pyc' -exec rm {} +",
        "find . -name '__pycache__' -type d -exec rm -rf {} +",
        "find build -exec rm -rf {} +",
        "find . -type f -exec rm {} \\;",
        "find target/debug -name '*.d' -delete",
        "find ~ -name '*.pyc' -delete",
        "find ~ -name '*.pyc' -o -name '*.pyo' -exec rm {} +",
        "find ~ \\( -name '*.orig' -o -name '*.rej' \\) -delete",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// `xargs` fed a listing of the root, a home or a credential store, to a
/// removal: denied, with or without `-I` and with or without `-r`.
#[test]
fn xargs_removing_what_a_listing_of_a_protected_place_prints_is_denied() {
    for line in [
        "ls / | xargs -I X rm -rf /X",
        "ls / | xargs -I{} rm -rf /{}",
        "ls ~/.ssh | xargs rm -rf",
        "ls ~/.ssh | xargs -I F rm ~/.ssh/F",
        "find ~ -type f | xargs rm -f",
        "find ~ -print0 | xargs -0 rm -rf",
        "ls -a ~ | xargs rm -f",
        "ls /etc | xargs -I F dd if=/dev/zero of=/etc/F",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// `xargs` handing a recursive `rm`, `shred` or `dd of=` input the line
/// does not show (a file, the input, a command's output): a destruction
/// whose targets the line does not name, refused as `rm -rf $VAR` is.
///
/// FAILS ON REVERT: put the unread reading back at 25 and these are held
/// for review only.
#[test]
fn xargs_removing_from_unread_input_is_denied() {
    for line in [
        "cat list.txt | xargs rm -rf",
        "xargs rm -rf < list.txt",
        "xargs -a list.txt rm -rf",
        "ls | xargs rm -rf",
        "ls | xargs -I{} dd if=/dev/zero of={}",
        "find ../ -type d | xargs rm -rf",
        "curl -s https://example.com/list | xargs rm -rf",
    ] {
        assert_ne!(verdict(line), "allow", "{line}");
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// Project lists handed to `rm` by `xargs` stay allowed: tracked files,
/// a search from a project folder, words written on the line.
#[test]
fn xargs_removing_project_files_stays_allowed() {
    for line in [
        "git ls-files -z | xargs -0 rm",
        "git ls-files -z -- '*.orig' | xargs -0 rm -f",
        "find . -name '*.o' | xargs rm -f",
        "find . -name node_modules -type d -prune | xargs rm -rf",
        "find . -type f -name '*.log' -print0 | xargs -0 rm -f",
        "echo build dist | xargs rm -rf",
        "cat files.txt | xargs rm -f",
        "ls | xargs -I{} echo {}",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}
