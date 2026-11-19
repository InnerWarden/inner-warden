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
        "find ~/.ssh -delete",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
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
/// does not show: held for review at least.
#[test]
fn xargs_removing_from_unread_input_is_held_for_review() {
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
