//! What a command means depends on where it runs, and the agent hook knows
//! where: the directory in its payload.
//!
//! Two questions the text alone cannot answer:
//!
//! - Does `rm -rf *` empty a build folder or the home? From the home or from
//!   `/` it is a wipe; anywhere else it keeps the verdict it has without a
//!   directory. The home named outright (`rm -rf ~`, `rm -rf "$HOME"`,
//!   `rm -rf /home/<user>`) is a wipe wherever it runs.
//! - Is `cat .env` the project's own file? A `.env`-class file inside the
//!   project (the repository the directory belongs to, so `cat ../.env` from
//!   a subdirectory of the same repository counts) stays an ordinary
//!   `review`. One outside it blocks the agent.
//!
//! Every dangerous case asserts the agent is blocked; every everyday case
//! asserts it is NOT, by deny or by a floor signal.

use innerwarden_agent_guard::mcp::{
    analyze_command, analyze_command_in, blocks_for_agent, project_root_of, CommandAnalysis,
    WorkingContext,
};

const HOME: &str = "/home/dev";

fn place(cwd: &str) -> WorkingContext {
    WorkingContext {
        cwd: cwd.to_string(),
        home: Some(HOME.to_string()),
        project_root: cwd.to_string(),
        related_roots: Vec::new(),
        enclosing_dirs: Vec::new(),
    }
}

fn in_place(command: &str, context: &WorkingContext) -> CommandAnalysis {
    analyze_command_in(command, None, Some(context))
}

fn signal_names(analysis: &CommandAnalysis) -> Vec<&str> {
    analysis.signals.iter().map(|s| s.signal.as_str()).collect()
}

/// FAILS ON REVERT (home wipe): each removed the whole home and scored 0,
/// because only `/`, `/*` and the top-level system directories were a wipe.
/// The home itself, or everything in it, is denied wherever it runs.
#[test]
fn removing_the_home_itself_is_denied_wherever_it_runs() {
    let wipes = [
        "rm -rf ~",
        "rm -rf ~/",
        "rm -rf ~/*",
        "rm -rf ~/.*",
        "rm -rf ~/..",
        "rm -rf ~bob",
        "rm -rf ~bob/",
        "rm -rf $HOME",
        "rm -rf ${HOME}",
        "rm -rf \"$HOME\"",
        "rm -rf \"${HOME}\"",
        "rm -rf $HOME/",
        "rm -rf $HOME/*",
        "rm -rf /home/bob",
        "rm -rf /home/bob/",
        "rm -rf /home/bob/*",
        "rm -rf /home/bob/proj/..",
        "rm -rf /Users/bob",
        "rm -rf /root",
        "rm -fr ~",
        "rm --recursive --force ~",
        "sudo rm -rf /home/bob",
        "cd /tmp && rm -rf ~",
        "echo \"$(rm -rf ~)\"",
        // A last component that is only a glob is everything in the home.
        "rm -rf ~/**",
        "rm -rf ~/.?*",
        "rm -rf ~/[!.]*",
        "rm -rf ~/{*,.*}",
        "rm -rf \"$HOME\"/*",
        "rm -rf /home/bob/.[!.]*",
        // A home expansion with an operator is the home, or unknown.
        "rm -rf \"${HOME%/}\"",
        "rm -rf ${HOME%/}/*",
        "rm -rf \"${HOME:?}\"",
        "rm -rf \"${HOME:-/tmp/x}\"",
        // The same wipe behind a rewrite the shell undoes.
        "${x:-rm} -rf ~",
        "r''m -rf ~",
        "rm -rf ${x:-~}",
    ];
    for command in wipes {
        let analysis = analyze_command(command, None);
        assert_eq!(analysis.recommendation, "deny", "{command}: {analysis:?}");
        assert!(
            signal_names(&analysis).contains(&"destructive_command"),
            "{command}: {analysis:?}"
        );
        let analysis = in_place(command, &place("/home/dev/proj"));
        assert_eq!(analysis.recommendation, "deny", "{command} (in a project)");
    }
    // A command word printed by a substitution is denied as code the shell
    // builds and runs, whatever it removes.
    for command in ["$(echo rm) -rf ~", "`echo rm` -rf ~"] {
        assert_eq!(
            analyze_command(command, None).recommendation,
            "deny",
            "{command}"
        );
    }
}

/// Everyday cleanups under a home are scoped work and keep their verdict,
/// with or without a directory, and from the home itself too.
#[test]
fn cleaning_up_under_a_home_is_never_blocked() {
    let cleanups = [
        "rm -rf ./build",
        "rm -rf build",
        "rm -rf ~/.cache/x",
        "rm -rf ~/.cache/build",
        "rm -rf \"$HOME/.cache/x\"",
        "rm -rf $HOME/x",
        "rm -rf ${HOME}/.cache/x",
        "rm -rf /home/u/proj/build",
        "rm -rf /home/dev/proj/target",
        "rm -rf ~bob/tmp",
        "cd build && rm -rf ./*",
        "cd build && rm -rf *",
        "rm -f ~/notes.txt",
        "rm -r ~/scratch",
        "rm -rf ~/.cache/*",
        "rm -rf ~/*.log",
        "rm -rf ~/build*",
        "rm -rf $HOME/.npm/_cacache",
        "rm -rf ~/.cache/x/.[!.]*",
        "(cd ~ && git pull); rm -rf ./build",
    ];
    for command in cleanups {
        let alone = analyze_command(command, None);
        assert!(
            !blocks_for_agent(&alone),
            "{command} must not be blocked: {alone:?}"
        );
        for cwd in [HOME, "/home/dev/proj", "/"] {
            let analysis = in_place(command, &place(cwd));
            assert!(
                !blocks_for_agent(&analysis),
                "{command} from {cwd} must not be blocked: {analysis:?}"
            );
        }
    }
}

/// FAILS ON REVERT (directory resolution): `*`, `.`, `./*` and `..` carry no
/// path of their own, so the text alone scores them 0. Run from the home or
/// from `/`, they remove the home or the whole filesystem.
#[test]
fn a_relative_wipe_from_the_home_or_the_root_is_denied() {
    for (cwd, command) in [
        (HOME, "rm -rf *"),
        (HOME, "rm -rf ./*"),
        (HOME, "rm -rf ."),
        (HOME, "rm -rf .*"),
        (HOME, "rm -rf .."),
        ("/home/dev/", "rm -rf *"),
        ("/", "rm -rf *"),
        ("/", "rm -rf ./*"),
        ("/", "rm -rf ."),
        ("/", "rm -rf .."),
        // A `cd` earlier in the same command moves where it runs.
        ("/home/dev/proj", "cd ~ && rm -rf *"),
        ("/home/dev/proj", "cd && rm -rf ./*"),
        ("/home/dev/proj", "cd $HOME; rm -rf ./*"),
        ("/home/dev/proj", "cd / && rm -rf *"),
        ("/home/dev/proj", "cd .. && rm -rf *"),
        ("/home/dev/proj", "rm -rf ../*"),
        ("/home/dev/proj", "D=/home/dev; rm -rf $D/*"),
        ("/srv/app", "rm -rf ~/*"),
        // Inside the subshell that moved there.
        ("/home/dev/proj", "(cd ~ && rm -rf *)"),
        ("/home/dev/proj", "(cd ~; rm -rf ./*)"),
        (HOME, "rm -rf ./.?*"),
    ] {
        let analysis = in_place(command, &place(cwd));
        assert_eq!(
            analysis.recommendation, "deny",
            "{command} from {cwd}: {analysis:?}"
        );
        assert!(blocks_for_agent(&analysis), "{command} from {cwd}");
    }
}

/// Anywhere other than the home or `/`, the same commands keep exactly the
/// verdict they get without a directory: no floor, no new signal.
#[test]
fn a_relative_wipe_elsewhere_keeps_its_verdict() {
    for cwd in [
        "/home/dev/proj",
        "/home/dev/proj/build",
        "/tmp/scratch",
        "/srv/app/dist",
    ] {
        for command in [
            "rm -rf *",
            "rm -rf ./*",
            "rm -rf .",
            "rm -rf ./build",
            "cd build && rm -rf ./*",
        ] {
            let with = in_place(command, &place(cwd));
            let without = analyze_command(command, None);
            assert_eq!(
                with.recommendation, without.recommendation,
                "{command} from {cwd}"
            );
            assert_eq!(with.risk_score, without.risk_score, "{command} from {cwd}");
            assert!(!blocks_for_agent(&with), "{command} from {cwd}");
        }
    }
    // FAILS ON REVERT (a subshell's `cd` leaked out): the `cd` ends with
    // the subshell, so the wipe after it runs where the command started.
    for command in [
        "(cd ~ && git pull); rm -rf ./*",
        "(cd / && ls) && rm -rf *",
        "x=$(cd ~; pwd); rm -rf ./*",
    ] {
        let with = in_place(command, &place("/home/dev/proj"));
        let without = analyze_command(command, None);
        assert_eq!(with.recommendation, without.recommendation, "{command}");
        assert!(!blocks_for_agent(&with), "{command}: {with:?}");
    }
    // A `cd` to a place the text does not name is not guessed at: the command
    // keeps the verdict it has without a directory.
    for command in [
        "cd \"$(mktemp -d)\" && rm -rf ./*",
        "cd - && rm -rf *",
        "cd $BUILD_DIR && rm -rf *",
    ] {
        let with = in_place(command, &place(HOME));
        let without = analyze_command(command, None);
        assert_eq!(with.recommendation, without.recommendation, "{command}");
        assert!(!blocks_for_agent(&with), "{command}");
    }
}

/// A repository on disk: `<tmp>/repo` (with `.git`) holding `pkg/`, and a
/// home elsewhere under `<tmp>/home`.
struct Layout {
    _dir: tempfile::TempDir,
    root: String,
    repo: String,
    home: String,
}

fn layout() -> Layout {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().to_string_lossy().into_owned();
    let repo = format!("{root}/repo");
    std::fs::create_dir_all(format!("{repo}/.git")).expect("git dir");
    std::fs::create_dir_all(format!("{repo}/pkg/api")).expect("pkg dir");
    std::fs::create_dir_all(format!("{root}/home")).expect("home dir");
    std::fs::create_dir_all(format!("{root}/plain/sub")).expect("plain dir");
    Layout {
        root: root.clone(),
        repo,
        home: format!("{root}/home"),
        _dir: dir,
    }
}

fn discovered(cwd: &str, home: &str) -> WorkingContext {
    WorkingContext::discover(cwd, Some(home)).expect("absolute cwd")
}

/// The project is the repository the directory belongs to, found by its
/// `.git` entry (a directory for a clone, a file for a worktree), so a
/// subdirectory of a monorepo belongs to the whole repository. With no
/// repository, the directory itself.
#[test]
fn the_project_is_the_repository_the_directory_belongs_to() {
    let at = layout();
    let pkg = format!("{}/pkg/api", at.repo);
    assert_eq!(
        project_root_of(std::path::Path::new(&pkg)),
        std::path::PathBuf::from(&at.repo)
    );
    assert_eq!(discovered(&pkg, &at.home).project_root, at.repo);

    // A worktree's `.git` is a file.
    let worktree = format!("{}/worktree", at.root);
    std::fs::create_dir_all(format!("{worktree}/src")).expect("worktree dir");
    std::fs::write(format!("{worktree}/.git"), "gitdir: /elsewhere\n").expect("git file");
    assert_eq!(
        discovered(&format!("{worktree}/src"), &at.home).project_root,
        worktree
    );

    let plain = format!("{}/plain/sub", at.root);
    assert_eq!(discovered(&plain, &at.home).project_root, plain);
    assert!(WorkingContext::discover("relative/dir", Some(&at.home)).is_none());
}

/// The project's own `.env`, from anywhere inside the same repository, stays
/// an ordinary review: never a block.
#[test]
fn reading_the_projects_own_env_is_never_blocked() {
    let at = layout();
    for (cwd, command) in [
        (at.repo.clone(), "cat .env".to_string()),
        (at.repo.clone(), "cat .env.local".to_string()),
        (at.repo.clone(), "grep API_URL .env".to_string()),
        (format!("{}/pkg", at.repo), "cat ../.env".to_string()),
        (format!("{}/pkg/api", at.repo), "cat ../../.env".to_string()),
        (format!("{}/pkg/api", at.repo), "cat .env".to_string()),
        (format!("{}/pkg", at.repo), format!("cat {}/.env", at.repo)),
        (format!("{}/pkg", at.repo), "cat $PWD/.env".to_string()),
        (format!("{}/pkg", at.repo), "cd .. && cat .env".to_string()),
        (at.repo.clone(), "cat pkg/api/.env".to_string()),
        (format!("{}/plain/sub", at.root), "cat .env".to_string()),
    ] {
        let analysis = in_place_at(&command, &discovered(&cwd, &at.home));
        assert!(
            !blocks_for_agent(&analysis),
            "{command} from {cwd} must not be blocked: {analysis:?}"
        );
        assert!(
            !signal_names(&analysis).contains(&"credential_read_outside_project"),
            "{command} from {cwd}: {analysis:?}"
        );
    }
}

fn in_place_at(command: &str, context: &WorkingContext) -> CommandAnalysis {
    analyze_command_in(command, None, Some(context))
}

/// FAILS ON REVERT (outside the project): a `.env`-class file in the home or
/// in another tree was an ordinary `review` the default hook let through. It
/// is still a review, and now one that blocks the agent.
#[test]
fn reading_a_secrets_file_outside_the_project_blocks_the_agent() {
    let at = layout();
    let pkg = format!("{}/pkg", at.repo);
    for command in [
        "cat ~/secret.env".to_string(),
        "cat $HOME/.env".to_string(),
        "cat ${HOME}/app/.env.production".to_string(),
        "cat /srv/other/.env".to_string(),
        "cat ../../.env".to_string(),
        "cd ~ && cat .env".to_string(),
        "cd /srv/other && cat .env".to_string(),
        format!("cat {}/plain/.env", at.root),
        "grep TOKEN ~/work/other/.env".to_string(),
        "python3 -c \"print(open('/srv/other/.env').read())\"".to_string(),
    ] {
        let analysis = in_place_at(&command, &discovered(&pkg, &at.home));
        assert!(
            blocks_for_agent(&analysis),
            "{command} must block the agent: {analysis:?}"
        );
        assert!(
            signal_names(&analysis).contains(&"credential_read_outside_project"),
            "{command}: {analysis:?}"
        );
    }
    // The block is the floor, not a deny: the verdict a person sees is the
    // same review it was.
    let analysis = in_place_at("cat ~/secret.env", &discovered(&pkg, &at.home));
    assert_eq!(analysis.recommendation, "review", "{analysis:?}");
    let alone = analyze_command("cat ~/secret.env", None);
    assert_eq!(alone.recommendation, "review");
    assert!(!blocks_for_agent(&alone), "without a directory: {alone:?}");
}

/// FAILS ON REVERT (everything outside from the home): a session started in
/// the home, or a hook run from `/` with no directory in its payload, says
/// nothing about which project is the work. Reads from there keep the verdict
/// they have without a directory, as before.
#[test]
fn a_read_from_the_home_or_the_root_keeps_its_verdict() {
    let at = layout();
    for (cwd, command) in [
        (at.home.clone(), "cat .env"),
        (at.home.clone(), "cat secret.env"),
        (at.home.clone(), "cat ~/.env"),
        (at.home.clone(), "cat myapp/.env"),
        ("/".to_string(), "cat .env"),
        ("/".to_string(), "cat srv/app/.env"),
    ] {
        let context = discovered(&cwd, &at.home);
        let with = in_place_at(command, &context);
        let without = analyze_command(command, None);
        assert_eq!(
            with.recommendation, without.recommendation,
            "{command} from {cwd}"
        );
        assert!(!blocks_for_agent(&with), "{command} from {cwd}: {with:?}");
        assert!(
            !signal_names(&with).contains(&"credential_read_outside_project"),
            "{command} from {cwd}"
        );
    }
}

/// FAILS ON REVERT (a project not under git ended at the directory): opened
/// in a subdirectory, its `.env` one level up is still its own. A sibling's,
/// the home's and one under another tree stay outside.
#[test]
fn a_project_not_under_git_keeps_its_env_above_the_directory() {
    let at = layout();
    let sub = format!("{}/plain/sub", at.root);
    for command in ["cat ../.env", "cp ../.env .env", "grep KEY ../.env.local"] {
        let analysis = in_place_at(command, &discovered(&sub, &at.home));
        assert!(!blocks_for_agent(&analysis), "{command}: {analysis:?}");
    }
    for command in [
        "cat ../other/.env".to_string(),
        "cat ~/.env".to_string(),
        format!("cat {}/.env", at.home),
        format!("cat {}/pkg/.env", at.repo),
    ] {
        let analysis = in_place_at(&command, &discovered(&sub, &at.home));
        assert!(blocks_for_agent(&analysis), "{command}: {analysis:?}");
    }
    // Inside a repository the root is the boundary: nothing above it counts.
    assert!(discovered(&format!("{}/pkg", at.repo), &at.home)
        .enclosing_dirs
        .is_empty());
}

/// FAILS ON REVERT (a worktree was its own island): a worktree or a
/// submodule has a `.git` FILE, and the checkout it belongs to is part of the
/// work. Copying the main checkout's `.env` into a worktree is setting it up.
/// A tree that is neither stays outside.
#[test]
fn a_worktree_or_submodule_reads_its_main_checkout() {
    let at = layout();
    std::fs::create_dir_all(format!("{}/.git/worktrees/wt", at.repo)).unwrap();
    std::fs::create_dir_all(format!("{}/.git/modules/sub", at.repo)).unwrap();
    std::fs::create_dir_all(format!("{}/.git/worktrees/outer", at.repo)).unwrap();
    let inner = format!("{}/.worktrees/wt", at.repo);
    let agent = format!("{}/.claude/worktrees/wt", at.repo);
    let submodule = format!("{}/libs/sub", at.repo);
    let outer = format!("{}/outer-wt", at.root);
    for (dir, gitdir) in [
        (&inner, format!("{}/.git/worktrees/wt", at.repo)),
        (&agent, format!("{}/.git/worktrees/wt", at.repo)),
        (&submodule, "../../.git/modules/sub".to_string()),
        (&outer, format!("{}/.git/worktrees/outer", at.repo)),
    ] {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(format!("{dir}/.git"), format!("gitdir: {gitdir}\n")).unwrap();
    }
    for (cwd, command) in [
        (inner.clone(), "cp ../../.env .".to_string()),
        (agent.clone(), "cat ../../../.env".to_string()),
        (submodule.clone(), "cat ../../.env".to_string()),
        (outer.clone(), format!("cp {}/.env .env", at.repo)),
        (outer.clone(), format!("cat {}/pkg/.env.local", at.repo)),
    ] {
        let analysis = in_place_at(&command, &discovered(&cwd, &at.home));
        assert!(
            !blocks_for_agent(&analysis),
            "{command} from {cwd} must not be blocked: {analysis:?}"
        );
    }
    let analysis = in_place_at(
        &format!("cat {}/plain/.env", at.root),
        &discovered(&outer, &at.home),
    );
    assert!(blocks_for_agent(&analysis), "{analysis:?}");
}

/// FAILS ON REVERT (spelling, not place): the project reached through a
/// symlink (`/tmp` for `/private/tmp`) is still the project.
#[cfg(unix)]
#[test]
fn the_project_reached_through_a_symlink_is_the_project() {
    let at = layout();
    std::fs::write(format!("{}/.env", at.repo), "X=1\n").unwrap();
    let link = format!("{}/link", at.root);
    std::os::unix::fs::symlink(&at.repo, &link).unwrap();
    let analysis = in_place_at(
        &format!("cat {link}/.env"),
        &discovered(&format!("{}/pkg", at.repo), &at.home),
    );
    assert!(!blocks_for_agent(&analysis), "{analysis:?}");
}

/// A committed template is public, and a path the text cannot resolve is not
/// guessed at: both keep the verdict they have without a directory.
#[test]
fn templates_and_unresolvable_paths_keep_their_verdict() {
    let at = layout();
    let pkg = format!("{}/pkg", at.repo);
    for command in [
        "cat /srv/other/.env.example",
        "cat ~/app/.env.sample",
        "cat $CONFIG_DIR/.env",
        "cat ~bob/.env",
        "cd \"$(git rev-parse --show-toplevel)\" && cat .env",
    ] {
        let with = in_place_at(command, &discovered(&pkg, &at.home));
        let without = analyze_command(command, None);
        assert_eq!(with.recommendation, without.recommendation, "{command}");
        assert!(!blocks_for_agent(&with), "{command}: {with:?}");
    }
}

/// FAILS ON REVERT (`$HOME` is visible): a delete under `$HOME` was denied as
/// though its target were hidden, which made `rm -rf "$HOME/.cache/x"` a hard
/// block. Its value is not hidden; every other variable still is, and so is
/// `$HOME` once the same command changes it.
#[test]
fn a_delete_under_home_is_scoped_and_other_variables_stay_hidden() {
    for command in [
        "rm -rf \"$HOME/.cache/x\"",
        "rm -rf $HOME/x",
        "rm -rf ${HOME}/.cache/x",
        "rm -rf \"${HOME}/build\"",
    ] {
        let analysis = analyze_command(command, None);
        assert_ne!(analysis.recommendation, "deny", "{command}: {analysis:?}");
        assert!(!blocks_for_agent(&analysis), "{command}: {analysis:?}");
    }
    for command in [
        "rm -rf $DEPLOY_ROOT/x",
        "rm -rf \"$TARGET/\"",
        "rm -rf $HOMEDIR/x",
        "rm -rf $home/x",
        "rm -rf $HOME/x $DEPLOY_ROOT/y",
        "rm -rf $DEPLOY_ROOT/y $HOME/x",
        "HOME=/ ; rm -rf $HOME/etc",
        "export HOME=/srv; rm -rf \"$HOME/data\"",
    ] {
        let analysis = analyze_command(command, None);
        assert_eq!(analysis.recommendation, "deny", "{command}: {analysis:?}");
    }
}
