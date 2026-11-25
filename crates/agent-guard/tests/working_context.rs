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

/// FAILS ON REVERT (no project read as no verdict): a session started in
/// the home, or a hook run from `/`, has no project, so every `.env`-class
/// read from there is outside one and blocks the agent. Nothing was reported
/// from there, and a session in the home read the home's `.env` and every
/// project's unchallenged. The verdict a person sees is the review it was,
/// and the agent is told where to start instead.
#[test]
fn a_read_from_the_home_or_the_root_has_no_project_and_blocks_the_agent() {
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
        assert!(blocks_for_agent(&with), "{command} from {cwd}: {with:?}");
        let outside = with
            .signals
            .iter()
            .find(|s| s.signal == "credential_read_outside_project")
            .expect("read outside a project");
        assert!(
            outside
                .detail
                .contains("start it in the project's own folder"),
            "{command} from {cwd}: {}",
            outside.detail
        );
    }
    // Inside a project the detail says nothing about where to start.
    let pkg = format!("{}/pkg", at.repo);
    let analysis = in_place_at("cat ~/secret.env", &discovered(&pkg, &at.home));
    let outside = analysis
        .signals
        .iter()
        .find(|s| s.signal == "credential_read_outside_project")
        .expect("read outside the project");
    assert!(!outside.detail.contains("start it"), "{}", outside.detail);
}

/// FAILS ON REVERT (stored logins reached through the place): a tool's
/// token file named by a path only the directory makes whole, or read with
/// the whole hidden folder that holds it, passed the agent hook.
#[test]
fn a_stored_login_is_refused_however_the_path_reaches_it() {
    let at = layout();
    let app = format!("{}/.hermes", at.home);
    std::fs::create_dir_all(format!("{app}/work")).expect("app");
    std::fs::write(format!("{app}/.env"), "K=v\n").expect("app env");
    std::fs::write(format!("{app}/auth.json"), "{}\n").expect("app auth");
    std::fs::write(format!("{app}/notes.md"), "x\n").expect("app notes");
    std::fs::create_dir_all(format!("{}/.config/nvim", at.home)).expect("nvim");
    // A project in the home, not hidden, with its own `.env`.
    std::fs::create_dir_all(format!("{}/proj2", at.home)).expect("proj2");
    std::fs::write(format!("{}/proj2/.env", at.home), "K=v\n").expect("proj2 env");
    let work = format!("{}/work", at.home);
    std::fs::create_dir_all(&work).expect("work");
    let from_work = discovered(&work, &at.home);
    let from_home = discovered(&at.home, &at.home);
    for (context, command) in [
        (&from_work, "cd ~/.codex && cat auth.json"),
        (&from_work, "cd ~/.aws && cat credentials"),
        (&from_work, "cd ~/.config/gh && head hosts.yml"),
        (&from_home, "cat .hermes/auth.json"),
        (&from_home, "head -c 100 .gemini/oauth_creds.json"),
        (&from_work, "grep -r xoxb ~/.hermes"),
        (&from_work, "rg xoxb ~/.hermes/"),
        (&from_work, "tar czf /tmp/h.tgz ~/.hermes"),
        (&from_work, "cp -r ~/.hermes /tmp/h"),
        (&from_work, "cat ~/.hermes/*"),
        (&from_work, "cat ~/.hermes/.e*"),
        (&from_work, "cd ~/.hermes && grep -r xoxb ."),
        (&from_work, "find ~/.hermes -type f -exec cat {} +"),
        (&from_home, "tar czf /tmp/h.tgz .hermes"),
    ] {
        let analysis = in_place_at(command, context);
        assert_eq!(
            analysis.recommendation, "deny",
            "{command} from {}: {analysis:?}",
            context.cwd
        );
    }
    // Ordinary reads near those folders pass.
    for command in [
        "grep -rn theme ~/.config/nvim",
        "grep -rn theme ~/.config",
        "grep -rn TODO ~/proj2",
        "ls -la ~/.hermes",
        "find ~/.hermes -name '*.json'",
        "cat ~/.hermes/*.md",
        "stat ~/.codex/auth.json",
    ] {
        let analysis = in_place_at(command, &from_work);
        assert!(!blocks_for_agent(&analysis), "{command}: {analysis:?}");
    }
    // An agent working inside the folder reads it as its project.
    let inside = discovered(&format!("{app}/work"), &at.home);
    let analysis = in_place_at("grep -rn TODO ..", &inside);
    assert!(!blocks_for_agent(&analysis), "{analysis:?}");
}

/// FAILS ON REVERT (one level down, and the registry logins): a whole read
/// of `~/.config` took `~/.config/gh/hosts.yml` with it, one folder below
/// the top level that was looked at, and `~/.docker/config.json` and
/// `~/.cargo/credentials.toml` were no stored login (found in review of
/// 1.6.13). Each passed the agent hook.
#[test]
fn a_stored_login_one_folder_down_or_a_registry_login_is_refused() {
    let at = layout();
    std::fs::create_dir_all(format!("{}/.config/gh", at.home)).expect("gh");
    std::fs::write(format!("{}/.config/gh/hosts.yml", at.home), "x: y\n").expect("hosts");
    std::fs::create_dir_all(format!("{}/.docker", at.home)).expect("docker");
    std::fs::write(format!("{}/.docker/config.json", at.home), "{}\n").expect("docker");
    std::fs::create_dir_all(format!("{}/.cargo", at.home)).expect("cargo");
    std::fs::write(format!("{}/.cargo/credentials.toml", at.home), "x\n").expect("cargo");
    std::fs::create_dir_all(format!("{}/.cache/pip/http", at.home)).expect("cache");
    std::fs::write(format!("{}/.cache/pip/http/a", at.home), "x\n").expect("cache file");
    let work = format!("{}/work", at.home);
    std::fs::create_dir_all(&work).expect("work");
    let from_work = discovered(&work, &at.home);
    for command in [
        "grep -r oauth_token ~/.config",
        "tar czf /tmp/c.tgz ~/.config",
        "grep -r auths ~/.docker",
        "cd ~/.docker && cat config.json",
        "cd ~/.cargo && cat credentials.toml",
        "cat ~/.cargo/credentials.toml",
    ] {
        let analysis = in_place_at(command, &from_work);
        assert_eq!(analysis.recommendation, "deny", "{command}: {analysis:?}");
    }
    for command in [
        "grep -r x ~/.cache",
        "ls ~/.config",
        "cat ~/.cargo/config.toml",
    ] {
        let analysis = in_place_at(command, &from_work);
        assert!(!blocks_for_agent(&analysis), "{command}: {analysis:?}");
    }
}

/// A public SSH file is public under every name the system gives it: with
/// the home reached through a link (on macOS a home under `/var` is, since
/// `/var` leads to `/private/var`), `cat ~/.ssh/id_ed25519.pub` is still the
/// public key. A public name that leads to the private key is still the key.
///
/// FAILS ON REVERT of the public-file test in `secret_behind` (the public key
/// under its second name was read as a key).
#[cfg(unix)]
#[test]
fn a_public_ssh_file_under_a_linked_home_is_public() {
    let at = layout();
    let real = format!("{}/real-home", at.root);
    std::fs::create_dir_all(format!("{real}/.ssh")).expect("ssh");
    std::fs::create_dir_all(format!("{real}/work")).expect("work");
    std::fs::write(format!("{real}/.ssh/id_ed25519"), "k\n").expect("key");
    std::fs::write(format!("{real}/.ssh/id_ed25519.pub"), "p\n").expect("pub");
    std::fs::write(format!("{real}/.ssh/authorized_keys"), "p\n").expect("keys");
    std::os::unix::fs::symlink("id_ed25519", format!("{real}/.ssh/leak.pub")).expect("link");
    let home = format!("{}/linked-home", at.root);
    std::os::unix::fs::symlink(&real, &home).expect("linked home");
    let context = discovered(&format!("{home}/work"), &home);
    for command in ["cat ~/.ssh/id_ed25519.pub", "cat ~/.ssh/authorized_keys"] {
        let analysis = in_place_at(command, &context);
        assert!(!blocks_for_agent(&analysis), "{command}: {analysis:?}");
    }
    let analysis = in_place_at("cat ~/.ssh/leak.pub", &context);
    assert!(blocks_for_agent(&analysis), "{analysis:?}");
}

/// A whole read of the home, or of a folder the home is in, takes the keys
/// and logins kept in it: refused as a read of one of them, from anywhere,
/// the agent's own folder climbed out of too. A search that leaves hidden
/// files out, a listing, and a read of a project in the home are not.
///
/// FAILS ON REVERT of the whole-home arm in `stored_secret_read_in_place`
/// (each read in the first list is allowed or only a review).
#[test]
fn a_whole_read_of_the_home_is_a_read_of_its_secrets() {
    let at = layout();
    std::fs::create_dir_all(format!("{}/.ssh", at.home)).expect("ssh");
    std::fs::write(format!("{}/.ssh/id_ed25519", at.home), "k\n").expect("key");
    std::fs::write(format!("{}/.ssh/id_ed25519.pub", at.home), "p\n").expect("pub");
    let work = format!("{}/work", at.home);
    std::fs::create_dir_all(&work).expect("work");
    let from_work = discovered(&work, &at.home);
    let from_home = discovered(&at.home, &at.home);
    for (context, command) in [
        (&from_work, "grep -r oauth_token ~"),
        (&from_work, "grep -rn '' ~/"),
        (&from_work, "grep -rv TODO ~/"),
        (&from_work, "grep -r x $HOME"),
        (&from_work, "grep -r x .."),
        (&from_work, "grep -r x /"),
        (&from_work, "tar czf /tmp/h.tgz ~"),
        (&from_work, "rg --hidden x ~"),
        (&from_work, "cp -a ~ /tmp/h"),
        (&from_work, "find ~ -type f -exec cat {} +"),
        (&from_home, "grep -rl x ."),
    ] {
        let analysis = in_place_at(command, context);
        assert_eq!(analysis.recommendation, "deny", "{command}: {analysis:?}");
        assert!(
            analysis
                .signals
                .iter()
                .any(|s| s.detail.contains(".ssh/id_ed25519")),
            "{command}: {analysis:?}"
        );
    }
    for command in [
        "rg x ~",
        "ls -R ~",
        "du -sh ~",
        "find ~ -name '*.py'",
        "grep -rn TODO ~/work",
        "cat ~/.ssh/id_ed25519.pub",
    ] {
        let analysis = in_place_at(command, &from_work);
        assert!(!blocks_for_agent(&analysis), "{command}: {analysis:?}");
    }
    // A grep of the whole home for a narrow text opens the key too, but
    // prints from it only a line holding that text: a person's call
    // (`review`), still named by the key, not a hard refusal.
    for command in ["grep -rn TODO ~/", "grep -rl 'fn main' ~"] {
        let analysis = in_place_at(command, &from_work);
        assert_eq!(analysis.recommendation, "review", "{command}: {analysis:?}");
        assert!(
            analysis
                .signals
                .iter()
                .any(|s| s.detail.contains(".ssh/id_ed25519")),
            "{command}: {analysis:?}"
        );
    }
    // A home that keeps no key and no login.
    let bare = layout();
    let bare_work = format!("{}/work", bare.home);
    std::fs::create_dir_all(&bare_work).expect("work");
    let analysis = in_place_at("grep -rn TODO ~", &discovered(&bare_work, &bare.home));
    assert!(!blocks_for_agent(&analysis), "{analysis:?}");
}

/// FAILS ON REVERT (the hunt reads the search text): the projection hides
/// what `grep` searches for, and the hunt for secrets never saw the word it
/// hunts, so each of these had no signal at all (measured 2026-11-14). Text
/// that only prints the same words is still no hunt.
#[test]
fn a_search_over_a_broad_root_for_a_secret_is_a_hunt() {
    let hunts = |command: &str| {
        analyze_command(command, None)
            .signals
            .iter()
            .any(|s| s.signal == "credential_hunt")
    };
    for command in [
        "grep -r password /",
        "grep -ri password /home",
        "grep -r -e id_rsa /etc",
        "cd /tmp && grep -rl api_key /srv",
    ] {
        assert!(hunts(command), "{command}");
    }
    // A pattern given by `-e` left the file masked as the pattern, and the
    // key was printed with no signal.
    for command in [
        "grep -e . ~/.ssh/id_rsa",
        "grep -e x /etc/shadow",
        "rg -e x ~/.aws/credentials",
    ] {
        assert_eq!(
            analyze_command(command, None).recommendation,
            "deny",
            "{command}"
        );
    }
    for command in [
        "echo \"grep -r password /\"",
        "grep -r password src/",
        "grep -r foo /; echo password",
        "grep -rn TODO /etc",
        // The broad root is inside the pattern, not the search: what the
        // scan shows is a search of src/.
        "grep -r -e \"password /\" src/",
    ] {
        assert!(!hunts(command), "{command}");
    }
}

/// One read signal, at the always-secret score: a softer read in the same
/// command is raised to it, and a read already at it keeps its own detail.
///
/// FAILS ON REVERT: count the place-level read beside a softer one and the
/// line carries two read signals and 40 points too many; replace a hard
/// read's detail and the key it names is lost.
#[test]
fn a_stored_login_raises_a_softer_read_and_keeps_a_harder_one() {
    let at = layout();
    let work = format!("{}/work", at.home);
    std::fs::create_dir_all(&work).expect("work");
    let context = discovered(&work, &at.home);
    let reads = |analysis: &CommandAnalysis| -> Vec<(u32, String)> {
        analysis
            .signals
            .iter()
            .filter(|s| s.signal == "sensitive_credential_read")
            .map(|s| (s.score, s.detail.clone()))
            .collect()
    };

    let command = "cd ~/.codex && cat ~/.npmrc auth.json";
    let alone = analyze_command(command, None);
    assert_eq!(
        reads(&alone).iter().map(|r| r.0).collect::<Vec<_>>(),
        [20],
        "{alone:?}"
    );
    let raised = in_place_at(command, &context);
    let read = reads(&raised);
    assert_eq!(read.len(), 1, "{raised:?}");
    assert_eq!(read[0].0, 60, "{raised:?}");
    assert!(read[0].1.contains(".codex/auth.json"), "{}", read[0].1);
    // The read is raised by 40, once. The home's `.npmrc` is also a login
    // file outside the project (`credential_read_outside_project`, 10),
    // judged by the project since 2026-11-19 as `.env` is.
    assert!(
        raised
            .signals
            .iter()
            .any(|s| s.signal == "credential_read_outside_project" && s.score == 10),
        "{raised:?}"
    );
    assert_eq!(raised.risk_score, alone.risk_score + 40 + 10, "{raised:?}");

    let command = "cat ~/.ssh/id_ed25519 ~/.codex/auth.json";
    let alone = analyze_command(command, None);
    let kept = in_place_at(command, &context);
    let read = reads(&kept);
    assert_eq!(read.len(), 1, "{kept:?}");
    assert_eq!(read[0].0, 60, "{kept:?}");
    assert!(read[0].1.contains(".ssh/"), "{}", read[0].1);
    assert_eq!(kept.risk_score, alone.risk_score, "{kept:?}");
}

/// FAILS ON REVERT (a `.git` in the home): the nearest `.git` was the
/// project whatever it was, so a `.git` entry in the home (a dotfiles
/// repository, or one an agent made) made every folder below it one
/// project, and the `.env` of any of them the project's own.
#[test]
fn a_git_entry_in_the_home_makes_no_project() {
    let at = layout();
    std::fs::create_dir_all(format!("{}/.git", at.home)).expect("home git");
    std::fs::create_dir_all(format!("{}/work", at.home)).expect("work");
    std::fs::create_dir_all(format!("{}/app/sub", at.home)).expect("app");
    let work = format!("{}/work", at.home);
    let context = discovered(&work, &at.home);
    assert_eq!(context.project_root, work);
    for command in ["cat ~/app/.env", "cat ../app/.env", "cat ~/.env"] {
        let analysis = in_place_at(command, &context);
        assert!(blocks_for_agent(&analysis), "{command}: {analysis:?}");
    }
    // A folder below the home keeps its own `.env` one level up, as with no
    // `.git` in the home.
    let sub = format!("{}/app/sub", at.home);
    let analysis = in_place_at("cat ../.env", &discovered(&sub, &at.home));
    assert!(!blocks_for_agent(&analysis), "{analysis:?}");
    // A repository of its own below the home is still its own project.
    let repo = format!("{}/proj", at.home);
    std::fs::create_dir_all(format!("{repo}/.git")).expect("proj git");
    std::fs::create_dir_all(format!("{repo}/pkg")).expect("proj pkg");
    let context = discovered(&format!("{repo}/pkg"), &at.home);
    assert_eq!(context.project_root, repo);
    let analysis = in_place_at("cat ../.env", &context);
    assert!(!blocks_for_agent(&analysis), "{analysis:?}");
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
