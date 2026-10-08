//! Look-alike package names on install.
//!
//! `pip install reqeusts` and `npm install expresss` were scored `allow`: no
//! rule looked at WHICH package an install names, only at where it came from
//! (see `check_untrusted_software_source`). A typosquat is published under a
//! name one slip away from a package everybody installs, and an AI agent adds a
//! second route to the same place: it can invent a plausible package name, and
//! an attacker who registers that name is installed by every agent that makes
//! the same guess. Install hooks run with the user's rights the moment the
//! package lands, so the install IS the execution step.
//!
//! The test is deliberately narrow so it can be trusted:
//! - only names given to a real install subcommand of pip, pipx, uv, poetry,
//!   pipenv, npm, yarn, pnpm or bun are read, never words elsewhere, plus the
//!   package a fetch-and-run names (`npx`, `npm exec`, `pnpm dlx`, `yarn dlx`,
//!   `bunx`, `uvx`, `uv tool run`, `pipx run`, and its `-p`/`--package`,
//!   `--from`, `--spec`, `--with` options) and a `pip download`/`pip wheel`,
//!   which fetch the same package and, for a source package, run its build
//!   code. A run reads only its first word as the package: what follows is
//!   that package's own arguments;
//! - a name that is itself on the shipped popular list
//!   (`data/popular-packages.txt`) is never flagged, and real packages that sit
//!   one edit from a popular one are listed there for that reason;
//! - the typed name must be exactly ONE edit (insert, delete, substitute, or
//!   swap two adjacent letters) from a popular name, and both must be at least
//!   five characters, because one edit from `pg` or `six` is half a registry.
//!
//! Scored to `review`, not `deny`: an unlisted package one letter from a
//! popular one is usually a squat or a slip, but not always, and the person at
//! a terminal can read the name and decide. For an agent the class is in
//! `AGENT_REVIEW_FLOOR`, because an agent that invented the name has nobody
//! reading it before the install hook runs.

use std::collections::HashSet;
use std::sync::OnceLock;

use crate::threats::{
    effective_command_index, shell_command_segments, shell_tokens, token_basename,
};

const POPULAR: &str = include_str!("../data/popular-packages.txt");

/// Shortest name compared, typed or popular.
const MIN_COMPARED_LEN: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ecosystem {
    PyPi,
    Npm,
}

impl Ecosystem {
    fn registry(self) -> &'static str {
        match self {
            Ecosystem::PyPi => "PyPI",
            Ecosystem::Npm => "npm",
        }
    }
}

struct PopularLists {
    pypi: Vec<String>,
    npm: Vec<String>,
    pypi_set: HashSet<String>,
    npm_set: HashSet<String>,
}

fn popular() -> &'static PopularLists {
    static LISTS: OnceLock<PopularLists> = OnceLock::new();
    LISTS.get_or_init(|| {
        let mut pypi = Vec::new();
        let mut npm = Vec::new();
        let mut section = None;
        for line in POPULAR.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match line {
                "[pypi]" => section = Some(Ecosystem::PyPi),
                "[npm]" => section = Some(Ecosystem::Npm),
                name => match section {
                    Some(Ecosystem::PyPi) => pypi.push(normalize_pypi(name)),
                    Some(Ecosystem::Npm) => npm.push(name.to_ascii_lowercase()),
                    None => {}
                },
            }
        }
        PopularLists {
            pypi_set: pypi.iter().cloned().collect(),
            npm_set: npm.iter().cloned().collect(),
            pypi,
            npm,
        }
    })
}

/// PEP 503 name normalisation: lower case, runs of `-`, `_`, `.` become `-`.
fn normalize_pypi(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut in_separator = false;
    for character in name.chars() {
        if matches!(character, '-' | '_' | '.') {
            if !in_separator {
                out.push('-');
            }
            in_separator = true;
        } else {
            out.push(character.to_ascii_lowercase());
            in_separator = false;
        }
    }
    out
}

/// Whether `a` and `b` differ by exactly one insertion, deletion,
/// substitution or swap of two adjacent characters (optimal string alignment
/// distance 1). Linear, no allocation beyond the char vectors.
fn one_edit_apart(a: &str, b: &str) -> bool {
    if a == b {
        return false;
    }
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (short, long) = if a.len() <= b.len() {
        (&a, &b)
    } else {
        (&b, &a)
    };
    match long.len() - short.len() {
        0 => {
            let differing: Vec<usize> = (0..short.len()).filter(|&i| short[i] != long[i]).collect();
            match differing.as_slice() {
                [_] => true,
                [first, second] => {
                    *second == first + 1
                        && short[*first] == long[*second]
                        && short[*second] == long[*first]
                }
                _ => false,
            }
        }
        1 => {
            let prefix = short
                .iter()
                .zip(long.iter())
                .take_while(|(left, right)| left == right)
                .count();
            short[prefix..] == long[prefix + 1..]
        }
        _ => false,
    }
}

/// How a subcommand reads its arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Every positional argument is a package (`pip install a b`).
    Install,
    /// The first positional argument is the package to fetch and run, and the
    /// rest are its own arguments (`npx cowsay hello`, `uvx ruff check .`).
    Run,
}

/// The package arguments of an install, a download or a fetch-and-run, with
/// the ecosystem they name and how they are read.
///
/// A run (`npx`, `uvx`, `pipx run`, `pnpm dlx`, `bunx`, ...) and a download
/// (`pip download`, `pip wheel`) fetch the same package an install does, and a
/// run executes it at once, so a look-alike there is the same step.
fn install_arguments(words: &[String]) -> Option<(Ecosystem, Mode, &[String])> {
    let index = effective_command_index(words)?;
    let tool = token_basename(&words[index]).to_ascii_lowercase();
    let rest = &words[index + 1..];
    // The subcommand (first word that is not an option) and what follows it.
    let subcommand = |rest: &'_ [String]| -> Option<(String, usize)> {
        let position = rest.iter().position(|word| !word.starts_with('-'))?;
        Some((rest[position].to_ascii_lowercase(), position + 1))
    };
    let pick = |rest: &'_ [String], table: &[(&str, Mode)]| -> Option<(Mode, usize)> {
        let (name, after) = subcommand(rest)?;
        table
            .iter()
            .find(|(candidate, _)| *candidate == name)
            .map(|(_, mode)| (*mode, after))
    };
    use Mode::{Install, Run};
    let (ecosystem, mode, from) = match tool.as_str() {
        "pip" | "pip3" => {
            let (mode, after) = pick(
                rest,
                &[
                    ("install", Install),
                    ("download", Install),
                    ("wheel", Install),
                ],
            )?;
            (Ecosystem::PyPi, mode, after)
        }
        "pipenv" => {
            let (mode, after) = pick(rest, &[("install", Install)])?;
            (Ecosystem::PyPi, mode, after)
        }
        "pipx" => {
            let (mode, after) = pick(rest, &[("install", Install), ("run", Run)])?;
            (Ecosystem::PyPi, mode, after)
        }
        "poetry" => {
            let (mode, after) = pick(rest, &[("add", Install)])?;
            (Ecosystem::PyPi, mode, after)
        }
        "uvx" => (Ecosystem::PyPi, Run, 0),
        "uv" => {
            let (name, after) = subcommand(rest)?;
            match name.as_str() {
                "add" => (Ecosystem::PyPi, Install, after),
                "pip" | "tool" => {
                    let table: &[(&str, Mode)] = if name == "pip" {
                        &[("install", Install)]
                    } else {
                        &[("install", Install), ("run", Run)]
                    };
                    let (mode, more) = pick(&rest[after..], table)?;
                    (Ecosystem::PyPi, mode, after + more)
                }
                _ => return None,
            }
        }
        name if name.starts_with("python") || name == "py" => {
            // `python3 -m pip install X`
            let module = rest.iter().position(|word| word == "-m")?;
            if rest.get(module + 1).map(String::as_str) != Some("pip") {
                return None;
            }
            let start = module + 2;
            let (mode, after) = pick(
                &rest[start..],
                &[
                    ("install", Install),
                    ("download", Install),
                    ("wheel", Install),
                ],
            )?;
            (Ecosystem::PyPi, mode, start + after)
        }
        "npx" | "pnpx" | "bunx" => (Ecosystem::Npm, Run, 0),
        "npm" => {
            let (mode, after) = pick(
                rest,
                &[
                    ("install", Install),
                    ("i", Install),
                    ("add", Install),
                    ("isntall", Install),
                    ("in", Install),
                    ("exec", Run),
                    ("x", Run),
                ],
            )?;
            (Ecosystem::Npm, mode, after)
        }
        "yarn" => {
            let (mode, after) = pick(rest, &[("add", Install), ("dlx", Run)])?;
            (Ecosystem::Npm, mode, after)
        }
        "pnpm" => {
            let (mode, after) = pick(
                rest,
                &[
                    ("add", Install),
                    ("install", Install),
                    ("i", Install),
                    ("dlx", Run),
                ],
            )?;
            (Ecosystem::Npm, mode, after)
        }
        "bun" => {
            let (mode, after) = pick(
                rest,
                &[
                    ("add", Install),
                    ("install", Install),
                    ("i", Install),
                    ("x", Run),
                ],
            )?;
            (Ecosystem::Npm, mode, after)
        }
        _ => return None,
    };
    Some((ecosystem, mode, &rest[from..]))
}

/// An option of a fetch-and-run that names a package: `npx -p pkg cmd`,
/// `uvx --from pkg cmd`, `pipx run --spec pkg app`, `uvx --with pkg cmd`.
/// Returns whether the option REPLACES the positional package (the positional
/// is then a command name, not a package).
fn package_option(ecosystem: Ecosystem, option: &str) -> Option<bool> {
    match (ecosystem, option) {
        (Ecosystem::Npm, "-p" | "--package") => Some(true),
        (Ecosystem::PyPi, "--from" | "--spec") => Some(true),
        (Ecosystem::PyPi, "--with") => Some(false),
        _ => None,
    }
}

/// The package names an install or a fetch-and-run names, as typed.
fn named_packages(ecosystem: Ecosystem, mode: Mode, arguments: &[String]) -> Vec<String> {
    let mut named = Vec::new();
    let mut positional_is_package = true;
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        index += 1;
        if argument == "--" {
            continue;
        }
        if argument.starts_with('-') {
            let (option, inline_value) = match argument.split_once('=') {
                Some((option, value)) => (option, Some(value.to_string())),
                None => (argument.as_str(), None),
            };
            if let Some(replaces) = package_option(ecosystem, option) {
                let value = match inline_value {
                    Some(value) => Some(value),
                    None => {
                        index += 1;
                        arguments.get(index - 1).cloned()
                    }
                };
                if let Some(value) = value {
                    // `--with a,b` names two packages.
                    named.extend(value.split(',').map(str::to_string));
                }
                if replaces {
                    positional_is_package = false;
                }
                continue;
            }
            if mode == Mode::Run && matches!(option, "-c" | "--call") {
                // `npx -c 'cmd'` runs a command string, not a package.
                positional_is_package = false;
            }
            if inline_value.is_none()
                && (option_takes_value(ecosystem, option)
                    || (mode == Mode::Run && matches!(option, "-c" | "--call")))
            {
                index += 1;
            }
            continue;
        }
        match mode {
            Mode::Install => named.push(argument.clone()),
            Mode::Run => {
                // Everything after the package belongs to it, not to the runner.
                if positional_is_package {
                    named.push(argument.clone());
                }
                break;
            }
        }
    }
    named
}

/// Options that take a value, so the value is not read as a package name.
fn option_takes_value(ecosystem: Ecosystem, option: &str) -> bool {
    match ecosystem {
        Ecosystem::PyPi => matches!(
            option,
            "-r" | "--requirement"
                // `pip download -d DIR`, `pip wheel -w DIR`
                | "-d"
                | "--dest"
                | "-w"
                | "--wheel-dir"
                | "-c"
                | "--constraint"
                | "-e"
                | "--editable"
                | "-i"
                | "--index-url"
                | "--extra-index-url"
                | "--index"
                | "--default-index"
                | "-f"
                | "--find-links"
                | "-t"
                | "--target"
                | "--prefix"
                | "--root"
                | "--src"
                | "--trusted-host"
                | "--platform"
                | "--python-version"
                | "--implementation"
                | "--abi"
                | "--upgrade-strategy"
                | "--cache-dir"
                | "--log"
                | "--proxy"
                | "--retries"
                | "--timeout"
                | "--cert"
                | "--client-cert"
                | "--python"
                | "-p"
                | "--group"
                | "-G"
                | "--source"
                | "--optional"
                | "--extra"
                | "-E"
                | "--extras"
                | "--package"
                | "-C"
                | "--config-settings"
        ),
        Ecosystem::Npm => matches!(
            option,
            "--registry"
                | "--prefix"
                | "-w"
                | "--workspace"
                | "--tag"
                | "--cache"
                | "--userconfig"
                | "--cwd"
                | "--filter"
                | "-C"
                | "--dir"
        ),
    }
}

/// The bare package name of one install argument, or `None` when the argument
/// is not a registry name (a path, a URL, a VCS spec, an archive).
fn package_name(ecosystem: Ecosystem, argument: &str) -> Option<String> {
    let argument = argument.trim_matches(['\'', '"']);
    if argument.is_empty()
        || argument.contains("://")
        || argument.starts_with('.')
        || argument.starts_with('/')
        || argument.starts_with('~')
        || argument.contains(':')
    {
        return None;
    }
    match ecosystem {
        Ecosystem::PyPi => {
            // `name[extra]==1.0 ; marker` -> `name`
            let end = argument
                .find(['[', '=', '<', '>', '!', '~', ';', ' ', '@'])
                .unwrap_or(argument.len());
            let name = &argument[..end];
            if name.is_empty()
                || name.contains('/')
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                || name.ends_with(".whl")
                || name.ends_with(".tar.gz")
                || name.ends_with(".zip")
            {
                return None;
            }
            Some(normalize_pypi(name))
        }
        Ecosystem::Npm => {
            // `@scope/name@1.2` -> `@scope/name`, `name@latest` -> `name`
            let (scope, rest) = match argument.strip_prefix('@') {
                Some(rest) => {
                    let (scope, name) = rest.split_once('/')?;
                    (Some(scope), name)
                }
                None => (None, argument),
            };
            let name = rest.split('@').next().unwrap_or(rest);
            if name.is_empty()
                || name.contains('/')
                || name.ends_with(".tgz")
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            {
                return None;
            }
            let name = name.to_ascii_lowercase();
            Some(match scope {
                Some(scope) => format!("@{}/{name}", scope.to_ascii_lowercase()),
                None => name,
            })
        }
    }
}

/// The popular package `name` imitates, when it is one edit from one without
/// being on the list itself.
fn look_alike(ecosystem: Ecosystem, name: &str) -> Option<String> {
    let lists = popular();
    let (list, set) = match ecosystem {
        Ecosystem::PyPi => (&lists.pypi, &lists.pypi_set),
        Ecosystem::Npm => (&lists.npm, &lists.npm_set),
    };
    if set.contains(name) || name.chars().count() < MIN_COMPARED_LEN {
        return None;
    }
    list.iter()
        .filter(|popular| popular.chars().count() >= MIN_COMPARED_LEN)
        .find(|popular| one_edit_apart(name, popular))
        .cloned()
}

/// A package install naming a look-alike of a popular package.
///
/// Returns the human detail and the score (25, `review`).
pub(crate) fn check_package_typosquat(content: &str) -> Option<(String, u32)> {
    let lower = content.to_ascii_lowercase();
    if !["pip", "uv", "poetry", "npm", "npx", "yarn", "pnpm", "bun"]
        .iter()
        .any(|tool| lower.contains(tool))
    {
        return None;
    }
    for segment in shell_command_segments(content) {
        let words = shell_tokens(segment);
        let Some((ecosystem, mode, arguments)) = install_arguments(&words) else {
            continue;
        };
        for argument in named_packages(ecosystem, mode, arguments) {
            let Some(name) = package_name(ecosystem, &argument) else {
                continue;
            };
            if let Some(popular) = look_alike(ecosystem, &name) {
                let verb = match mode {
                    Mode::Install => "installs",
                    Mode::Run => "fetches and runs",
                };
                return Some((
                    format!(
                        "{verb} `{name}`, one edit from the popular {} package `{popular}`: a \
                         look-alike name is how typosquatted and invented packages get installed",
                        ecosystem.registry()
                    ),
                    25,
                ));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_edit_covers_the_four_slips_and_nothing_wider() {
        assert!(one_edit_apart("reqeusts", "requests"), "swap");
        assert!(one_edit_apart("expresss", "express"), "insert");
        assert!(one_edit_apart("expres", "express"), "delete");
        assert!(one_edit_apart("djangp", "django"), "substitute");
        assert!(
            !one_edit_apart("requests", "requests"),
            "equal is not a slip"
        );
        assert!(!one_edit_apart("rqeuestss", "requests"), "two edits");
        assert!(!one_edit_apart("abcd", "badc"), "two swaps");
    }

    #[test]
    fn look_alike_installs_are_named_with_the_package_they_imitate() {
        for (command, typed, real) in [
            ("pip install reqeusts", "reqeusts", "requests"),
            ("pip3 install --user djnago", "djnago", "django"),
            ("python3 -m pip install -U nunpy==1.26", "nunpy", "numpy"),
            (
                "uv pip install python-dateutils",
                "python-dateutils",
                "python-dateutil",
            ),
            ("poetry add --group dev pytset", "pytset", "pytest"),
            ("npm install expresss", "expresss", "express"),
            ("npm i -g lodahs", "lodahs", "lodash"),
            ("yarn add recat@18", "recat", "react"),
            ("sudo pnpm add -D typescirpt", "typescirpt", "typescript"),
            ("npm install @types/nodee", "@types/nodee", "@types/node"),
        ] {
            let (detail, score) = check_package_typosquat(command)
                .unwrap_or_else(|| panic!("must surface the look-alike in: {command}"));
            assert_eq!(score, 25, "review band: {command}");
            assert!(
                detail.contains(&format!("`{typed}`")) && detail.contains(&format!("`{real}`")),
                "{command}: {detail}"
            );
        }
    }

    #[test]
    fn real_packages_paths_and_option_values_are_not_look_alikes() {
        for command in [
            "pip install requests",
            "pip install Requests==2.31.0",
            "pip install -r requirements.txt",
            "pip install -e .",
            "pip install 'django>=4.2' djangorestframework",
            "pip install scapy scipy scrapy pyaml",
            "pip install --index-url https://pypi.example/simple requests",
            "pip install git+https://github.com/psf/requests.git",
            "pip install ./dist/pkg-1.0-py3-none-any.whl",
            "pip install python_dateutil",
            "npm install",
            "npm ci",
            "npm install express react react-dom",
            "npm install preact tslint expresso colors server",
            "npm install lodash@4.17.21 --save",
            "npm install --registry https://registry.npmjs.org axios",
            "npm install ./local-package file:../lib",
            "yarn add @types/node -D",
            "npm run expresss",
            "echo pip install reqeusts",
            "npm install mkdi",
        ] {
            assert!(
                check_package_typosquat(command).is_none(),
                "must not flag: {command}"
            );
        }
    }

    #[test]
    fn a_fetch_and_run_or_a_download_of_a_look_alike_is_named() {
        // Each fetched a look-alike and was `allow`: only install subcommands
        // were read, and a run executes the package the moment it lands.
        for (command, typed, real) in [
            ("npx expresss", "expresss", "express"),
            ("npx -y lodahs@latest", "lodahs", "lodash"),
            ("npx --package=typescirpt tsc", "typescirpt", "typescript"),
            ("npx -p recat some-bin --flag", "recat", "react"),
            ("npm exec -- expresss", "expresss", "express"),
            ("pnpm dlx expresss", "expresss", "express"),
            ("yarn dlx expresss", "expresss", "express"),
            ("bunx expresss", "expresss", "express"),
            ("bun x expresss", "expresss", "express"),
            ("pip download reqeusts", "reqeusts", "requests"),
            ("pip3 download -d ./wheels djnago==4.2", "djnago", "django"),
            ("python3 -m pip download nunpy", "nunpy", "numpy"),
            ("pip wheel reqeusts", "reqeusts", "requests"),
            ("uvx reqeusts", "reqeusts", "requests"),
            ("uvx --python 3.12 pytset --version", "pytset", "pytest"),
            ("uvx --from reqeusts some-cli", "reqeusts", "requests"),
            ("uvx --with nunpy ipython", "nunpy", "numpy"),
            ("uv tool run pytset", "pytset", "pytest"),
            ("uv tool install djnago", "djnago", "django"),
            ("pipx run reqeusts", "reqeusts", "requests"),
            ("pipx run --spec djnago django-admin", "djnago", "django"),
        ] {
            let (detail, score) = check_package_typosquat(command)
                .unwrap_or_else(|| panic!("must surface the look-alike in: {command}"));
            assert_eq!(score, 25, "review band: {command}");
            assert!(
                detail.contains(&format!("`{typed}`")) && detail.contains(&format!("`{real}`")),
                "{command}: {detail}"
            );
        }
    }

    #[test]
    fn a_runs_own_arguments_and_real_packages_are_not_look_alikes() {
        for command in [
            "npx create-react-app my-app",
            "npx -y @modelcontextprotocol/server-filesystem /home/u/projects",
            "npx prettier --write expresss.js",
            // What follows the package is the package's own arguments.
            "npx cowsay expresss",
            "npx -p typescript tsc --init",
            "npx -c 'echo expresss'",
            "npm exec -- eslint .",
            "pnpm dlx create-vite my-app",
            "bunx vitest run",
            "uvx ruff check .",
            "uvx mcp-server-git --repository reqeusts",
            "uvx --from httpie http GET https://example.com",
            "uv tool run black reqeusts.py",
            "pipx run cowsay reqeusts",
            "pip download -d ./wheels requests",
            "pip wheel -w ./dist .",
            "npm exec --help",
        ] {
            assert!(
                check_package_typosquat(command).is_none(),
                "must not flag: {command}"
            );
        }
    }

    #[test]
    fn the_shipped_list_parses_and_holds_both_registries() {
        let lists = popular();
        assert!(lists.pypi.len() >= 200, "pypi list {}", lists.pypi.len());
        assert!(lists.npm.len() >= 200, "npm list {}", lists.npm.len());
        assert!(lists.pypi_set.contains("requests"));
        assert!(lists.npm_set.contains("express"));
        // The list stores normalised names, so a separator variant of a listed
        // package is an exact match, never a look-alike of itself.
        assert!(lists.pypi.iter().all(|name| *name == normalize_pypi(name)));
    }
}
