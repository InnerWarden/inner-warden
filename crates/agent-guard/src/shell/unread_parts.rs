//! What a line leaves unread, for the guard's one fail-closed rule.
//!
//! A reader of shell lines never knows every spelling the shell has. Where
//! the guard cannot read part of a line, that part may run, write, delete,
//! stop or send anything, so such a line is never allowed: it is held for
//! review ([`unread_part`]), unless the part not read stands where it
//! provably decides none of those.
//!
//! A part is unread when the text does not show its value: a command
//! substitution, a process substitution, a variable the line does not set
//! to a value it writes out (and that is not one the guard knows, such as
//! the home), a positional parameter, an indirect expansion. Read, on the
//! other hand: a variable the line sets to text it writes out, a loop
//! variable over words and patterns written out, the special parameters
//! that hold a number (`$?`, `$$`, `$!`, `$#`), arithmetic, and a substitution
//! that only prints text written out (`$(cat <<'EOF' ... EOF)`) or a value no
//! line can steer (the date, the number of processors, the user's or the
//! host's name).
//!
//! Where an unread part stands decides. It is held when it names the
//! program; is the code an `eval`, a shell, an interpreter or `source` runs
//! (an argument, a here-document that expands, a here-string, a file named
//! by it, a pipe); is the target of a write; is the value of a setting that
//! changes what later programs load (`PATH`, `LD_PRELOAD`, `BASH_ENV`, ...);
//! is a word of a wrapper in front of the program (`sudo`, `env`); or is an
//! argument of any program not known to only read or print. The words
//! `xargs` adds from its input are unread too. A program written out that
//! runs a script file is read by its name, as any program is: what the file
//! holds is the file's. A line the grammar cannot read at all keeps the
//! reading it has (see [`unread_part_at`]).

use super::{
    collect_all_commands, collect_nodes_of_kind, command_arguments, command_code_input,
    command_words, effective_command_words, heredoc_owner, is_folder_printer, is_shell_name,
    node_is_in_literal_unreachable_branch, node_text, normalized_command_name, parse_complete_tree,
    runtime_word_ends_in_literal_program, shell_inline_code_place, shell_literal_word, shell_word,
    CodeInput, MAX_AST_DEPTH,
};
use std::collections::HashMap;

/// Why a line is held: what the guard could not read, and where it stands.
pub(crate) const UNREAD_PROGRAM: &str = "the program this line runs is named by a value the guard cannot read (a variable or a substitution), so what runs is unread";
pub(crate) const UNREAD_CODE: &str = "the code this line hands to eval, a shell, an interpreter or source comes from a value the guard cannot read (a variable, a substitution, a here-document that expands, or a pipe), so what runs is unread";
pub(crate) const UNREAD_WRITE_TARGET: &str =
    "this line writes to a file named by a value the guard cannot read, so where it writes is unread";
pub(crate) const UNREAD_SETTING: &str = "this line sets what later programs load or run (a search path, a preload, a startup file) to a value the guard cannot read";
pub(crate) const UNREAD_WRAPPER: &str = "a word in front of the program (sudo, env and the like) holds a value the guard cannot read, so how the program runs is unread";
pub(crate) const UNREAD_ARGUMENT: &str = "a program that may run, write, delete, stop or send is handed a value the guard cannot read (a variable or a substitution), so what it acts on is unread";
pub(crate) const UNREAD_XARGS: &str = "xargs hands a program that may run, write, delete, stop or send the words it reads on its input, which the guard cannot read";

/// Variables the guard reads without the line setting them: its rules
/// read the home, and the search path only changes here through a value a
/// line sets.
const KNOWN_VARIABLES: &[&str] = &[
    "HOME", "USER", "LOGNAME", "UID", "EUID", "PPID", "HOSTNAME", "RANDOM", "SECONDS", "LINENO",
    "BASHPID", "PATH",
];

/// Folders the guard knows by their meaning, not by their text: the working
/// folder. Read where they name a program's folder, as the folder queries
/// are; unread where a program writes, deletes or runs as code what they
/// name (`rm -rf "$PWD"` empties a folder no rule saw).
const FOLDERS_BY_MEANING: &[&str] = &["PWD", "OLDPWD"];

/// Settings whose value decides what later programs load or run.
fn is_loading_setting(name: &str) -> bool {
    matches!(
        name,
        "PATH"
            | "LD_PRELOAD"
            | "LD_LIBRARY_PATH"
            | "LD_AUDIT"
            | "DYLD_INSERT_LIBRARIES"
            | "DYLD_LIBRARY_PATH"
            | "BASH_ENV"
            | "ENV"
            | "PROMPT_COMMAND"
            | "PS0"
            | "PS1"
            | "PS4"
            | "SHELLOPTS"
            | "BASHOPTS"
            | "IFS"
            | "NODE_OPTIONS"
            | "NODE_PATH"
            | "PYTHONPATH"
            | "PYTHONSTARTUP"
            | "PYTHONHOME"
            | "PERL5OPT"
            | "PERL5LIB"
            | "RUBYOPT"
            | "RUBYLIB"
            | "GIT_SSH"
            | "GIT_SSH_COMMAND"
            | "GIT_EXEC_PATH"
            | "GIT_PAGER"
            | "EDITOR"
            | "VISUAL"
            | "PAGER"
            | "SSH_ASKPASS"
            | "SUDO_ASKPASS"
    ) || name.starts_with("BASH_FUNC_")
        || name.starts_with("GIT_CONFIG")
}

/// One place the line sets a variable.
#[derive(Clone)]
struct Setting {
    /// Where it stands in the line.
    at: usize,
    /// Its value is read where a folder the guard knows by its meaning
    /// counts as read (a program's folder).
    read: bool,
    /// Its value is read as text (what a program writes, deletes or runs
    /// as code).
    read_strict: bool,
    /// The value, when the line writes it out; for a program's path the
    /// line looks up (`$(command -v python3)`), the program's name.
    value: Option<String>,
}

/// What the line sets, and where, as far as it shows.
#[derive(Default)]
struct Names {
    settings: HashMap<String, Vec<Setting>>,
    /// The spans of the loops of the line: a value set later in a loop
    /// reaches a use earlier in it.
    loops: Vec<(usize, usize)>,
    /// The bodies of the functions the line defines, and whether every
    /// call of each hands it words the line shows.
    functions: Vec<(usize, usize, bool)>,
    /// For a shell's line written out: which of its positional parameters
    /// (`$0` first) are handed values the outer line shows.
    positional: Vec<bool>,
}

impl Names {
    fn add(&mut self, name: &str, setting: Setting) {
        self.settings
            .entry(name.to_owned())
            .or_default()
            .push(setting);
    }

    /// The settings of `name` that may be its value at `at`: the last one
    /// before it, and any later one in a loop around it.
    fn candidates(&self, name: &str, at: usize) -> Vec<&Setting> {
        let Some(all) = self.settings.get(name) else {
            return Vec::new();
        };
        let mut found: Vec<&Setting> = all.iter().rfind(|s| s.at < at).into_iter().collect();
        for (start, end) in &self.loops {
            if *start <= at && at < *end {
                found.extend(all.iter().filter(|s| s.at > at && s.at < *end));
            }
        }
        found
    }

    fn is_read(&self, name: &str, at: usize, strict: bool) -> bool {
        if name.chars().all(|c| c.is_ascii_digit()) || matches!(name, "@" | "*") {
            let bound = self
                .functions
                .iter()
                .filter(|(start, end, _)| *start <= at && at < *end)
                .min_by_key(|(start, end, _)| end - start);
            if let Some((_, _, read)) = bound {
                return *read;
            }
            if matches!(name, "@" | "*") {
                return self.positional.len() > 1 && self.positional[1..].iter().all(|r| *r);
            }
            return name
                .parse::<usize>()
                .ok()
                .and_then(|place| self.positional.get(place))
                .copied()
                .unwrap_or(false);
        }
        let found = self.candidates(name, at);
        if found.is_empty() {
            return KNOWN_VARIABLES.contains(&name)
                || (!strict && FOLDERS_BY_MEANING.contains(&name));
        }
        found.iter().all(|setting| {
            if strict {
                setting.read_strict
            } else {
                setting.read
            }
        })
    }

    /// The values written out `name` may hold at `at`, when every one is
    /// (where not `strict`, a program's name a value looks up counts).
    fn values(&self, name: &str, at: usize, strict: bool) -> Option<Vec<String>> {
        let found = self.candidates(name, at);
        let read = |setting: &&Setting| {
            if strict {
                setting.read_strict
            } else {
                setting.read
            }
        };
        if found.is_empty() || !found.iter().all(read) {
            return None;
        }
        found.iter().map(|setting| setting.value.clone()).collect()
    }
}

/// How deep a shell's `-c` line written out is read again.
const DEPTH: u8 = 3;

/// The part of `source` the guard cannot read, as the reason a line is held
/// for, or `None` when everything that decides what runs, where it writes,
/// what it deletes or stops and where it sends is read.
pub(crate) fn unread_part(source: &str) -> Option<&'static str> {
    unread_part_at(source, 0, Vec::new())
}

/// [`unread_part`] of a line at `depth` shells down, whose positional
/// parameters are read where `positional` says (`$0` first).
fn unread_part_at(source: &str, depth: u8, positional: Vec<bool>) -> Option<&'static str> {
    if source.trim().is_empty() {
        return None;
    }
    // A line the grammar cannot read keeps the reading it has: the raw
    // text scan and the fetch-and-run net of `unparsed.rs`. Holding it too
    // was measured on 2026-11-20 at 8 of the 160 benign lines of the proof
    // corpus, 4 of them everyday ones (`grep -rn TODO src | wc -l )`), most
    // of them lines bash refuses as well. Kept out by decision of 2026-11-20,
    // until the grammar reads more of what bash reads.
    let tree = parse_complete_tree(source)?;
    let bytes = source.as_bytes();
    let root = tree.root_node();
    let mut names = names_of(root, bytes);
    names.positional = positional;

    // Settings that change what later programs load.
    let mut assignments = Vec::new();
    collect_nodes_of_kind(root, "variable_assignment", &mut assignments, 0);
    for assignment in assignments {
        let Some(name) = assignment.child_by_field_name("name") else {
            continue;
        };
        let name = node_text(name, bytes);
        let name = name.split('[').next().unwrap_or(&name);
        if is_loading_setting(name)
            && assignment
                .child_by_field_name("value")
                .is_some_and(|value| unread(value, bytes, &names, true))
        {
            return Some(UNREAD_SETTING);
        }
    }

    // Writes to a file the line does not name.
    let mut redirects = Vec::new();
    collect_nodes_of_kind(root, "file_redirect", &mut redirects, 0);
    for redirect in redirects {
        let Some(destination) = redirect.child_by_field_name("destination") else {
            continue;
        };
        let operator = redirect_operator(redirect, bytes);
        let writes = operator.contains('>')
            && !(operator.contains(">&") && is_descriptor(&node_text(destination, bytes)));
        if writes && unread(destination, bytes, &names, true) {
            return Some(UNREAD_WRITE_TARGET);
        }
    }

    let mut commands = Vec::new();
    collect_all_commands(root, &mut commands, 0);
    commands
        .into_iter()
        // A branch that never runs (`if false; then ...`) decides nothing.
        .filter(|command| !node_is_in_literal_unreachable_branch(*command, bytes))
        .find_map(|command| command_unread(command, bytes, &names, depth))
}

/// The operator of a file redirection: its text but the destination.
fn redirect_operator(redirect: tree_sitter::Node<'_>, source: &[u8]) -> String {
    let mut cursor = redirect.walk();
    let parts: Vec<_> = redirect
        .children(&mut cursor)
        .filter(|child| !child.is_named() || child.kind() == "file_descriptor")
        .collect();
    parts
        .into_iter()
        .map(|child| node_text(child, source))
        .collect::<Vec<_>>()
        .concat()
}

fn is_descriptor(text: &str) -> bool {
    let text = shell_word(text);
    text == "-" || (!text.is_empty() && text.chars().all(|c| c.is_ascii_digit()))
}

/// A word that is a variable's name.
fn is_name(word: &str) -> bool {
    !word.is_empty()
        && !word.starts_with(|c: char| c.is_ascii_digit())
        && word.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// What the line sets, in the order it sets it.
fn names_of(root: tree_sitter::Node<'_>, source: &[u8]) -> Names {
    let mut names = Names::default();
    let mut places = Vec::new();
    collect_setting_places(root, &mut places, 0);
    for place in places {
        let at = place.start_byte();
        match place.kind() {
            "variable_assignment" => {
                let Some(name) = place.child_by_field_name("name") else {
                    continue;
                };
                let name = node_text(name, source);
                let name = name.split('[').next().unwrap_or(&name).to_owned();
                // A reference (`declare -n`) writes to a name the value says.
                let by_reference = place.parent().is_some_and(|owner| {
                    owner.kind() == "declaration_command"
                        && node_text(owner, source)
                            .split_whitespace()
                            .skip(1)
                            .take_while(|word| word.starts_with('-'))
                            .any(|word| word.contains('n'))
                });
                let value = place.child_by_field_name("value");
                let read = !by_reference
                    && value.is_none_or(|value| !unread(value, source, &names, false));
                let read_strict =
                    !by_reference && value.is_none_or(|value| !unread(value, source, &names, true));
                let value = match value {
                    None => Some(String::new()),
                    Some(value) => literal_value(value, source),
                };
                names.add(
                    &name,
                    Setting {
                        at,
                        read,
                        read_strict,
                        value,
                    },
                );
            }
            "expansion" => {
                // `${NAME:=default}` sets NAME where it is unset.
                let text = node_text(place, source);
                let Some(inner) = text.strip_prefix("${").and_then(|t| t.strip_suffix('}')) else {
                    continue;
                };
                let name: String = inner
                    .chars()
                    .take_while(|c| *c == '_' || c.is_ascii_alphanumeric())
                    .collect();
                let rest = &inner[name.len()..];
                let Some(default) = rest.strip_prefix(":=").or_else(|| rest.strip_prefix('='))
                else {
                    continue;
                };
                if !is_name(&name) {
                    continue;
                }
                let read = !default.contains(['$', '`']);
                let value = read.then(|| shell_word(default));
                names.add(
                    &name,
                    Setting {
                        at,
                        read,
                        read_strict: read,
                        value,
                    },
                );
            }
            "for_statement" | "select_statement" => {
                let Some(variable) = place.child_by_field_name("variable") else {
                    continue;
                };
                let name = node_text(variable, source);
                let mut cursor = place.walk();
                let values: Vec<_> = place.children_by_field_name("value", &mut cursor).collect();
                let over = |strict: bool| {
                    place.kind() == "for_statement"
                        && !values.is_empty()
                        && values
                            .iter()
                            .all(|value| !unread(*value, source, &names, strict))
                };
                let (read, read_strict) = (over(false), over(true));
                names.add(
                    &name,
                    Setting {
                        at,
                        read,
                        read_strict,
                        value: None,
                    },
                );
            }
            "command" => {
                // Builtins that set a variable from what they read.
                let Some(words) = command_words(place, source) else {
                    continue;
                };
                let program = normalized_command_name(&words[0]);
                if !matches!(
                    program.as_str(),
                    "read" | "mapfile" | "readarray" | "getopts" | "printf"
                ) {
                    continue;
                }
                let unread_here = Setting {
                    at,
                    read: false,
                    read_strict: false,
                    value: None,
                };
                let mut next_is_name = false;
                for word in &words[1..] {
                    let word = shell_word(word);
                    if next_is_name || (program != "printf" && is_name(&word)) {
                        names.add(&word, unread_here.clone());
                    }
                    next_is_name = word == "-v" || (program == "read" && word == "-a");
                }
                for implied in ["REPLY", "MAPFILE", "OPTARG"] {
                    names.add(implied, unread_here.clone());
                }
            }
            _ => {}
        }
    }
    let mut loops = Vec::new();
    for kind in [
        "for_statement",
        "c_style_for_statement",
        "while_statement",
        "select_statement",
    ] {
        collect_nodes_of_kind(root, kind, &mut loops, 0);
    }
    names.loops = loops
        .into_iter()
        .map(|node| (node.start_byte(), node.end_byte()))
        .collect();
    names.functions = function_bindings(root, source, &names);
    names
}

/// The text of a value the line writes out, or the program's name a value
/// that looks a program up (`$(command -v python3)`) holds the path of.
fn literal_value(value: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    let text = node_text(value, source);
    if !text.contains(['$', '`']) {
        return Some(shell_word(&text));
    }
    let mut substitutions = Vec::new();
    collect_nodes_of_kind(value, "command_substitution", &mut substitutions, 0);
    let [only] = substitutions.as_slice() else {
        return None;
    };
    if shell_word(&text) != node_text(*only, source) {
        return None;
    }
    looked_up_program(*only, source)
}

/// The program a substitution looks up: `command -v NAME`, `which NAME`,
/// `type -P NAME`, NAME written out.
fn looked_up_program(substitution: tree_sitter::Node<'_>, source: &[u8]) -> Option<String> {
    let mut commands = Vec::new();
    collect_all_commands(substitution, &mut commands, 0);
    let [only] = commands.as_slice() else {
        return None;
    };
    let words: Vec<String> = command_words(*only, source)?
        .iter()
        .map(|word| shell_word(word))
        .collect();
    let named = match words
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["command", "-v", name] | ["which", name] | ["type", "-P" | "-p", name] => {
            (*name).to_owned()
        }
        _ => return None,
    };
    (!named.is_empty() && !named.contains(['$', '`', ' '])).then_some(named)
}

/// The functions the line defines: each body's span, and whether every
/// call of it hands it only words the line shows (its `$1`, `$@` are read
/// then).
fn function_bindings(
    root: tree_sitter::Node<'_>,
    source: &[u8],
    names: &Names,
) -> Vec<(usize, usize, bool)> {
    let mut definitions = Vec::new();
    collect_nodes_of_kind(root, "function_definition", &mut definitions, 0);
    let mut commands = Vec::new();
    collect_all_commands(root, &mut commands, 0);
    definitions
        .into_iter()
        .filter_map(|definition| {
            let name = node_text(definition.child_by_field_name("name")?, source);
            let body = definition.child_by_field_name("body")?;
            let calls: Vec<_> = commands
                .iter()
                .filter(|command| {
                    command_words(**command, source)
                        .is_some_and(|words| shell_word(&words[0]) == name)
                })
                .collect();
            let read = !calls.is_empty()
                && calls.iter().all(|call| {
                    command_arguments(**call)
                        .into_iter()
                        .all(|argument| !unread(argument, source, names, true))
                });
            Some((body.start_byte(), body.end_byte(), read))
        })
        .collect()
}

fn collect_setting_places<'tree>(
    node: tree_sitter::Node<'tree>,
    places: &mut Vec<tree_sitter::Node<'tree>>,
    depth: usize,
) {
    if depth > MAX_AST_DEPTH {
        return;
    }
    if matches!(
        node.kind(),
        "variable_assignment" | "for_statement" | "select_statement" | "command" | "expansion"
    ) {
        places.push(node);
    }
    let mut cursor = node.walk();
    let children: Vec<_> = node.children(&mut cursor).collect();
    for child in children {
        collect_setting_places(child, places, depth + 1);
    }
}

/// Whether `node` (a word, a string, a value) holds a part whose value the
/// line does not show. Where `strict`, a folder the guard knows only by its
/// meaning (the working folder, a folder query) is not read: what a
/// program writes, deletes or runs as code has to be text the line shows.
fn unread(node: tree_sitter::Node<'_>, source: &[u8], names: &Names, strict: bool) -> bool {
    match node.kind() {
        "command_substitution" => !substitution_is_read(node, source, names, strict),
        // Its value is the path of a pipe from or to a command read on
        // its own; what flows through it is unread where it is run as code.
        "process_substitution" => false,
        "simple_expansion" | "expansion" => expansion_unread(node, source, names, strict),
        "arithmetic_expansion" => {
            let mut inside = Vec::new();
            collect_nodes_of_kind(node, "command_substitution", &mut inside, 0);
            !inside.is_empty()
        }
        "heredoc_body" | "heredoc_redirect" | "herestring_redirect" | "file_redirect" => false,
        _ => {
            let mut cursor = node.walk();
            let children: Vec<_> = node.children(&mut cursor).collect();
            children.iter().enumerate().any(|(at, child)| {
                unread(*child, source, names, strict)
                    && !(strict
                        && !unread(*child, source, names, false)
                        && names_a_path_inside(&children[at + 1..], source))
            })
        }
    }
}

/// What follows a folder the guard knows by its meaning names a path
/// inside it (`$PWD/out`, `"$R/Cargo.toml"`): the same place as that path
/// written from the folder. The folder itself, or a path that climbs out of
/// it with `..`, is not.
fn names_a_path_inside(rest: &[tree_sitter::Node<'_>], source: &[u8]) -> bool {
    let text: String = rest
        .iter()
        .take_while(|part| {
            !matches!(
                part.kind(),
                "simple_expansion" | "expansion" | "command_substitution" | "process_substitution"
            )
        })
        .map(|part| node_text(*part, source))
        .collect::<String>()
        .replace('"', "");
    let all: String = rest.iter().map(|part| node_text(*part, source)).collect();
    text.starts_with('/')
        && text
            .split('/')
            .any(|part| !part.is_empty() && part != "." && part != "..")
        && !all.replace('"', "").split('/').any(|part| part == "..")
}

/// `$NAME`, `${NAME}`, `${NAME:-default}`, `${#NAME}`, `${!NAME}`.
fn expansion_unread(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    names: &Names,
    strict: bool,
) -> bool {
    let text = node_text(node, source);
    let body = text.strip_prefix('$').unwrap_or(&text);
    let (inner, braced) = match body.strip_prefix('{') {
        Some(inner) => (inner.strip_suffix('}').unwrap_or(inner), true),
        None => (body, false),
    };
    if braced && inner.starts_with('!') {
        return true;
    }
    let length = braced && inner.len() > 1 && inner.starts_with('#');
    let inner = if length { &inner[1..] } else { inner };
    let name: String = match inner.chars().next() {
        Some(c) if c == '_' || c.is_ascii_alphabetic() => inner
            .chars()
            .take_while(|c| *c == '_' || c.is_ascii_alphanumeric())
            .collect(),
        Some(c) => c.to_string(),
        None => return true,
    };
    let name_unread = match name.as_str() {
        "?" | "$" | "!" | "#" | "-" => false,
        _ => !length && !names.is_read(&name, node.start_byte(), strict),
    };
    if name_unread {
        return true;
    }
    // A default or a pattern may hold a substitution of its own.
    let mut cursor = node.walk();
    let parts: Vec<_> = node
        .named_children(&mut cursor)
        .filter(|child| !matches!(child.kind(), "variable_name" | "special_variable_name"))
        .collect();
    parts
        .into_iter()
        .any(|part| unread(part, source, names, strict))
}

/// A substitution whose value the line shows: it only prints text written
/// out (`$(cat <<'EOF' ...)`, `$(echo text)`), or a value no line can steer
/// (the date, a count or a sequence of numbers, the user, the host or the
/// system's name, a new temporary file's path). Not `strict`, a folder the
/// guard's folder queries know or a program's path looked up by a name
/// written out is read too.
fn substitution_is_read(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    names: &Names,
    strict: bool,
) -> bool {
    let mut commands = Vec::new();
    collect_all_commands(node, &mut commands, 0);
    let [only] = commands.as_slice() else {
        return false;
    };
    let Some(words) = command_words(*only, source) else {
        return false;
    };
    if command_arguments(*only)
        .into_iter()
        .any(|argument| unread(argument, source, names, strict))
    {
        return false;
    }
    let mut redirects = Vec::new();
    for kind in ["file_redirect", "herestring_redirect"] {
        collect_nodes_of_kind(node, kind, &mut redirects, 0);
    }
    let mut heredocs = Vec::new();
    collect_nodes_of_kind(node, "heredoc_redirect", &mut heredocs, 0);
    let plain = redirects.is_empty() && heredocs.is_empty();
    match normalized_command_name(&words[0]).as_str() {
        "echo" | "printf" | "date" | "nproc" | "whoami" | "hostname" | "uname" | "getconf"
        | "seq" | "mktemp" => plain,
        "cat" => {
            words.len() == 1
                && redirects.is_empty()
                && heredocs.len() == 1
                && heredoc_is_literal(heredocs[0], source)
        }
        "id" => {
            plain
                && words[1..].iter().all(|word| {
                    matches!(
                        shell_word(word).as_str(),
                        "-u" | "-g" | "-un" | "-gn" | "-n"
                    )
                })
        }
        // A folder the guard's folder queries know (the project's root, a
        // package tool's folder), or a program's path looked up by a name
        // written out.
        name => {
            !strict
                && plain
                && (looked_up_program(node, source).is_some()
                    || is_folder_printer(
                        name,
                        &words[1..]
                            .iter()
                            .map(|word| shell_word(word))
                            .collect::<Vec<_>>(),
                    ))
        }
    }
}

/// A here-document whose delimiter is quoted: its body is handed over as
/// written.
fn heredoc_is_literal(heredoc: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    let mut starts = Vec::new();
    collect_nodes_of_kind(heredoc, "heredoc_start", &mut starts, 0);
    starts
        .first()
        .is_some_and(|start| node_text(*start, source).contains(['\'', '"', '\\']))
}

/// A here-document or a here-string a command reads holds a part not read,
/// or its input is a file a part not read names.
fn input_unread(command: tree_sitter::Node<'_>, source: &[u8], names: &Names) -> bool {
    // The redirects on the command itself, and those the grammar hangs on an
    // enclosing statement whose owner ([`heredoc_owner`]) is this command:
    // `cd x && python3 - <<EOF` hangs the here-document on the whole list.
    let mut owners = vec![command];
    let mut node = command;
    while let Some(parent) = node.parent() {
        match parent.kind() {
            "redirected_statement" => owners.push(parent),
            "list" | "pipeline" => {}
            _ => break,
        }
        node = parent;
    }
    owners.into_iter().any(|owner| {
        let mut cursor = owner.walk();
        let children: Vec<_> = owner
            .children(&mut cursor)
            .filter(|child| {
                owner.id() == command.id()
                    || heredoc_owner(*child).is_some_and(|reader| reader.id() == command.id())
            })
            .collect();
        children.into_iter().any(|child| match child.kind() {
            "heredoc_redirect" => {
                !heredoc_is_literal(child, source) && {
                    let mut bodies = Vec::new();
                    collect_nodes_of_kind(child, "heredoc_body", &mut bodies, 0);
                    bodies.into_iter().any(|body| {
                        let mut cursor = body.walk();
                        let parts: Vec<_> = body.named_children(&mut cursor).collect();
                        parts
                            .into_iter()
                            .any(|part| unread(part, source, names, true))
                    })
                }
            }
            "herestring_redirect" => {
                let mut cursor = child.walk();
                let parts: Vec<_> = child.named_children(&mut cursor).collect();
                parts
                    .into_iter()
                    .any(|part| unread(part, source, names, true))
            }
            "file_redirect" => {
                let operator = redirect_operator(child, source);
                operator.contains('<')
                    && !operator.contains("<&")
                    && child
                        .child_by_field_name("destination")
                        .is_some_and(|target| {
                            unread(target, source, names, true)
                                || holds_process_substitution(target)
                        })
            }
            _ => false,
        })
    })
}

/// The command reads its input from a pipe whose writer is not an `echo`
/// or a `printf` of text the line shows.
fn input_from_unread_pipe(command: tree_sitter::Node<'_>, source: &[u8], names: &Names) -> bool {
    let unit = command
        .parent()
        .filter(|parent| parent.kind() == "redirected_statement")
        .unwrap_or(command);
    let Some(pipeline) = unit.parent().filter(|parent| parent.kind() == "pipeline") else {
        return false;
    };
    let mut cursor = pipeline.walk();
    let stages: Vec<_> = pipeline.named_children(&mut cursor).collect();
    let Some(at) = stages.iter().position(|stage| *stage == unit) else {
        return false;
    };
    let Some(writer) = at.checked_sub(1).map(|before| stages[before]) else {
        return false;
    };
    if writer.kind() != "command" {
        return true;
    }
    let prints = command_words(writer, source).is_some_and(|words| {
        matches!(
            normalized_command_name(&words[0]).as_str(),
            "echo" | "printf"
        )
    });
    !prints
        || command_arguments(writer)
            .into_iter()
            .any(|argument| unread(argument, source, names, true))
}

/// The unread part of one simple command, by where it stands.
fn command_unread(
    command: tree_sitter::Node<'_>,
    source: &[u8],
    names: &Names,
    depth: u8,
) -> Option<&'static str> {
    let words = command_words(command, source)?;
    let mut nodes = vec![command.child_by_field_name("name")?];
    nodes.extend(command_arguments(command));
    if nodes.len() != words.len() {
        return None;
    }
    let flags: Vec<bool> = nodes
        .iter()
        .map(|node| unread(*node, source, names, true))
        .collect();
    let any_unread = flags.iter().any(|flag| *flag);
    let Some(effective) = effective_command_words(&words, 0) else {
        return any_unread.then_some(UNREAD_WRAPPER);
    };
    let offset = words.len() - effective.len();
    // A value a wrapper hands on (`env NAME=VALUE`) is a variable like any
    // other, unread where it is used; one that changes what loads is held.
    let wrapper_unread = words[..offset]
        .iter()
        .zip(&flags[..offset])
        .any(|(word, unread)| {
            *unread
                && match word.split_once('=') {
                    Some((name, _)) if is_name(name) => is_loading_setting(name),
                    _ => true,
                }
        });
    if wrapper_unread {
        return Some(UNREAD_WRAPPER);
    }
    let program = &effective[0];
    // The program is read by its name: written out; or a path ending in its
    // name written out under a folder the guard reads, including one it
    // knows by its meaning as the folder queries (`"$(npm bin)/jest"`); or a
    // variable the line sets to one program written out, or to the path of
    // one it looks up (`X=$(command -v python3); "$X"`).
    let written = shell_word(program);
    let name = if !written.contains(['$', '`'])
        || (runtime_word_ends_in_literal_program(program)
            && !unread(nodes[offset], source, names, false))
    {
        normalized_command_name(program)
    } else {
        let programs: Vec<String> = sole_variable_values(nodes[offset], source, names, false)
            .unwrap_or_default()
            .iter()
            .filter_map(|value| value.split_whitespace().next().map(normalized_command_name))
            .collect();
        match programs.as_slice() {
            [first, rest @ ..] if rest.iter().all(|other| other == first) => first.clone(),
            _ => return Some(UNREAD_PROGRAM),
        }
    };
    let arguments = &effective[1..];
    let argument_flags = &flags[offset + 1..];

    if matches!(name.as_str(), "eval" | "trap" | "alias") {
        return any_unread.then_some(UNREAD_CODE);
    }
    match command_code_input(effective) {
        CodeInput::Argument(code) => {
            if let Some(place) = arguments
                .iter()
                .position(|argument| shell_literal_word(argument) == code)
            {
                // Code given inline (`-c`, `-e`) is read as text; a script's file
                // is read by its name, as a program's is.
                let inline = place > 0 && arguments[place - 1].starts_with('-');
                let word = nodes[offset + 1 + place];
                let unread_code = if inline {
                    argument_flags[place]
                } else {
                    unread(word, source, names, false)
                };
                if unread_code || holds_process_substitution(word) {
                    return Some(UNREAD_CODE);
                }
                // A shell's line written out is read as a line of its own,
                // in a shell that sees none of this line's variables, its
                // positional parameters the words after it. What it does
                // with them is that reading's to say.
                if is_shell_name(&name) && shell_inline_code_place(effective) == Some(place + 1) {
                    if depth >= DEPTH {
                        return Some(UNREAD_CODE);
                    }
                    let positional: Vec<bool> = argument_flags[place + 1..]
                        .iter()
                        .map(|unread| !unread)
                        .collect();
                    let lines = handed_lines(nodes[offset + 1 + place], source, names);
                    return lines
                        .iter()
                        .find_map(|line| unread_part_at(line, depth + 1, positional.clone()))
                        .or_else(|| {
                            argument_flags[..place]
                                .iter()
                                .any(|unread| *unread)
                                .then_some(UNREAD_ARGUMENT)
                        });
                }
            }
        }
        CodeInput::Stdin => {
            if input_unread(command, source, names)
                || input_from_unread_pipe(command, source, names)
            {
                return Some(UNREAD_CODE);
            }
        }
        CodeInput::None => {}
    }
    // Only a plain expansion (`$T`, `"${T}"`, `${T:-x}`) can be data. A command
    // substitution, a backtick or a process substitution in a place a known
    // program takes as data runs before the program does, and is held unless
    // it only prints text the line writes out (`cargo test "$(curl x | sh)"`,
    // `pytest -k "\`id\`"`, `git commit -m "$(<~/.aws/credentials)"`).
    let data = data_arguments(&name, arguments);
    if nodes[offset + 1..]
        .iter()
        .zip(&data)
        .any(|(node, data)| *data && runs_something(*node, source, names))
    {
        return Some(UNREAD_ARGUMENT);
    }
    if !argument_flags.iter().any(|flag| *flag) {
        return None;
    }
    // Words a known program only takes as data (a test filter, a commit's
    // message, a name it gives a thing): unread there, they name no program
    // to run and no path to write or delete.
    if argument_flags
        .iter()
        .zip(&data)
        .all(|(unread, data)| !unread || *data)
    {
        return None;
    }
    match name.as_str() {
        "source" | "." => Some(UNREAD_CODE),
        "xargs" | "gxargs" | "parallel" => xargs_unread(arguments, argument_flags),
        "find" => arguments
            .iter()
            .any(|argument| {
                matches!(
                    shell_word(argument).as_str(),
                    "-delete"
                        | "-exec"
                        | "-execdir"
                        | "-ok"
                        | "-okdir"
                        | "-fprint"
                        | "-fprint0"
                        | "-fprintf"
                        | "-fls"
                )
            })
            .then_some(UNREAD_ARGUMENT),
        _ if only_reads(&name, arguments, argument_flags) => None,
        _ => Some(UNREAD_ARGUMENT),
    }
}

/// The word holds a process substitution, or a command substitution (a
/// backtick too) that does more than print text the line writes out
/// (`$(cat <<'EOF' ...)`, `$(echo text)`): something runs to make it.
fn runs_something(node: tree_sitter::Node<'_>, source: &[u8], names: &Names) -> bool {
    let mut found = Vec::new();
    collect_nodes_of_kind(node, "command_substitution", &mut found, 0);
    holds_process_substitution(node)
        || found.into_iter().any(|substitution| {
            let mut commands = Vec::new();
            collect_all_commands(substitution, &mut commands, 0);
            let prints_text = commands.len() == 1
                && command_words(commands[0], source).is_some_and(|words| {
                    matches!(
                        normalized_command_name(&words[0]).as_str(),
                        "echo" | "printf" | "cat"
                    )
                });
            !(prints_text && substitution_is_read(substitution, source, names, true))
        })
}

/// The word holds a process substitution: run as code, what flows through
/// it is unread.
fn holds_process_substitution(node: tree_sitter::Node<'_>) -> bool {
    let mut found = Vec::new();
    collect_nodes_of_kind(node, "process_substitution", &mut found, 0);
    !found.is_empty()
}

/// The lines a shell's `-c` word hands it, as the outer shell expands
/// them: written out in single quotes; one for each value written out of a
/// sole variable (`sh -c "$C"`); else the text with each variable that has
/// one value written out put in its place.
fn handed_lines(word: tree_sitter::Node<'_>, source: &[u8], names: &Names) -> Vec<String> {
    let text = node_text(word, source);
    if text.trim_start().starts_with('\'') {
        return vec![shell_literal_word(&text)];
    }
    if let Some(values) = sole_variable_values(word, source, names, true) {
        return values;
    }
    let inner = shell_literal_word(&text);
    let chars: Vec<char> = inner.chars().collect();
    let mut out = String::with_capacity(inner.len());
    let mut at = 0;
    while at < chars.len() {
        if chars[at] == '$' {
            let braced = chars.get(at + 1) == Some(&'{');
            let start = at + 1 + usize::from(braced);
            let mut end = start;
            while end < chars.len() && (chars[end] == '_' || chars[end].is_ascii_alphanumeric()) {
                end += 1;
            }
            let name: String = chars[start..end].iter().collect();
            let closes = !braced || chars.get(end) == Some(&'}');
            if is_name(&name) && closes {
                if let Some([value]) = names.values(&name, word.start_byte(), true).as_deref() {
                    out.push_str(value);
                    at = end + usize::from(braced);
                    continue;
                }
            }
        }
        out.push(chars[at]);
        at += 1;
    }
    vec![out]
}

/// Which of `arguments` a known program takes only as data: a test filter
/// (`cargo test FILTER` and what follows its `--`, `pytest -k`/`-m`, `go test
/// -run`, `jest -t`), a commit's or a pull request's text, a name or a label
/// it gives a thing (`--name`). None of these names a program to run or a
/// path to write or delete. Anything else is not data, a path the program
/// reads or builds in included.
fn data_arguments(name: &str, arguments: &[String]) -> Vec<bool> {
    let words: Vec<String> = arguments.iter().map(|word| shell_word(word)).collect();
    let mut data = vec![false; words.len()];
    // `python3 -m pytest ...` is pytest.
    if name.starts_with("python")
        && words.len() >= 2
        && words[0] == "-m"
        && matches!(words[1].as_str(), "pytest" | "unittest")
    {
        let inner = data_arguments(&words[1], &arguments[2..]);
        data[2..].copy_from_slice(&inner);
        return data;
    }
    // `npx jest ...` is jest.
    if matches!(name, "npx" | "pnpx" | "bunx") {
        if let Some(at) = words.iter().position(|word| !word.starts_with('-')) {
            let inner = data_arguments(&normalized_command_name(&words[at]), &arguments[at + 1..]);
            data[at + 1..].copy_from_slice(&inner);
        }
        return data;
    }
    let value_flags: &[&str] = match name {
        "cargo" => &["-p", "--package", "--test", "--features", "-F", "--bench"],
        "pytest" | "py.test" | "unittest" => &["-k", "-m"],
        "go" => &["-run", "-bench", "-skip"],
        "jest" | "vitest" => &["-t", "--testNamePattern"],
        "git" => &["-m", "--message"],
        "gh" => &["--title", "-t", "--body", "-b", "--name", "--label", "-l"],
        "docker" | "podman" | "kubectl" | "helm" | "npm" | "pnpm" | "yarn" => &["--name"],
        _ => return data,
    };
    for (at, word) in words.iter().enumerate() {
        if value_flags.contains(&word.as_str()) && at + 1 < data.len() {
            data[at + 1] = true;
        }
        if let Some((flag, _)) = word.split_once('=') {
            if flag.starts_with("--") && value_flags.contains(&flag) {
                data[at] = true;
            }
        }
    }
    // `cargo test FILTER -- ARGS`: the filter and the test binary's own
    // arguments are data; a flag's value is not, unless listed above.
    if name == "cargo" {
        const TAKES_VALUE: &[&str] = &[
            "--manifest-path",
            "--target-dir",
            "--config",
            "--bin",
            "--example",
            "--target",
            "-j",
            "--jobs",
            "--profile",
            "-Z",
            "--color",
            "--message-format",
            "-p",
            "--package",
            "--test",
            "--features",
            "-F",
            "--bench",
            "--exclude",
        ];
        if let Some(sub) = words.iter().position(|word| !word.starts_with('-')) {
            let nextest = words[sub] == "nextest";
            if matches!(words[sub].as_str(), "test" | "t" | "bench") || nextest {
                let mut after_dashes = false;
                for at in sub + 1..words.len() {
                    let word = &words[at];
                    if after_dashes {
                        data[at] = true;
                    } else if word == "--" {
                        after_dashes = true;
                    } else if !word.starts_with('-')
                        && !TAKES_VALUE.contains(&words[at - 1].as_str())
                        && !(nextest && at == sub + 1)
                    {
                        data[at] = true;
                    }
                }
            }
        }
    }
    data
}

/// The value of a word that is one variable the line sets to text written
/// out (`p=python3; $p x.py`).
fn sole_variable_values(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    names: &Names,
    strict: bool,
) -> Option<Vec<String>> {
    let text = shell_word(&node_text(node, source));
    let name = text
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
        .or_else(|| text.strip_prefix('$'))?;
    if !is_name(name) {
        return None;
    }
    names.values(name, node.start_byte(), strict)
}

/// xargs adds the words it reads to the program it runs: held unless that
/// program only reads or prints.
fn xargs_unread(arguments: &[String], flags: &[bool]) -> Option<&'static str> {
    const WITH_VALUE: &[&str] = &[
        "-n",
        "-L",
        "-l",
        "-I",
        "-d",
        "-P",
        "-s",
        "-a",
        "-E",
        "--max-args",
        "--max-lines",
        "--replace",
        "--delimiter",
        "--max-procs",
        "--max-chars",
        "--arg-file",
        "--eof",
        "-j",
        "--jobs",
    ];
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        let word = shell_word(argument);
        if word == "--" {
            index += 1;
            break;
        }
        if WITH_VALUE.contains(&word.as_str()) {
            if flags[index] || flags.get(index + 1).copied().unwrap_or(false) {
                return Some(UNREAD_XARGS);
            }
            index += 2;
            continue;
        }
        if word.starts_with('-') {
            if flags[index] {
                return Some(UNREAD_XARGS);
            }
            index += 1;
            continue;
        }
        break;
    }
    let program = arguments.get(index)?;
    if flags[index] {
        return Some(UNREAD_PROGRAM);
    }
    let rest = &arguments[index + 1..];
    // Every word it adds is unread; mark the program's own words so.
    let rest_flags = vec![true; rest.len()];
    (!only_reads(&normalized_command_name(program), rest, &rest_flags)).then_some(UNREAD_XARGS)
}

/// Programs that only read, print or test, whatever words they are handed:
/// an unread word there decides nothing that runs, writes, deletes, stops
/// or sends.
fn only_reads(name: &str, arguments: &[String], flags: &[bool]) -> bool {
    let words: Vec<String> = arguments
        .iter()
        .map(|argument| shell_word(argument))
        .collect();
    let subcommand = || words.iter().find(|word| !word.starts_with('-')).cloned();
    match name {
        "echo" | "printf" | "cat" | "tac" | "less" | "more" | "head" | "tail" | "grep"
        | "egrep" | "fgrep" | "rg" | "ag" | "ack" | "ls" | "tree" | "wc" | "cut" | "tr" | "nl"
        | "column" | "diff" | "cmp" | "comm" | "file" | "stat" | "du" | "df" | "realpath"
        | "readlink" | "basename" | "dirname" | "which" | "type" | "whereis" | "test" | "["
        | "[[" | "true" | "false" | ":" | "cd" | "pushd" | "popd" | "pwd" | "date" | "sleep"
        | "seq" | "jq" | "printenv" | "id" | "whoami" | "uname" | "hostname" | "ps" | "pgrep"
        | "lsof" | "read" | "mapfile" | "readarray" | "local" | "export" | "declare"
        | "typeset" | "readonly" | "shift" | "unset" | "getopts" | "wait" | "return" | "exit"
        | "break" | "continue" | "md5sum" | "sha1sum" | "sha256sum" | "sha512sum" | "b2sum"
        | "cksum" | "xxd" | "od" | "hexdump" | "strings" | "fold" | "fmt" | "rev" | "paste"
        | "join" | "let" => true,
        // `sort -o` and `uniq IN OUT` write a file.
        "sort" => !words.iter().any(|word| {
            word.starts_with("--output") || (word.starts_with("-o") && !word.starts_with("--"))
        }),
        "uniq" => words.iter().filter(|word| !word.starts_with('-')).count() <= 1,
        "git" => git_only_reads(&words, flags),
        "gh" => gh_only_reads(&words),
        "docker" | "podman" => subcommand().is_some_and(|sub| {
            matches!(
                sub.as_str(),
                "ps" | "images"
                    | "logs"
                    | "inspect"
                    | "version"
                    | "info"
                    | "stats"
                    | "top"
                    | "port"
                    | "history"
            )
        }),
        "kubectl" => subcommand().is_some_and(|sub| {
            matches!(
                sub.as_str(),
                "get" | "describe" | "logs" | "explain" | "version"
            )
        }),
        _ => false,
    }
}

/// gh asking GitHub what it holds: a view, a list, a diff, checks or
/// status of a pull request, an issue, a run, a release or a repository,
/// or an API request that sends no method but GET and no fields.
fn gh_only_reads(words: &[String]) -> bool {
    let plain: Vec<&str> = words
        .iter()
        .map(String::as_str)
        .filter(|word| !word.starts_with('-'))
        .collect();
    match plain.as_slice() {
        ["api", ..] => !words.iter().any(|word| {
            let flag = word.split('=').next().unwrap_or(word);
            matches!(
                flag,
                "-X" | "--method" | "-f" | "-F" | "--field" | "--raw-field" | "--input"
            ) || (word.starts_with("-X") && word.len() > 2)
                || (word.starts_with("-f") && word.len() > 2)
                || (word.starts_with("-F") && word.len() > 2)
        }),
        ["pr" | "issue" | "run" | "release" | "repo" | "workflow", action, ..] => {
            matches!(*action, "view" | "list" | "diff" | "checks" | "status")
        }
        _ => false,
    }
}

/// git with a subcommand that only reads, or a commit or a tag whose only
/// unread words are its message.
fn git_only_reads(words: &[String], flags: &[bool]) -> bool {
    let mut index = 0;
    while let Some(word) = words.get(index) {
        match word.as_str() {
            // A setting given on the line may name a program to run.
            "-c" | "--config-env" => return false,
            // A folder the line does not show decides which repository and
            // which settings (hooks, a pager) git uses.
            "-C" | "--git-dir" | "--work-tree" | "--namespace" => {
                if flags.get(index + 1).copied().unwrap_or(true) {
                    return false;
                }
                index += 2;
            }
            _ if word.starts_with('-') => index += 1,
            _ => break,
        }
    }
    let Some(sub) = words.get(index) else {
        return true;
    };
    if flags.get(index).copied().unwrap_or(true) {
        return false;
    }
    let rest = index + 1;
    match sub.as_str() {
        "status" | "log" | "show" | "diff" | "rev-parse" | "ls-files" | "ls-tree" | "blame"
        | "grep" | "describe" | "shortlog" | "rev-list" | "cat-file" | "merge-base"
        | "name-rev" | "reflog" | "whatchanged" | "cherry" | "range-diff" => true,
        "commit" | "tag" => {
            let mut message_next = false;
            words[rest..]
                .iter()
                .zip(&flags[rest..])
                .all(|(word, unread)| {
                    let message = message_next;
                    message_next = matches!(word.as_str(), "-m" | "--message" | "-F" | "--file");
                    !*unread
                        || message
                        || word.starts_with("--message=")
                        || word.starts_with("--file=")
                })
        }
        _ => false,
    }
}
