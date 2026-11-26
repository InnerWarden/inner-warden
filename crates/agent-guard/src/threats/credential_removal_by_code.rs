//! Inline code that removes or overwrites the account's keys or credential
//! store, read as the shell's `rm` of the same path is
//! ([`super::destructive_rm_credentials`]).
//!
//! Measured 2026-11-24 against main b52291b, each was allowed while `rm` of
//! the same path was refused: `lua -e 'os.remove("/home/u/.ssh/id_ed25519")'`,
//! Python's `os.remove`, `os.unlink`, `shutil.rmtree` and `Path(...).unlink()`,
//! Ruby's `File.delete` and `FileUtils.rm_rf`, Perl's and PHP's `unlink` and
//! Node's `unlinkSync` and `rmSync`, given the key or the store by path or
//! through the home by name.
//!
//! A statement that calls something that removes or writes over a file is
//! read with the strings it holds (and what a name it uses was given, one
//! assignment back): each string, and each run of them joined as a path
//! under the home when the statement names the home, is a target read by
//! the same test the shell's `rm` uses. What holds no key stays a
//! cleanup: `os.remove('build/out.o')`, `os.remove(os.path.expanduser('~/.ssh/known_hosts'))`.

use super::rm_target_is_credential_store;
use std::sync::LazyLock;

/// A command word that is an interpreter handed inline code.
static INLINE_CODE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"(?is)\b(?:python[\d.]*|pypy[\d.]*|node|nodejs|bun|deno|ruby|perl[\d.]*|php[\d.]*|lua(?:jit)?[\d.]*)\b.{0,200}?(?:\s-[a-z]*[cer]\b|<<<)",
    )
    .expect("static inline code regex")
});

/// Calls that remove a file or a tree, or open one to write over it, in
/// Python, Lua, Ruby, Perl, PHP and JavaScript.
static REMOVES_OR_WRITES_OVER: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(concat!(
        r"\bos\.(?:remove|unlink|removedirs|rmdir|truncate)\b|\bshutil\.rmtree\b|\brmtree\b|\bremove_tree\b",
        r"|\bunlink\b|\.unlink\s*\(|\bunlinkSync\b|\brmSync\b|\brmdirSync\b|\btruncateSync\b|\brmdir\b",
        r"|\bfs\.(?:promises\.)?(?:rm|unlink|truncate|writeFile)\b|\bfsPromises\.(?:rm|unlink|writeFile)\b",
        r"|\bFile\.(?:delete|unlink|truncate|write)\b|\bFileUtils\.(?:rm\w*|remove\w*)\b|\bDeno\.(?:remove|writeTextFile|writeFile)\b",
        r"|\.write_(?:text|bytes)\s*\(|\bwriteFileSync\b|\bfile_put_contents\b",
        r"|\bos\.(?:rename|renames|replace)\b|\bshutil\.move\b|\.rename\s*\(|\brename\b|\brenameSync\b",
        r"|\bFileUtils\.(?:mv|move)\b|\bDeno\.rename\b",
        r#"|\bio\.open\s*\([^)]*,\s*["']w"#,
        r#"|\bopen\s*\([^()]*(?:\([^()]*\)[^()]*)*,\s*(?:mode\s*=\s*)?["'][rbt]*w"#,
        r#"|\bopen\s*\(?\s*(?:my\s+)?[$\w]+\s*,\s*["']\s*>"#,
    ))
    .expect("static removal regex")
});

/// The home named rather than written: `os.path.expanduser('~')`,
/// `Path.home()`, `os.environ['HOME']`, `os.getenv("HOME")`, `os.homedir()`,
/// `process.env.HOME`, `ENV['HOME']`, `Dir.home`, `$ENV{HOME}`, PHP's
/// `getenv('HOME')` and `$_SERVER['HOME']`.
static HOME_BY_NAME: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"expanduser\(\s*\\?["']~/?\\?["']\s*\)|\bPath\.home\(\s*\)|\benviron\[\s*\\?["']HOME\\?["']\s*\]|\bgetenv\(\s*\\?["']HOME\\?["']\s*\)|\bhomedir\(\s*\)|\bprocess\.env\.HOME\b|\bENV\[\s*\\?["']HOME\\?["']\s*\]|\bDir\.home\b|\$ENV\{\s*HOME\s*\}|\$_SERVER\[\s*\\?["']HOME\\?["']\s*\]|\benviron\.get\(\s*\\?["']HOME\\?["']"#,
    )
    .expect("static home regex")
});

/// A string in single, double or back quotes, each kind read apart: code
/// handed in single quotes holds its strings in double quotes.
static STRINGS: LazyLock<[regex::Regex; 3]> = LazyLock::new(|| {
    [r"'([^'\n]*)'", r#""([^"\n]*)""#, r"`([^`\n]*)`"]
        .map(|re| regex::Regex::new(re).expect("static string regex"))
});

/// An assignment that starts a statement: `p = ...`, `local p = ...`,
/// `my $p = ...`, `const p = ...`.
static ASSIGNMENT: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^\s*(?:(?:local|my|our|const|let|var)\s+)?\$?([A-Za-z_]\w*)\s*=([^=~].*)$")
        .expect("static assignment regex")
});

/// Python's `__import__('os')` and `importlib.import_module('os')` (by
/// any name the module is given), Lua's `require("os")` and `require "os"`:
/// the module itself.
static MODULE_BY_CALL: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"\b(?:__import__|(?:[A-Za-z_]\w*\.)?import_module)\s*\(\s*\\?["']([\w.]+)\\?["']\s*\)|\brequire\s*\(?\s*\\?["'](?:node:)?([\w./-]+)\\?["']\s*\)?"#,
    )
    .expect("static module call regex")
});

/// `getattr(os, 'remove')`: the function by name.
static GETATTR: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"\bgetattr\s*\(\s*([A-Za-z_][\w.]*)\s*,\s*\\?["'](\w+)\\?["']\s*\)"#)
        .expect("static getattr regex")
});

/// Python's `import os as o` and `import os.path as p`.
static IMPORT_AS: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\b([A-Za-z_][\w.]*)\s+as\s+([A-Za-z_]\w*)").expect("static import regex")
});

/// Python's `import`, where a statement holds it.
static IMPORT: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"(?:^|[\s'"])import\s+"#).expect("static import word regex")
});

/// Python's `from os import remove, unlink as u`.
static FROM_IMPORT: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\bfrom\s+([A-Za-z_][\w.]*)\s+import\s+\(?([\w\s,]+)\)?")
        .expect("static from import regex")
});

/// A name given another name or a function by its dotted name: `o = os`,
/// `local r = os.remove`, `f = os.unlink`, and Lua's `local ok, o =
/// pcall(require, "os")` once the module is read.
static NAME_GIVEN_NAME: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"(?:^|[\s'"])(?:(?:local|my|our|const|let|var)\s+)?(?:[A-Za-z_]\w*\s*,\s*)?([A-Za-z_]\w*)\s*=\s*(?:x?pcall\s*\(\s*)?([A-Za-z_][\w.]*)\s*\)?\s*$"#,
    )
    .expect("static name given name regex")
});

/// Node's `import('fs/promises')`, the module a dynamic import loads.
static MODULE_BY_IMPORT: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"\bimport\s*\(\s*\\?["'](?:node:)?([\w./-]+)\\?["']\s*\)"#)
        .expect("static dynamic import regex")
});

/// The name a promise's `.then` hands a module to: `fs.promises.then(f =>`,
/// `.then((f) =>`, `.then(function (f)`.
static THEN_NAME: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"\b([A-Za-z_][\w.]*)\.then\(\s*(?:function\s*\(\s*([A-Za-z_]\w*)\s*\)|\(?\s*([A-Za-z_]\w*)\s*\)?\s*=>)",
    )
    .expect("static then regex")
});

/// An ES module's `import {rm, unlink as u} from 'fs/promises'`, `import *
/// as f from 'fs'` and `import f from 'fs'`.
static ESM_IMPORT: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"\bimport\s+(.+?)\s+from\s+\\?["'](?:node:)?([\w./-]+)\\?["']"#)
        .expect("static esm import regex")
});

/// A destructuring of a module or a value: `const {rm, unlink: u} = fs.promises`.
static DESTRUCTURED: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\b(?:const|let|var)\s*\{([^{}]*)\}\s*=\s*([A-Za-z_][\w.]*)")
        .expect("static destructuring regex")
});

/// Strings joined by an operator: `'/home/u/.s' + 'sh/id_rsa'`, Lua's
/// `..`, Perl's and PHP's `.`.
static JOINED_STRINGS: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"\\?["']\s*(?:\+|\.\.?)\s*\\?["']"#).expect("static joined strings regex")
});

/// The rest of a path after the home put in by a format: `f"{home}/.ssh/x"`,
/// `'%s/.ssh/x' % home`, `'{}/.ssh/x'.format(home)`.
static FORMATTED_HOME_TAIL: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?:\}|%s)(/[\w.*/-]+)").expect("static formatted home regex")
});

/// How many times names given names are followed.
const ALIAS_ROUNDS: usize = 4;

/// The code with each module, function and name given another written as
/// what it reaches: `import os as o; o.remove(p)` is read as
/// `os.remove(p)`, `from os import remove; remove(p)` as `os.remove(p)`,
/// `__import__('os').remove(p)` and `getattr(os, 'remove')(p)` as
/// `os.remove(p)`, Lua's `local o = require("os"); o.remove(p)` as
/// `os.remove(p)`.
fn canonical_code(code: &str) -> String {
    let code = crate::shell::lua_builtin_aliases_in_line(code);
    let mut text = MODULE_BY_CALL
        .replace_all(&code, |found: &regex::Captures| {
            // Node's `require('fs/promises')` is `fs.promises`.
            found
                .get(1)
                .or_else(|| found.get(2))
                .map_or(String::new(), |module| module.as_str().replace('/', "."))
        })
        .into_owned();
    text = MODULE_BY_IMPORT
        .replace_all(&text, |found: &regex::Captures| found[1].replace('/', "."))
        .into_owned();
    text = GETATTR.replace_all(&text, "${1}.${2}").into_owned();
    let mut aliases: Vec<(String, String)> = Vec::new();
    for found in THEN_NAME.captures_iter(&text) {
        if let Some(name) = found.get(2).or_else(|| found.get(3)) {
            aliases.push((name.as_str().to_owned(), found[1].to_owned()));
        }
    }
    for found in DESTRUCTURED.captures_iter(&text) {
        for field in found[1].split(',') {
            let field = field.split('=').next().unwrap_or("").trim();
            let (key, name) = field.split_once(':').unwrap_or((field, field));
            let (key, name) = (key.trim(), name.trim());
            if !key.is_empty() && !name.is_empty() {
                aliases.push((name.to_owned(), format!("{}.{key}", &found[2])));
            }
        }
    }
    for statement in text.split([';', '\n']) {
        if let Some(esm) = ESM_IMPORT.captures(statement) {
            let module = esm[2].replace('/', ".");
            let names = esm[1].trim();
            if let Some(star) = names.strip_prefix('*') {
                if let Some(name) = star.trim().strip_prefix("as") {
                    aliases.push((name.trim().to_owned(), module.clone()));
                }
            }
            let (default, braced) = match names.split_once('{') {
                Some((default, braced)) => (default, braced.trim_end_matches('}')),
                None => (names, ""),
            };
            let default = default.trim().trim_end_matches(',').trim();
            if !default.is_empty() && !default.starts_with('*') {
                aliases.push((default.to_owned(), module.clone()));
            }
            for field in braced.split(',') {
                let mut words = field.split_whitespace();
                let (Some(key), alias) = (words.next(), words.nth(1)) else {
                    continue;
                };
                aliases.push((alias.unwrap_or(key).to_owned(), format!("{module}.{key}")));
            }
        } else if let Some(from) = FROM_IMPORT.captures(statement) {
            let module = &from[1];
            for name in from[2].split(',') {
                let mut words = name.split_whitespace();
                let (Some(function), alias) = (words.next(), words.nth(1)) else {
                    continue;
                };
                let alias = alias.unwrap_or(function);
                aliases.push((alias.to_owned(), format!("{module}.{function}")));
            }
        } else if let Some(at) = IMPORT.find(statement) {
            for found in IMPORT_AS.captures_iter(&statement[at.end()..]) {
                aliases.push((found[2].to_owned(), found[1].to_owned()));
            }
        } else if let Some(found) = NAME_GIVEN_NAME.captures(statement) {
            if found[1] != found[2] {
                aliases.push((found[1].to_owned(), found[2].to_owned()));
            }
        }
    }
    for _ in 0..ALIAS_ROUNDS {
        let before = text.clone();
        for (alias, target) in &aliases {
            text = replace_name(&text, alias, target);
        }
        if text == before {
            break;
        }
    }
    text
}

/// `text` with each use of `name` as a name (not a member, not part of
/// a longer name, not where it is given) written as `target`.
fn replace_name(text: &str, name: &str, target: &str) -> String {
    let is_name = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(name) {
        let (before, after) = (&rest[..at], &rest[at + name.len()..]);
        let alone = before
            .chars()
            .next_back()
            .is_none_or(|c| !is_name(c) && c != '.' && c != '$')
            && after.chars().next().is_none_or(|c| !is_name(c));
        let given = {
            let next = after.trim_start();
            next.starts_with('=') && !next.starts_with("==")
        };
        let head = before.trim_end();
        let imported = head.ends_with(" as") || head.ends_with(',') || head.ends_with("import");
        out.push_str(before);
        out.push_str(if alone && !given && !imported {
            target
        } else {
            name
        });
        rest = after;
    }
    out.push_str(rest);
    out
}

/// A name in code.
static NAME: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"[A-Za-z_]\w*").expect("static name regex"));

/// How many strings of one statement are joined into paths.
const MAX_STRINGS: usize = 16;

/// Whether a line hands an interpreter inline code that removes or writes
/// over the account's keys or credential store.
pub(crate) fn interpreter_code_removes_credentials(content: &str) -> bool {
    INLINE_CODE.is_match(content) && code_removes_credentials(content)
}

fn code_removes_credentials(code: &str) -> bool {
    // A single quote inside single-quoted code is written `'\''`.
    let code = canonical_code(&code.replace("'\\''", "'"));
    let statements: Vec<&str> = code.split([';', '\n']).collect();
    let assigned: Vec<(&str, &str)> = statements
        .iter()
        .filter_map(|statement| {
            let found = ASSIGNMENT.captures(statement)?;
            Some((found.get(1)?.as_str(), found.get(2)?.as_str()))
        })
        .collect();
    statements.iter().any(|statement| {
        if !REMOVES_OR_WRITES_OVER.is_match(statement) {
            return false;
        }
        let mut text = (*statement).to_owned();
        for name in NAME.find_iter(statement) {
            for (assigned_name, value) in &assigned {
                if *assigned_name == name.as_str() {
                    text.push(' ');
                    text.push_str(value);
                }
            }
        }
        reads_credential_target(&text)
            || reads_credential_target(&JOINED_STRINGS.replace_all(&text, ""))
    })
}

/// Whether the strings of a statement name a key or a credential store,
/// alone or joined under the home the statement names.
fn reads_credential_target(text: &str) -> bool {
    let strings: Vec<String> = STRINGS
        .iter()
        .flat_map(|string| string.captures_iter(text))
        .filter_map(|found| found.get(1))
        .map(|found| {
            found
                .as_str()
                .replace("$ENV{HOME}", "~")
                .replace("${HOME}", "~")
                .replace("$HOME", "~")
        })
        .filter(|string| !string.is_empty() && !string.contains(char::is_whitespace))
        .take(MAX_STRINGS)
        .collect();
    if strings
        .iter()
        .any(|string| rm_target_is_credential_store(string))
    {
        return true;
    }
    // Strings that build one path: `'/'.join(['/home/u', '.ssh', 'id_rsa'])`.
    let joined = |run: &[String]| {
        let mut path = run[0].trim_end_matches('/').to_owned();
        for part in &run[1..] {
            path.push('/');
            path.push_str(part.trim_matches('/'));
        }
        path
    };
    if (0..strings.len()).any(|from| {
        (from + 2..=strings.len())
            .any(|to| rm_target_is_credential_store(&joined(&strings[from..to])))
    }) {
        return true;
    }
    if !HOME_BY_NAME.is_match(text) {
        return false;
    }
    if FORMATTED_HOME_TAIL
        .captures_iter(text)
        .any(|tail| rm_target_is_credential_store(&format!("~{}", &tail[1])))
    {
        return true;
    }
    let parts: Vec<&str> = strings
        .iter()
        .map(|string| string.trim_matches('/'))
        .filter(|part| !part.is_empty() && !part.eq_ignore_ascii_case("home") && *part != "~")
        .collect();
    (0..parts.len()).any(|from| {
        (from + 1..=parts.len())
            .any(|to| rm_target_is_credential_store(&format!("~/{}", parts[from..to].join("/"))))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_language_removing_a_key_is_read() {
        for line in [
            r#"lua -e 'os.remove("/home/u/.ssh/id_ed25519")'"#,
            r#"lua -e 'os.remove(os.getenv("HOME").."/.ssh/id_rsa")'"#,
            r#"python3 -c "import os; os.unlink(os.path.join(os.environ['HOME'], '.ssh', 'id_rsa'))""#,
            r#"python3 -c "import os; p = os.path.expanduser('~/.aws/credentials'); os.remove(p)""#,
            r#"perl -e 'unlink "$ENV{HOME}/.ssh/id_ed25519"'"#,
            r#"php -r 'unlink(getenv("HOME") . "/.kube/config");'"#,
        ] {
            assert!(interpreter_code_removes_credentials(line), "{line}");
        }
    }

    #[test]
    fn what_holds_no_key_stays_a_cleanup() {
        for line in [
            r#"python3 -c "import os; os.remove('build/out.o')""#,
            r#"python3 -c "import os; os.remove(os.path.expanduser('~/.ssh/known_hosts'))""#,
            r#"python3 -c "import os; os.remove('/home/u/.ssh/id_ed25519.pub')""#,
            r#"python3 -c "import os; print(os.path.exists('/home/u/.ssh/id_ed25519'))""#,
            r#"lua -e 'os.remove(os.getenv("HOME").."/.cache/x")'"#,
            r#"rm build/out.o"#,
        ] {
            assert!(!interpreter_code_removes_credentials(line), "{line}");
        }
    }
}
