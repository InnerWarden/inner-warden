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
        r"(?is)\b(?:python[\d.]*|pypy[\d.]*|node|nodejs|bun|deno|ruby|perl[\d.]*|php[\d.]*|lua(?:jit)?[\d.]*)\b.{0,200}?\s-[a-z]*[cer]\b",
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
    let code = code.replace("'\\''", "'");
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
    if !HOME_BY_NAME.is_match(text) {
        return false;
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
