//! The posture a connect, an install or a setup leaves the hook in
//! ([`innerwarden_agent_guard::posture`]).
//!
//! - `--strict`: the enforce of every install before the posture existed.
//! - `--guard`: the default posture, asked for by name (an install that was
//!   strict moves to it). It lowers what the hook refuses, so it is the
//!   person's, never a command an agent's shell runs.
//! - neither: a posture already chosen stays; a home with no file and no
//!   wiring yet (a new install) gets the default posture; a home already
//!   wired before the posture existed is kept strict, so an upgrade or a
//!   reconnect never changes what an existing install refuses.

use std::path::Path;

use innerwarden_agent_guard::agents_ops;
use innerwarden_agent_guard::posture::{self, Posture};

/// The posture flags this command line names: `Err` when it names both.
pub(crate) fn requested(rest: &[String]) -> Result<Option<Posture>, String> {
    let strict = rest.iter().any(|a| a == "--strict");
    let guard = rest.iter().any(|a| a == "--guard");
    match (strict, guard) {
        (true, true) => Err("`--strict` and `--guard` name two postures; choose one".into()),
        (true, false) => Ok(Some(Posture::Strict)),
        (false, true) => Ok(Some(Posture::Guard)),
        (false, false) => Ok(None),
    }
}

/// The command line for the wiring engine: `--guard` taken out, and
/// `--strict` kept, because `--strict` is both the posture and the wiring
/// it had before the posture existed (`--block-review`, which the engine
/// reads it as). A strict connect never wires less than it did.
pub(crate) fn without_posture_flags(rest: &[String]) -> Vec<String> {
    rest.iter()
        .filter(|a| a.as_str() != "--guard")
        .cloned()
        .collect()
}

/// Whether any agent under `home` holds wiring of the guard already, read
/// before a connect writes anything.
///
/// Any line of ours counts, not only one `status` reports as guarded: an
/// install from before the posture existed whose hook sits under a matcher
/// that leaves the shell out, or whose MCP wrapping is partial, was still
/// wired by a person, and reading it as a new install would move it to the
/// default posture, which refuses less. Claude Code's settings are read
/// directly as well, so a home whose agent discovery does not list Claude
/// Code still counts a hook it holds.
pub(crate) fn already_wired(home: &Path) -> bool {
    let claude_hook = [".claude/settings.json", ".claude/settings.local.json"]
        .iter()
        .filter_map(|rel| std::fs::read_to_string(home.join(rel)).ok())
        .filter_map(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .any(|settings| innerwarden_agent_guard::hook::has_iwguard_wiring(&settings));
    claude_hook
        || agents_ops::rows(home)
            .iter()
            .any(|agent| agent.guarded || agents_ops::has_guard_wiring(home, &agent.name))
}

/// PURE: the posture to write, or `None` to leave the file as it is.
pub(crate) fn to_write(
    requested: Option<Posture>,
    on_file: Option<Posture>,
    was_wired: bool,
) -> Option<Posture> {
    match (requested, on_file) {
        (Some(asked), _) => Some(asked),
        (None, Some(_)) => None,
        (None, None) if was_wired => Some(Posture::Strict),
        (None, None) => Some(Posture::Guard),
    }
}

/// Settle the posture under `home` after a connect, install or setup that
/// wrote its wiring, and say it in one line.
pub(crate) fn settle(
    home: &Path,
    requested: Option<Posture>,
    was_wired: bool,
) -> Result<String, String> {
    if let Some(posture) = to_write(requested, posture::read_posture_file(home), was_wired) {
        posture::write_posture(home, posture)?;
    }
    Ok(line(posture::posture_in_force(home)))
}

/// The one line that says the posture in force and what it refuses.
pub(crate) fn line(posture: Posture) -> String {
    let harden = match posture {
        Posture::Guard => {
            " Refuse every deny and every review instead: `innerwarden agents connect --strict`."
        }
        Posture::Strict => "",
    };
    format!(
        "  Posture: {} ({}).{harden}",
        posture.word(),
        posture::refuses_summary(posture)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn a_new_install_gets_the_default_and_an_old_one_stays_strict() {
        assert_eq!(to_write(None, None, false), Some(Posture::Guard));
        assert_eq!(to_write(None, None, true), Some(Posture::Strict));
        assert_eq!(to_write(None, Some(Posture::Guard), true), None);
        assert_eq!(to_write(None, Some(Posture::Strict), false), None);
        assert_eq!(
            to_write(Some(Posture::Strict), Some(Posture::Guard), true),
            Some(Posture::Strict)
        );
        assert_eq!(
            to_write(Some(Posture::Guard), Some(Posture::Strict), true),
            Some(Posture::Guard)
        );
    }

    #[test]
    fn the_flags_are_read_and_taken_out_for_the_engine() {
        assert_eq!(
            requested(&args(&["connect", "--strict"])),
            Ok(Some(Posture::Strict))
        );
        assert_eq!(
            requested(&args(&["connect", "--guard"])),
            Ok(Some(Posture::Guard))
        );
        assert_eq!(requested(&args(&["connect"])), Ok(None));
        assert!(requested(&args(&["connect", "--guard", "--strict"])).is_err());
        assert_eq!(
            without_posture_flags(&args(&["connect", "cursor", "--guard", "--block-review"])),
            args(&["connect", "cursor", "--block-review"])
        );
        // `--strict` reaches the engine, which wires it as `--block-review`.
        assert_eq!(
            without_posture_flags(&args(&["connect", "cursor", "--strict"])),
            args(&["connect", "cursor", "--strict"])
        );
    }

    #[test]
    fn settle_writes_once_and_keeps_a_choice() {
        let home = tempfile::tempdir().unwrap();
        let said = settle(home.path(), None, false).unwrap();
        assert!(said.contains("Posture: guard"), "{said}");
        // A later connect with no flag keeps it.
        settle(home.path(), None, true).unwrap();
        assert_eq!(posture::posture_in_force(home.path()), Posture::Guard);
        let said = settle(home.path(), Some(Posture::Strict), true).unwrap();
        assert!(said.contains("Posture: strict"), "{said}");
    }
}
