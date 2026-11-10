//! What the words after each word of a command hold, read once.
//!
//! The reading of a command asks, of each word that may run a guard program,
//! what the words after it say: `exec-gate` and one of its verbs, `disarm`,
//! `agent kernel` and a word that is not a read. Asked afresh of the words
//! after each word, a command of N words was read N times over, and 64 KB of
//! a guard program's name on one line held the check for thirteen seconds. A
//! hook that does not answer in time lets the command run, so the time a
//! line takes is part of what the guard refuses.
//!
//! [`WordsAfter`] reads the command once, from its last word to its first,
//! and keeps for each place what the words from it on hold. Each question is
//! then answered from what was kept, in the same time whatever the length of
//! the command.

use super::{GuardProgram, Look, KERNEL_PROTECTION_READS};
use crate::shell_words::Word;

/// The verbs of `exec-gate` that authorise or disarm the gate.
const EXEC_GATE_VERBS: [&str; 3] = ["allow", "approve", "disarm"];

/// What the words of one command hold from each place on. Place `P` speaks
/// of the words from the `P`th on; the place past the last word speaks of
/// no word.
pub(super) struct WordsAfter {
    /// The number of words: the place that speaks of no word.
    count: usize,
    kept: Kept,
}

/// What is kept for each place, by what is looked for.
enum Kept {
    /// The words hold `exec-gate` and, after it, one of its verbs.
    ExecGate(Vec<bool>),
    /// The words hold `disarm` or `--self-approve`; they hold
    /// `--self-approve`.
    Disarm(Vec<(bool, bool)>),
    Kernel(Vec<KernelPlace>),
}

/// What the words from one place on hold of a change of the kernel
/// protection.
#[derive(Clone, Copy)]
struct KernelPlace {
    /// The first place from here on that says `agent`; `count` when none.
    agent: usize,
    /// The first place from here on that says `kernel`; `count` when none.
    kernel: usize,
    /// How many words before this place the text does not show whole.
    not_plain_before: usize,
    /// A word from here on is not a read ([`KERNEL_PROTECTION_READS`]).
    not_a_read: bool,
    /// The first place from here on that is not an option; `count` when none.
    past_options: usize,
    /// The first place from here on that is neither an option nor `host`;
    /// `count` when none.
    past_options_and_host: usize,
    /// How the search for a verb the text does not show ends from here
    /// ([`VerbSearch`]), for each state it may be in: two bits a state.
    verb_search: u16,
}

fn says(word: &Word, verb: &str) -> bool {
    word.is_plain() && word.text.eq_ignore_ascii_case(verb)
}

fn is_option(word: &Word) -> bool {
    word.is_plain() && word.text.len() > 1 && word.text.starts_with('-')
}

fn is_a_read(word: &Word) -> bool {
    word.is_plain() && KERNEL_PROTECTION_READS.contains(&word.text.as_str())
}

/// The search, among the words of a guard program that hold no `agent ...
/// kernel` as written, for a word the text does not show where the verb
/// would be. The verb is the first word that is not an option; a word right
/// after an option may be its value.
///
/// A state is three facts of the words read so far, one bit each.
struct VerbSearch;

impl VerbSearch {
    /// `agent` was read.
    const AFTER_AGENT: u16 = 1;
    /// The last word was an option that may take the next word as its value.
    const MAYBE_A_VALUE: u16 = 2;
    /// `--` was read: no word after it is an option.
    const OPTIONS_END: u16 = 4;
    const STATES: u16 = 8;

    /// The search reached a verb of its own, or another `agent` verb.
    const VERB: u16 = 0;
    /// The search reached a word the text does not show whole.
    const UNSHOWN: u16 = 1;
    /// The words ended where the verb would be.
    const ENDS: u16 = 2;
    /// The words ended where the verb would be, after `agent`.
    const ENDS_AFTER_AGENT: u16 = 3;

    /// How the search ends past the last word, for each state.
    fn past_the_last_word() -> u16 {
        (0..Self::STATES).fold(0, |ends, state| {
            let end = if state & Self::AFTER_AGENT != 0 {
                Self::ENDS_AFTER_AGENT
            } else {
                Self::ENDS
            };
            ends | (end << (2 * state))
        })
    }

    /// How the search ends from `word` on, for each state, given how it
    /// ends from the word after it (`next`).
    fn from(word: &Word, next: u16) -> u16 {
        let plain = word.is_plain();
        let text = word.text.as_str();
        let option = text.len() > 1 && text.starts_with('-');
        let agent = text.eq_ignore_ascii_case("agent");
        let host = text.eq_ignore_ascii_case("host");
        (0..Self::STATES).fold(0, |ends, state| {
            let after = |state: u16| (next >> (2 * state)) & 3;
            let options_end = state & Self::OPTIONS_END != 0;
            let after_agent = state & Self::AFTER_AGENT != 0;
            let no_value = state & !Self::MAYBE_A_VALUE;
            let end = if !plain {
                Self::UNSHOWN
            } else if !options_end && text == "--" {
                after(no_value | Self::OPTIONS_END)
            } else if !options_end && option {
                after(if text.contains('=') {
                    no_value
                } else {
                    state | Self::MAYBE_A_VALUE
                })
            } else if !after_agent && agent {
                after(no_value | Self::AFTER_AGENT)
            } else if !after_agent && host || state & Self::MAYBE_A_VALUE != 0 {
                after(no_value)
            } else {
                Self::VERB
            };
            ends | (end << (2 * state))
        })
    }

    /// How a search that starts at a place ends: no word read yet.
    fn end(ends: u16) -> u16 {
        ends & 3
    }
}

impl WordsAfter {
    /// Reads the words of one command for what `look` looks for.
    pub(super) fn read(look: Look, words: &[Word]) -> Self {
        let count = words.len();
        let kept = match look {
            Look::ExecGate => {
                let mut held = vec![false; count + 1];
                let mut verb_after = false;
                for (place, word) in words.iter().enumerate().rev() {
                    held[place] = held[place + 1] || says(word, "exec-gate") && verb_after;
                    verb_after |= EXEC_GATE_VERBS.iter().any(|verb| says(word, verb));
                }
                Kept::ExecGate(held)
            }
            Look::Disarm => {
                let mut held = vec![(false, false); count + 1];
                for (place, word) in words.iter().enumerate().rev() {
                    let (disarm, self_approve) = held[place + 1];
                    let approves = says(word, "--self-approve");
                    held[place] = (
                        disarm || approves || says(word, "disarm"),
                        self_approve || approves,
                    );
                }
                Kept::Disarm(held)
            }
            Look::Kernel => {
                let past_the_last_word = KernelPlace {
                    agent: count,
                    kernel: count,
                    not_plain_before: 0,
                    not_a_read: false,
                    past_options: count,
                    past_options_and_host: count,
                    verb_search: VerbSearch::past_the_last_word(),
                };
                let mut held = vec![past_the_last_word; count + 1];
                for (place, word) in words.iter().enumerate().rev() {
                    let next = held[place + 1];
                    let option = is_option(word);
                    held[place] = KernelPlace {
                        agent: if says(word, "agent") {
                            place
                        } else {
                            next.agent
                        },
                        kernel: if says(word, "kernel") {
                            place
                        } else {
                            next.kernel
                        },
                        not_plain_before: 0,
                        not_a_read: next.not_a_read || !is_a_read(word),
                        past_options: if option { next.past_options } else { place },
                        past_options_and_host: if option || says(word, "host") {
                            next.past_options_and_host
                        } else {
                            place
                        },
                        verb_search: VerbSearch::from(word, next.verb_search),
                    };
                }
                for (place, word) in words.iter().enumerate() {
                    held[place + 1].not_plain_before =
                        held[place].not_plain_before + usize::from(!word.is_plain());
                }
                Kept::Kernel(held)
            }
        };
        WordsAfter { count, kept }
    }

    /// Whether a word that runs a program of this kind (`program`), with
    /// the words from place `from` on after it, is what is looked for.
    /// `fed`: a program before it adds words of its own; `later`: the text
    /// is kept to be run later; `runs`: the shell runs the text as written.
    pub(super) fn found(
        &self,
        program: GuardProgram,
        from: usize,
        fed: bool,
        later: bool,
        runs: bool,
    ) -> bool {
        match (&self.kept, program) {
            (Kept::Kernel(held), GuardProgram::Is) => {
                self.kernel_arguments_change(held, from, fed, later)
            }
            (Kept::Kernel(held), GuardProgram::Maybe) => self
                .kernel_verb_changes(held, from, fed, later)
                .unwrap_or(false),
            (Kept::Kernel(held), GuardProgram::Not) => {
                runs && !later && self.guard_verbs_after_any_program(held, from)
            }
            (Kept::ExecGate(held), GuardProgram::Is | GuardProgram::Maybe) => held[from],
            (Kept::Disarm(held), GuardProgram::Is) => held[from].0,
            (Kept::Disarm(held), GuardProgram::Maybe) => held[from].1,
            (Kept::ExecGate(_) | Kept::Disarm(_), GuardProgram::Not) => false,
        }
    }

    /// The words of a guard program's command line: whether they change the
    /// kernel protection. `fed`: a program before it adds words of its own.
    fn kernel_arguments_change(
        &self,
        held: &[KernelPlace],
        from: usize,
        fed: bool,
        later: bool,
    ) -> bool {
        if let Some(changes) = self.kernel_verb_changes(held, from, fed, later) {
            return changes;
        }
        // No `agent ... kernel` as written: whether a word the text does
        // not show could stand where the verb is.
        match VerbSearch::end(held[from].verb_search) {
            VerbSearch::UNSHOWN => true,
            // The words end where the verb would be: what is added decides.
            VerbSearch::ENDS => fed,
            VerbSearch::ENDS_AFTER_AGENT => fed || later,
            _ => false,
        }
    }

    /// `agent`, then `kernel` after it, each as written: whether the words
    /// change the kernel protection. `None` when the words hold no such
    /// pair.
    fn kernel_verb_changes(
        &self,
        held: &[KernelPlace],
        from: usize,
        fed: bool,
        later: bool,
    ) -> Option<bool> {
        let agent = held[from].agent;
        if agent == self.count {
            return None;
        }
        let kernel = held[agent + 1].kernel;
        if kernel == self.count {
            return None;
        }
        Some(
            fed || later
                || held[kernel].not_plain_before > held[from].not_plain_before
                || held[kernel + 1].not_a_read,
        )
    }

    /// `agent` and `kernel` as written right after a program (options, and
    /// a `host` before `agent`, aside), then a word that is not a read
    /// ([`KERNEL_PROTECTION_READS`]): the guard's own verb under a name the
    /// text does not show to be the guard's.
    fn guard_verbs_after_any_program(&self, held: &[KernelPlace], from: usize) -> bool {
        let agent = held[from].past_options_and_host;
        if agent == self.count || held[agent].agent != agent {
            return false;
        }
        let kernel = held[agent + 1].past_options;
        if kernel == self.count || held[kernel].kernel != kernel {
            return false;
        }
        held[kernel + 1].not_a_read
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell_words::Mark;

    fn word(text: &str) -> Word {
        let mark = match text.chars().next() {
            Some('$') => Mark::Expansion,
            Some('*') => Mark::Pattern,
            _ => Mark::Plain,
        };
        Word {
            text: text.to_string(),
            marks: vec![mark; text.chars().count()],
            ..Word::default()
        }
    }

    fn program(kind: usize) -> GuardProgram {
        match kind {
            0 => GuardProgram::Is,
            1 => GuardProgram::Maybe,
            _ => GuardProgram::Not,
        }
    }

    const LOOKS: [Look; 3] = [Look::Kernel, Look::ExecGate, Look::Disarm];

    /// Every question, of every place of `words`, answered both ways: by
    /// the words read once and by the words read afresh. The count of
    /// questions answered yes, by look and kind of program.
    fn same_answers(words: &[Word]) -> [[usize; 3]; 3] {
        let mut yes = [[0; 3]; 3];
        for (which, look) in LOOKS.into_iter().enumerate() {
            let after = WordsAfter::read(look, words);
            for from in 0..=words.len() {
                for (kind, count) in yes[which].iter_mut().enumerate() {
                    for flags in 0..8 {
                        let (fed, later, runs) = (flags & 1 != 0, flags & 2 != 0, flags & 4 != 0);
                        let once = after.found(program(kind), from, fed, later, runs);
                        let afresh = look.found(program(kind), &words[from..], fed, later, runs);
                        assert_eq!(
                            once,
                            afresh,
                            "{look:?}, program {kind}, from {from}, fed {fed}, later {later}, \
                             runs {runs}: {:?}",
                            words.iter().map(|word| &word.text).collect::<Vec<_>>()
                        );
                        *count += usize::from(once);
                    }
                }
            }
        }
        yes
    }

    #[test]
    fn the_words_read_once_answer_as_the_words_read_afresh() {
        const SAID: [&str; 24] = [
            "agent",
            "kernel",
            "host",
            "status",
            "--json",
            "-h",
            "--",
            "-x",
            "--mode=fast",
            "-",
            "exec-gate",
            "allow",
            "approve",
            "disarm",
            "--self-approve",
            "off",
            "AGENT",
            "Kernel",
            "STATUS",
            "$x",
            "*",
            "$agent",
            "iw",
            "",
        ];
        let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = |below: usize| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) as usize % below
        };
        let mut yes = [[0; 3]; 3];
        let mut asked = 0;
        for _ in 0..6_000 {
            // Half the commands from the words that decide a kernel verb, so
            // `agent ... kernel` and what follows it come up often.
            let from = if next(2) == 0 { 10 } else { SAID.len() };
            let words: Vec<Word> = (0..next(9)).map(|_| word(SAID[next(from)])).collect();
            asked += 3 * 3 * 8 * (words.len() + 1);
            for (which, by_kind) in same_answers(&words).into_iter().enumerate() {
                for (kind, count) in by_kind.into_iter().enumerate() {
                    yes[which][kind] += count;
                }
            }
        }
        // Both answers come up for each question that has two.
        assert!(asked > 1_000_000, "{asked}");
        let floor = [[20_000, 5_000, 300], [2_000, 2_000, 0], [20_000, 5_000, 0]];
        for which in 0..3 {
            for kind in 0..3 {
                assert!(
                    yes[which][kind] >= floor[which][kind],
                    "{:?}, program {kind}: {yes:?} of {asked}",
                    LOOKS[which]
                );
            }
        }
        assert_eq!((yes[1][2], yes[2][2]), (0, 0));
    }
}
