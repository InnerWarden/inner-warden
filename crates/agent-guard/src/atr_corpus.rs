//! The ATR rule file as the engine reads it, and the literals a pattern
//! cannot match without.
//!
//! Shared by the library (rules read from disk, [`crate::rules`]) and by the
//! crate's build script, which reads the embedded corpus once at build time
//! and writes it out as a table the binary carries: a one-shot process (the
//! hook before every tool call) no longer parses YAML to judge a call, and a
//! rule whose literals are absent from the text is never compiled
//! (see `RuleConditions` in `rules.rs`).
//!
//! Nothing here may name `crate::`: the build script includes this file on
//! its own.

use regex_syntax::hir::{Class, Hir, HirKind};

#[derive(serde::Deserialize)]
pub struct RawRule {
    pub id: Option<String>,
    pub title: Option<String>,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub detection_tier: String,
    #[serde(default)]
    pub tags: RawTags,
    #[serde(default)]
    pub references: RawReferences,
    #[serde(default)]
    pub agent_source: RawAgentSource,
    #[serde(default)]
    pub detection: RawDetection,
}

#[derive(serde::Deserialize, Default)]
pub struct RawAgentSource {
    #[serde(default, rename = "type")]
    pub source_type: String,
}

#[derive(serde::Deserialize, Default)]
#[serde(untagged)]
pub enum RawTags {
    Map {
        #[serde(default)]
        category: String,
    },
    List(Vec<String>),
    String(String),
    #[default]
    Empty,
}

impl RawTags {
    pub fn category(&self) -> String {
        match self {
            Self::Map { category } => category.clone(),
            Self::List(v) => v.first().cloned().unwrap_or_default(),
            Self::String(s) => s.clone(),
            Self::Empty => String::new(),
        }
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(untagged)]
pub enum RawReferences {
    Map {
        #[serde(default)]
        owasp_llm: Vec<String>,
        #[serde(default)]
        owasp_agentic: Vec<String>,
        #[serde(default)]
        mitre_atlas: Vec<String>,
        #[serde(default)]
        mitre_attack: Vec<String>,
    },
    List(Vec<String>),
    String(String),
    #[default]
    Empty,
}

/// A rule's references by kind: OWASP LLM, OWASP Agentic, MITRE ATLAS and
/// MITRE ATT&CK, in that order.
pub type ReferenceLists = [Vec<String>; 4];

impl RawReferences {
    pub fn into_lists(self) -> ReferenceLists {
        match self {
            Self::Map {
                owasp_llm,
                owasp_agentic,
                mitre_atlas,
                mitre_attack,
            } => [owasp_llm, owasp_agentic, mitre_atlas, mitre_attack],
            Self::List(v) => [Vec::new(), Vec::new(), Vec::new(), v],
            Self::String(s) => [Vec::new(), Vec::new(), Vec::new(), vec![s]],
            Self::Empty => Default::default(),
        }
    }
}

#[derive(serde::Deserialize, Default)]
pub struct RawDetection {
    #[serde(default)]
    pub conditions: Vec<RawCondition>,
    #[serde(default)]
    pub condition: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct RawCondition {
    #[serde(default)]
    pub field: String,
    #[serde(default)]
    pub operator: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// One regex condition of a pattern-tier rule.
pub struct ParsedCondition {
    /// The field as the rule names it (`tool_args`, `content`, ...).
    pub field: String,
    pub pattern: String,
    /// The rule's words for it, or `<id> match`.
    pub description: String,
}

/// A pattern-tier rule with at least one regex condition, as the engine
/// keeps it before anything is compiled.
pub struct ParsedRule {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub category: String,
    pub source_type: String,
    /// `condition: all`.
    pub all: bool,
    pub references: ReferenceLists,
    pub conditions: Vec<ParsedCondition>,
}

/// Read one rule file. `Ok(None)` for a rule the engine does not run: not
/// pattern tier, or with no regex condition.
pub fn parse_rule(content: &str) -> Result<Option<ParsedRule>, serde_yaml::Error> {
    let raw: RawRule = serde_yaml::from_str(content)?;
    Ok(from_raw(raw))
}

/// [`parse_rule`] from a parsed file.
pub fn from_raw(raw: RawRule) -> Option<ParsedRule> {
    if raw.detection_tier != "pattern" {
        return None;
    }
    let id = raw.id.unwrap_or_default();
    let conditions: Vec<ParsedCondition> = raw
        .detection
        .conditions
        .iter()
        .filter(|cond| cond.operator == "regex" && !cond.value.is_empty())
        .map(|cond| ParsedCondition {
            field: cond.field.clone(),
            pattern: cond.value.clone(),
            description: cond
                .description
                .clone()
                .unwrap_or_else(|| format!("{id} match")),
        })
        .collect();
    if conditions.is_empty() {
        return None;
    }
    Some(ParsedRule {
        title: raw.title.unwrap_or_default(),
        severity: raw.severity,
        category: raw.tags.category(),
        source_type: raw.agent_source.source_type,
        all: raw.detection.condition.as_deref() == Some("all"),
        references: raw.references.into_lists(),
        conditions,
        id,
    })
}

/// The most literals one requirement may hold: past that the look costs
/// more than it saves.
const MAX_LITERALS: usize = 64;

/// How a text is looked at for literals, one character at a time: an ASCII
/// letter in lower case, the Kelvin sign as `k` and the long s as `s`
/// (the two characters Unicode's simple case folding joins to an ASCII
/// letter, which `(?i)k` and `(?i)s` match), anything else as it is.
pub fn fold_char(c: char) -> char {
    match c {
        '\u{212A}' => 'k',
        '\u{17F}' => 's',
        c => c.to_ascii_lowercase(),
    }
}

/// A text as [`fold_char`] reads it.
pub fn fold(text: &str) -> String {
    text.chars().map(fold_char).collect()
}

/// Literals at least one of which every match of `pattern` contains, read
/// as [`fold`] reads a text (so the text must be folded too). `None` when no such set is known:
/// the pattern does not parse as the `regex` crate parses it, or a match
/// can be made of anything (an optional part, a class), or more than
/// [`MAX_LITERALS`] are needed.
///
/// A pattern only `fancy-regex` reads (look-around, a back-reference) gets
/// no literals even when every match holds some: it is run with a backtrack
/// limit, and a text it cannot finish (a long one) is held for review
/// ([`crate::rules`]'s `Reading::Undecided`). Skipping it for a text
/// without its literals would let that text through where compiling the
/// rule holds it, and the verdict would hang on whether another text had
/// compiled the rule first.
///
/// Sound by construction, never complete: a class counts as one character
/// only when every character in it folds to the same one, literal text is
/// folded as the text is, and a part that is not sure to appear in every
/// match adds nothing. A text without
/// any of the literals cannot match.
pub fn required_literals(pattern: &str) -> Option<Vec<String>> {
    let hir = regex_syntax::Parser::new().parse(pattern).ok()?;
    let found = required(&hir)?;
    let usable = !found.is_empty() && found.len() <= MAX_LITERALS;
    if !usable {
        return None;
    }
    let mut out: Vec<String> = found
        .into_iter()
        .map(|lit| String::from_utf8(lit).ok())
        .collect::<Option<_>>()?;
    out.sort();
    out.dedup();
    Some(out)
}

/// The most characters a class may hold and still be read as one folded
/// character (`(?i)k` is three: `K`, `k` and the Kelvin sign).
const MAX_CLASS_CHARS: usize = 4;

/// The text one HIR node matches, folded ([`fold`]), when it can match
/// only one: a literal, or a class whose every character folds to the same
/// one.
fn fixed_bytes(hir: &Hir) -> Option<Vec<u8>> {
    match hir.kind() {
        HirKind::Literal(literal) => Some(fold(std::str::from_utf8(&literal.0).ok()?).into_bytes()),
        HirKind::Class(Class::Unicode(class)) => {
            let mut folded: Option<char> = None;
            let mut count = 0usize;
            for range in class.ranges() {
                for c in range.start()..=range.end() {
                    count += 1;
                    if count > MAX_CLASS_CHARS {
                        return None;
                    }
                    let f = fold_char(c);
                    match folded {
                        None => folded = Some(f),
                        Some(seen) if seen == f => {}
                        Some(_) => return None,
                    }
                }
            }
            folded.map(|c| c.to_string().into_bytes())
        }
        // A class of bytes (`(?-u)`) can match half a character: no text.
        HirKind::Capture(capture) => fixed_bytes(&capture.sub),
        _ => None,
    }
}

/// A set every match contains one of (see [`required_literals`]).
fn required(hir: &Hir) -> Option<Vec<Vec<u8>>> {
    if let Some(bytes) = fixed_bytes(hir) {
        return (!bytes.is_empty()).then(|| vec![bytes]);
    }
    match hir.kind() {
        HirKind::Capture(capture) => required(&capture.sub),
        HirKind::Repetition(rep) if rep.min >= 1 => required(&rep.sub),
        HirKind::Alternation(branches) => {
            let mut all = Vec::new();
            for branch in branches {
                all.extend(required(branch)?);
                if all.len() > MAX_LITERALS {
                    return None;
                }
            }
            Some(all)
        }
        HirKind::Concat(parts) => {
            let mut candidates: Vec<Vec<Vec<u8>>> = Vec::new();
            let mut run: Vec<u8> = Vec::new();
            for part in parts {
                if let Some(bytes) = fixed_bytes(part) {
                    run.extend(bytes);
                    continue;
                }
                if !run.is_empty() {
                    candidates.push(vec![std::mem::take(&mut run)]);
                }
                if let Some(set) = required(part) {
                    candidates.push(set);
                }
            }
            if !run.is_empty() {
                candidates.push(vec![run]);
            }
            // Every part appears in every match, so any one set will do: the
            // one whose shortest literal is longest rules out the most.
            candidates.into_iter().max_by_key(|set| {
                (
                    set.iter().map(Vec::len).min().unwrap_or(0),
                    std::cmp::Reverse(set.len()),
                )
            })
        }
        _ => None,
    }
}
