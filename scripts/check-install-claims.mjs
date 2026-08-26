#!/usr/bin/env node
/**
 * No document in this repository may claim `npm install -g` needs no root.
 *
 * WHY THIS EXISTS, AND WHY IT IS THE THIRD ONE
 *
 * A gate with this job shipped first in the website repository, written as
 * `DOCS = "client/src/content/docs"`. That is a scan of a DIRECTORY, not a gate
 * on a CLAIM, so the same false sentence survived in three files here.
 *
 * This file was the second attempt: same rule, whole-repository scan. It ran
 * green for its entire life and never once caught the sentence it names in its
 * own header. The detector was:
 *
 *   /\bno (?:sudo|root|sudo\/root|sudo or root)\b/i
 *
 * and the worst of the three real sentences was:
 *
 *   Same install on Linux, macOS, and Windows, no `curl | sh`, no `sudo`:
 *
 * "no " is followed by a BACKTICK, not by `s`, so `\bno sudo\b` cannot match
 * it. The author's own notes say each sentence "was reverted SEPARATELY to find
 * this", but the revert was retyped as `no sudo:` in plain text, and the plain
 * form does match. The gate was verified against a paraphrase of the defect
 * rather than the defect, and `npm/README.md` is in `package.json`'s `files`
 * array, so the unmatched sentence WAS the npmjs.com package page.
 *
 * THE FIX IS NOT THE REGEX
 *
 * Widening the pattern fixes today's blind spot and nothing else. What kept
 * this quiet is that nobody could tell a working detector from a broken one by
 * looking at a green run, because a gate that matches nothing and a repository
 * that says nothing wrong produce the identical output.
 *
 * So the detector now proves itself before it is trusted. `KNOWN_BAD` holds the
 * three sentences exactly as they shipped, recovered with
 * `git show d1752f0^:<file>` rather than retyped, and `KNOWN_GOOD` holds the
 * true statements that must not fire. Both run through `verdictFor`, the same
 * function the file scan uses. If a future edit makes the detector blind again,
 * this exits 1 on its own corpus and says which sentence it stopped seeing.
 *
 * FAILS ON REVERT: restore any of the three sentences and this exits 1. Checked
 * for all three, in their real form, not a paraphrase.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

/**
 * Directories with no prose of ours in them.
 *
 * `.claude` holds agent worktrees, which are COPIES of this repository rather
 * than content of it. Scanning them reported the same line six times, and worse
 * would let a stale copy fail a clean tree.
 */
const SKIP = new Set(["node_modules", "target", ".git", "dist", ".github", ".claude"]);

/**
 * Files whose job is to record what the product USED to say.
 *
 * A changelog quotes the claim it is announcing the removal of, and describes
 * the fix in the same breath ("it now leads with the installer that needs no
 * root"). Both read as the defect to a scanner and are correct prose. Nobody
 * installs from a changelog, so the risk of exempting it is the risk of a false
 * claim hiding somewhere nobody follows.
 */
const SKIP_FILES = new Set(["CHANGELOG.md"]);

/**
 * Inline markup that may sit between "no" and the word it negates.
 *
 * Markdown lets the same claim wear four costumes: `sudo`, **sudo**, _sudo_,
 * *sudo*. The previous detector understood only the naked one, which is how the
 * backticked sentence on npmjs.com survived. Optional on both sides, because
 * prose closes the markup and the old pattern's trailing `\b` would have
 * stumbled on the closing backtick even if the opening one were skipped.
 */
const MARKUP = "[`*_]*";

/**
 * Asserting no elevation is needed, in every shape the claim can take.
 *
 * Deliberately wider than the three sentences that prompted it: a rule written
 * to exactly the known instances is a rule that catches only the known
 * instances. "without sudo" and "does not require root" say the same false
 * thing and would have walked past the old pattern untouched.
 */
const NO_ELEVATION = new RegExp(
  [
    // no sudo / no root / no sudo or root, with or without markup
    `\\bno\\s+${MARKUP}(?:sudo|root|admin(?:istrator)?)${MARKUP}`,
    // no elevation / no privilege escalation / no elevated privileges
    `\\bno\\s+(?:elevation|elevated\\s+\\w+|privilege)`,
    // without sudo / without root
    `\\bwithout\\s+${MARKUP}(?:sudo|root)${MARKUP}`,
    // does not / doesn't / never needs|requires sudo|root
    `\\b(?:does\\s+not|doesn't|never)\\s+(?:need|require)s?\\s+${MARKUP}(?:sudo|root)${MARKUP}`,
    // no need for sudo
    `\\bno\\s+need\\s+for\\s+${MARKUP}(?:sudo|root)${MARKUP}`,
  ].join("|"),
  "i"
);

/**
 * The sentence is contrasting npm with the rootless path, or naming the failure
 * outright, rather than claiming npm needs nothing. That is correct prose and
 * must not be punished, or the gate gets muted.
 */
const CONTRASTS =
  /innerwarden\.com\/free|shell installer|EACCES|root-owned|sudo npm|needs\s+[`*_]*sudo[`*_]*|expect this to need/i;

/**
 * The sentence names a subject that is NOT npm.
 *
 * The window test asks whether npm is nearby, which is the right question for a
 * claim that omits its subject ("no sudo:" three lines above a fenced
 * `npm install -g`). It is the wrong question for a sentence that states its
 * subject and means it. Both of these sit within four lines of an npm command
 * in `npm/README.md` and both are true:
 *
 *   InnerWarden itself never needs root.
 *   into `~/.local/bin` with no elevation on any platform:
 *
 * The first is about the binary at runtime; the second about the shell
 * installer's destination. Flagging them is how a gate earns an `// eslint-
 * disable` from the next person who trips over it, and a muted gate protects
 * the defect as surely as a blind one. Every exemption here is pinned by a
 * `KNOWN_GOOD` case, so widening this list cannot be done quietly.
 */
const OTHER_SUBJECT =
  /innerwarden itself|the binary|running the binary|~\/\.local\/bin|\.npm-global/i;

/**
 * Prose that is about INSTALLING, as opposed to running.
 *
 * This condition replaced a growing list of subject exemptions. The rule
 * forbids exactly one claim: that installing via npm needs no elevation. Every
 * true sentence that got flagged before this existed was about the product at
 * RUNTIME rather than about an install:
 *
 *   InnerWarden itself never needs root.
 *   It runs entirely as your user, needs **no root**, and keeps its config ...
 *   curl|sh is the path that genuinely needs no root.
 *
 * None mentions npm, installing, a prebuilt binary, or provenance. Every false
 * claim in `KNOWN_BAD` does. One rule covers all of them, where the exemption
 * list needed one rule per sentence somebody happened to write.
 */
// `install` carries no leading \b on purpose: "postinstall" is install
// context, and requiring the boundary let
//   No sudo, no root, no postinstall script.
// through, on a live blog page, during this very rewrite's revert test.
const INSTALL_CONTEXT = /\bnpm\b|install|\bprebuilt\b|\bprovenance\b|\bpackage manager\b/i;

/**
 * Comment markers, stripped before sentences are reconstructed.
 *
 * A claim inside a `//` block is one sentence wrapped over several lines, and
 * judging each line separately severs it from its own subject.
 */
const COMMENT_PREFIX = /^\s*(?:\/\/+|\*+\/?|\{\s*\/\*|<!--)\s?/;
const COMMENT_SUFFIX = /(?:\*\/\s*\}?|-->)\s*$/;

/**
 * Every sentence in the file, each carrying the line it starts on.
 *
 * Sentences are reconstructed ACROSS line breaks on purpose. The claim and the
 * word that establishes its subject routinely sit on different lines:
 *
 *   Prebuilt binary with signed npm provenance from a trusted registry.
 *   No sudo, no postinstall script, nothing runs at install time.
 *
 * A per-line split reads the second line as a subjectless "no sudo", which is
 * both how false positives appear on true prose and how a real claim can hide.
 */
/**
 * A line that ends the sentence regardless of punctuation.
 *
 * A claim that introduces a code block ends in a colon, not a full stop, and
 * without this it runs on into whatever follows the fence. That is not
 * hypothetical: joining across the fence made
 *
 *   Same install on Linux, macOS, and Windows, no `curl | sh`, no `sudo`:
 *
 * swallow the warning three lines below it ("expect this to need `sudo`"),
 * whose presence then EXEMPTED the claim. The gate went blind to the worst of
 * the three sentences the moment sentences learned to cross lines. Blank lines
 * and fences are the other two boundaries, for the same reason.
 */
const HARD_BREAK = /:\s*$|^\s*```|^\s*$|^\s*<\/?(?:p|div|pre|li|h[1-6])\b/;

function sentencesOf(lines) {
  const out = [];
  let buffer = "";
  let bufferLine = 1;

  const flush = () => {
    if (!buffer.trim()) {
      buffer = "";
      return;
    }
    let cursor = 0;
    const splitter = /(?<=\.)\s+/g;
    let m;
    while ((m = splitter.exec(buffer)) !== null) {
      out.push({ text: buffer.slice(cursor, m.index + 1), line: bufferLine });
      cursor = splitter.lastIndex;
    }
    if (cursor < buffer.length) out.push({ text: buffer.slice(cursor), line: bufferLine });
    buffer = "";
  };

  lines.forEach((raw, i) => {
    const cleaned = raw.replace(COMMENT_PREFIX, "").replace(COMMENT_SUFFIX, "");
    if (!buffer) bufferLine = i + 1;
    buffer += cleaned + "\n";
    if (HARD_BREAK.test(cleaned)) flush();
  });
  flush();
  return out;
}

/**
 * Does this sentence assert that installing via npm needs no elevation?
 *
 * Whether npm is the SUBJECT is judged over a BLOCK when the sentence itself
 * omits the word, because the claim often introduces a fenced block whose
 * command is three lines below:
 *
 *   Same install on Linux, macOS, and Windows, no `sudo`:
 *
 *   ```sh
 *   npm install -g innerwarden
 *   ```
 *
 * Returns the offending sentence, or null.
 */
function verdictFor(sentence, window) {
  if (!NO_ELEVATION.test(sentence)) return null;
  if (!INSTALL_CONTEXT.test(sentence)) return null;
  if (CONTRASTS.test(sentence)) return null;
  if (OTHER_SUBJECT.test(sentence)) return null;
  if (!/\bnpm\b/i.test(sentence) && !/\bnpm\b/i.test(window)) return null;
  return sentence;
}

/**
 * The three sentences exactly as they shipped, recovered with
 * `git show d1752f0^:<file>`, NOT retyped. Retyping is what produced a gate
 * that passed its own revert test while blind to the real thing: the author
 * wrote `no sudo:` where the file said ``no `sudo`:``.
 *
 * Each carries the surrounding lines it needs for the npm-subject window, so
 * the corpus exercises the same code path as the scan rather than a
 * simplification of it.
 */
const KNOWN_BAD = [
  {
    where: "npm/README.md:7 (this one IS the npmjs.com package page)",
    line: "Same install on Linux, macOS, and Windows, no `curl | sh`, no `sudo`:",
    window: [
      "Same install on Linux, macOS, and Windows, no `curl | sh`, no `sudo`:",
      "",
      "```sh",
      "npm install -g innerwarden",
      "```",
    ].join("\n"),
  },
  {
    where: "README.md:26",
    line: "npm (every OS, prebuilt and signed, no sudo):",
    window: "npm (every OS, prebuilt and signed, no sudo):",
  },
  {
    where: "DISTRIBUTION.md:41",
    line:
      "- **npm (recommended, all OSes):** `npm install -g innerwarden` / `npx innerwarden`. " +
      "Prebuilt, signed provenance, no sudo, no postinstall.",
    window:
      "- **npm (recommended, all OSes):** `npm install -g innerwarden` / `npx innerwarden`. " +
      "Prebuilt, signed provenance, no sudo, no postinstall.",
  },
  // Shapes the claim could take next. Not sentences that ever shipped, but the
  // same false statement in other clothes: a detector that catches only what
  // already happened is a record, not a gate.
  {
    where: "hypothetical: bold markup",
    line: "npm install -g innerwarden works on every OS, no **sudo**.",
    window: "npm install -g innerwarden works on every OS, no **sudo**.",
  },
  {
    where: "postinstall is install context: this shape escaped the first rewrite",
    line: "No sudo, no root, no postinstall script.",
    window: "npm ships a prebuilt binary with signed npm provenance. No\nsudo, no root, no postinstall script.",
  },
  {
    where: "hypothetical: without",
    line: "Installs globally without sudo on any platform.",
    window: "Installs globally without sudo on any platform.\n\n```sh\nnpm install -g innerwarden\n```",
  },
  {
    where: "hypothetical: does not require",
    line: "The npm package does not require root.",
    window: "The npm package does not require root.",
  },
];

/**
 * True statements that must stay silent. Without these, "fix the detector"
 * degenerates into "match more", and a gate that flags correct prose gets
 * muted by the next person who trips over it.
 */
const KNOWN_GOOD = [
  {
    where: "the current npm/README.md warning",
    line: "**On Linux, expect this to need `sudo`.** `npm install -g` writes to npm's global prefix.",
    window: "**On Linux, expect this to need `sudo`.** `npm install -g` writes to npm's global prefix.",
  },
  {
    where: "the current README.md quick install",
    line: "npm (every OS, prebuilt and signed; needs `sudo` on Linux, where npm's global prefix is root-owned):",
    window: "npm (every OS, prebuilt and signed; needs `sudo` on Linux, where npm's global prefix is root-owned):",
  },
  {
    where: "the shell installer, which genuinely needs no root",
    line: "The shell installer at innerwarden.com/free needs no sudo.",
    window: "The shell installer at innerwarden.com/free needs no sudo.\n\nnpm is the other option.",
  },
  {
    where: "prose about npm nowhere nearby",
    line: "Running the binary needs no root.",
    window: "Running the binary needs no root.",
  },
  // The two real false positives the widened detector produced on its first
  // run, verbatim from npm/README.md with the npm mention that puts them in
  // window range. Pinned here so the OTHER_SUBJECT exemption cannot be
  // widened without a reason, and cannot be dropped without a failure.
  {
    where: "npm/README.md:25, true: about the binary at runtime",
    line: "InnerWarden itself never needs root. If you would rather not involve npm's",
    window: [
      "npm config set prefix ~/.npm-global   # then put ~/.npm-global/bin on PATH",
      "```",
      "",
      "InnerWarden itself never needs root. If you would rather not involve npm's",
      "prefix at all, the shell installer verifies the signed binary and installs it",
    ].join("\n"),
  },
  {
    where: "npm/README.md:27, true: about the shell installer's destination",
    line: "into `~/.local/bin` with no elevation on any platform:",
    window: [
      "InnerWarden itself never needs root. If you would rather not involve npm's",
      "prefix at all, the shell installer verifies the signed binary and installs it",
      "into `~/.local/bin` with no elevation on any platform:",
    ].join("\n"),
  },
];

/** Prove the detector can still see, before trusting a green scan. */
function selfCheck() {
  let broken = 0;
  for (const c of KNOWN_BAD) {
    if (verdictFor(c.line, c.window) === null) {
      console.error(
        `  FAIL  self-check: the detector no longer sees a known false claim\n` +
          `        ${c.where}\n` +
          `        ${c.line}`
      );
      broken += 1;
    }
  }
  for (const c of KNOWN_GOOD) {
    const hit = verdictFor(c.line, c.window);
    if (hit !== null) {
      console.error(
        `  FAIL  self-check: the detector now flags correct prose\n` +
          `        ${c.where}\n` +
          `        ${hit}`
      );
      broken += 1;
    }
  }
  if (broken > 0) {
    console.error(
      `\ninstall-claims: the gate itself is broken (${broken} corpus failure(s)).\n` +
        "A green scan from a blind detector is what this corpus exists to prevent."
    );
    process.exit(1);
  }
  return KNOWN_BAD.length + KNOWN_GOOD.length;
}

function markdownFiles(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const path = join(dir, name);
    let s;
    try {
      s = statSync(path);
    } catch {
      continue;
    }
    if (s.isDirectory()) markdownFiles(path, out);
    else if (name.endsWith(".md") && !SKIP_FILES.has(name)) out.push(path);
  }
  return out;
}

const corpusSize = selfCheck();

let failed = 0;
const files = markdownFiles(".");

if (files.length === 0) {
  // A gate that finds nothing to check is broken, not clean. This repository
  // has markdown; a scan that matches none of it is the failure mode that lets
  // a check stay green for its whole life without ever comparing anything.
  console.error("  FAIL  no markdown found: the scan is broken");
  process.exit(1);
}

for (const path of files) {
  const lines = readFileSync(path, "utf8").split("\n");
  for (const { text, line } of sentencesOf(lines)) {
    const window = lines.slice(Math.max(0, line - 5), line + 4).join("\n");
    const hit = verdictFor(text, window);
    if (hit === null) continue;
    console.error(
      `  FAIL  ${path}:${line}\n` +
        `        ${hit.replace(/\s+/g, " ").trim().slice(0, 120)}\n` +
        "        claims npm needs no sudo or root. On a distro-packaged Node,\n" +
        "        npm's global prefix is root-owned and `npm install -g` exits EACCES."
    );
    failed += 1;
  }
}

if (failed > 0) {
  console.error(`\ninstall-claims: ${failed} problem(s)`);
  process.exit(1);
}
console.log(
  `install-claims: clean (${files.length} markdown files, ${corpusSize} corpus cases)`
);
