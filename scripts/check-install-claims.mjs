#!/usr/bin/env node
/**
 * No document in this repository may claim `npm install -g` needs no root.
 *
 * WHY THIS EXISTS, AND WHY IT IS THE SECOND ONE
 *
 * A gate with this job already shipped, in the website repository, and it was
 * written as `DOCS = "client/src/content/docs"`. That is a scan of a DIRECTORY,
 * not a gate on a CLAIM, so the same false sentence survived here in three
 * files, and the worst of them is the one most people read:
 *
 *   npm/README.md:  "Same install on Linux, macOS, and Windows, no `curl | sh`, no `sudo`"
 *
 * `npm/README.md` is in `package.json`'s `files` array, so it IS the npmjs.com
 * package page. It told every reader that npm needs no root, and dispensed with
 * the one install path that genuinely does not, while `npm install -g` exits
 * EACCES on any Linux with a distro-packaged Node. Measured on a clean Ubuntu
 * 26.04 machine: the first command a new user runs fails.
 *
 * So the rule here is about the sentence, and the scan covers every markdown
 * file in the repository rather than one directory. If somebody adds a fourth
 * place to say it, this finds it there too.
 *
 * FAILS ON REVERT: restore any of those three sentences and this exits 1.
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

/** Asserting no elevation is needed, in the shapes it actually appeared in. */
const NO_ELEVATION = /\bno (?:sudo|root|sudo\/root|sudo or root)\b/i;

/**
 * The sentence is contrasting npm with the rootless path, or naming the failure
 * outright, rather than claiming npm needs nothing. That is correct prose and
 * must not be punished, or the gate gets muted.
 */
const CONTRASTS = /innerwarden\.com\/free|shell installer|EACCES|root-owned|sudo npm|needs `?sudo`?/i;

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
  lines.forEach((line, i) => {
    // Two different scopes, deliberately.
    //
    // The CLAIM is judged per sentence, because a line-wide window flags true
    // statements that merely sit near the word npm ("or use the shell
    // installer, which needs no root on any platform").
    //
    // Whether npm is the SUBJECT is judged per line, because the claim often
    // does not repeat the word. Both of these are about npm and neither
    // contains it:
    //
    //   npm (every OS, prebuilt and signed, no sudo):
    //   … `npm install -g innerwarden`. Prebuilt, signed provenance, no sudo, no postinstall.
    //
    // A first cut required npm in the SENTENCE and let two of three through. A
    // second required it in the LINE and still let one through, because the
    // sentence introduces a fenced block and the command is three lines below:
    //
    //   Same install on Linux, macOS, and Windows, no sudo:
    //
    //   ```sh
    //   npm install -g innerwarden
    //   ```
    //
    // So the subject is established by the BLOCK. A window of four lines either
    // side covers a sentence and the fence it introduces, and is still narrow
    // enough that an unrelated npm mention elsewhere on the page does not drag
    // a true statement into the net.
    //
    // Each of the three known sentences was reverted SEPARATELY to find this.
    // Reverting only one would have shipped a gate that catches a third of what
    // it claims to.
    const window = lines.slice(Math.max(0, i - 4), i + 5).join("\n");
    if (!/\bnpm\b/i.test(window)) return;
    for (const sentence of line.split(/(?<=\.)\s+/)) {
      if (!NO_ELEVATION.test(sentence)) continue;
      if (CONTRASTS.test(sentence)) continue;
      console.error(
        `  FAIL  ${path}:${i + 1}\n` +
          "        claims npm needs no sudo or root. On a distro-packaged Node,\n" +
          "        npm's global prefix is root-owned and `npm install -g` exits EACCES."
      );
      failed += 1;
    }
  });
}

if (failed > 0) {
  console.error(`\ninstall-claims: ${failed} problem(s)`);
  process.exit(1);
}
console.log(`install-claims: clean (${files.length} markdown files checked)`);
