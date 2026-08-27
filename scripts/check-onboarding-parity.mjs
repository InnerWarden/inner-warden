#!/usr/bin/env node
/**
 * Every documented way into the free product must reach the same wizard.
 *
 * WHY THIS EXISTS
 *
 * There are two front doors to the same binary and they behaved differently,
 * with nothing saying so:
 *
 *   curl -fsSL https://innerwarden.com/free | sh
 *       ends with `"$INSTALL_DIR/innerwarden" setup < /dev/tty`, i.e. the
 *       wizard opens by itself.
 *
 *   npm install -g innerwarden
 *       ends. npm runs nothing at install time and that is deliberate: there is
 *       no postinstall script, so `npm install --ignore-scripts` works and
 *       nothing executes before the operator asks. See npm/bin/innerwarden.js.
 *
 * So an operator arriving by npm got a binary and no next step, and
 * `npm/README.md` (which IS the npmjs.com package page) never mentioned
 * `innerwarden setup` at all. Two doors into one product, one of them opening
 * onto nothing.
 *
 * THE FIX IS DOCUMENTATION, AND THAT IS A DECISION, NOT A SHORTCUT
 *
 * npm cannot gain an install-time step without trading away the audit property
 * above, which is worth more than the convenience. So the npm path says the
 * second command out loud instead of running it.
 *
 * This gate exists because a difference that is only handled in prose drifts
 * back the moment somebody rewrites the prose.
 *
 * FAILS ON REVERT: remove the `innerwarden setup` line from the npm page and
 * this exits 1.
 *
 * Run: node scripts/check-onboarding-parity.mjs
 */

import { readFileSync } from "node:fs";

/** The verb both doors have to arrive at. */
const WIZARD = "innerwarden setup";

/**
 * Pages that document an install and must therefore name the wizard.
 *
 * `npm/README.md` first, because it is the one that is also the npmjs.com
 * package page and therefore the one most people read without ever seeing this
 * repository.
 */
const PAGES = [
  {
    path: "npm/README.md",
    why: "this file IS the npmjs.com package page; npm runs nothing at install time, so this is the only place the next step can appear",
  },
  {
    path: "README.md",
    why: "the repository front page offers npm as an install route",
  },
];

let failed = 0;

for (const { path, why } of PAGES) {
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    // A page that has vanished is a failure, not a skip: this gate exists to
    // notice change, and a missing file is the largest change there is.
    console.error(`  FAIL  ${path} is missing, so this check cannot run`);
    failed += 1;
    continue;
  }

  if (!text.includes("npm install -g innerwarden")) {
    // Not an install page any more. Nothing to require.
    continue;
  }

  if (!text.includes(WIZARD)) {
    console.error(
      `  FAIL  ${path}\n` +
        `        offers \`npm install -g innerwarden\` and never names \`${WIZARD}\`.\n` +
        `        ${why}.\n` +
        "        The shell installer at innerwarden.com/free opens the wizard by\n" +
        "        itself; npm deliberately runs nothing, so this page has to say so."
    );
    failed += 1;
  }
}

if (failed > 0) {
  console.error(`\nonboarding-parity: ${failed} page(s) leave an npm user with no next step`);
  process.exit(1);
}

console.log(`onboarding-parity: clean (${PAGES.length} install pages checked)`);
