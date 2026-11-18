#!/usr/bin/env node
// The shared stylesheet must not grow.
//
// A bundle that composes this kit builds its stylesheet from the kit's shared
// files and leaves the Community pages out (`@source not "./community"`). Its
// CSS budget has little room, so a utility class a shared file starts to use
// is paid for there, by a build that never draws a Community page. This
// builds the stylesheet those shared files produce, the way
// `@tailwindcss/vite` builds it (compile, scan, build, optimize), and
// compares its size and digest with the committed baseline.
//
//   node scripts/shared-css.mjs check   fail on any difference from the baseline
//   node scripts/shared-css.mjs write   record the current stylesheet as the baseline
//
// `npm run css:shared -- write` passes "write" after "check"; the last mode
// named wins, so that spelling writes.
//
// The numbers are this script's, not the composing build's: Vite minifies
// again after Tailwind, and the composed tree adds files of its own. Growth is
// caught in relative terms all the same, because the baseline comes from the
// same script on the same inputs.

import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { compile, optimize } from "@tailwindcss/node";
import { Scanner } from "@tailwindcss/oxide";

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const srcRoot = join(webRoot, "src");
const entry = join(srcRoot, "index.css");
const baselinePath = join(webRoot, "shared-css.baseline.json");

export const GROWTH_MESSAGE =
  "a new utility in a shared file reaches the paid stylesheet: reuse a class a shared file already uses";
export const CHANGED_MESSAGE =
  "shared stylesheet changed: rewrite the baseline with npm run css:shared -- write and say why in the commit";

/** The stylesheet the shared files produce, with the Community pages left out. */
export async function sharedStylesheet() {
  const css = `${await readFile(entry, "utf8")}\n@source not "./community";\n`;
  const compiler = await compile(css, {
    base: srcRoot,
    shouldRewriteUrls: true,
    onDependency: () => undefined,
  });
  const roots = compiler.root === "none"
    ? []
    : compiler.root === null
      ? [{ base: srcRoot, pattern: "**/*", negated: false }]
      : [{ ...compiler.root, negated: false }];
  const scanner = new Scanner({ sources: roots.concat(compiler.sources) });
  const candidates = [...new Set(scanner.scan())].sort();
  return optimize(compiler.build(candidates), { minify: true }).code;
}

export function measure(stylesheet) {
  const bytes = Buffer.byteLength(stylesheet, "utf8");
  const sha256 = `sha256:${createHash("sha256").update(stylesheet, "utf8").digest("hex")}`;
  return { bytes, sha256 };
}

/** What a check says about the stylesheet against the baseline, or `undefined` when they agree. */
export function verdict(baseline, current) {
  if (current.bytes > baseline.bytes) return GROWTH_MESSAGE;
  if (current.bytes !== baseline.bytes || current.sha256 !== baseline.sha256) return CHANGED_MESSAGE;
  return undefined;
}

async function readBaseline() {
  const parsed = JSON.parse(await readFile(baselinePath, "utf8"));
  if (!Number.isSafeInteger(parsed.bytes) || typeof parsed.sha256 !== "string" || !/^sha256:[0-9a-f]{64}$/.test(parsed.sha256)) {
    throw new Error("shared-css.baseline.json must hold { bytes, sha256 }");
  }
  return { bytes: parsed.bytes, sha256: parsed.sha256 };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const modes = process.argv.slice(2).filter((arg) => arg === "check" || arg === "write");
  const mode = modes.at(-1);
  try {
    if (mode === undefined) throw new Error("usage: node scripts/shared-css.mjs <check|write>");
    const current = measure(await sharedStylesheet());
    if (mode === "write") {
      await writeFile(baselinePath, `${JSON.stringify(current, null, 2)}\n`, "utf8");
      process.stdout.write(`wrote shared-css.baseline.json (${current.bytes} bytes, ${current.sha256})\n`);
    } else {
      const baseline = await readBaseline();
      const problem = verdict(baseline, current);
      if (problem !== undefined) {
        process.stderr.write(`${problem}\n  baseline: ${baseline.bytes} bytes, ${baseline.sha256}\n  now:      ${current.bytes} bytes, ${current.sha256}\n`);
        process.exitCode = 1;
      } else {
        process.stdout.write(`shared stylesheet unchanged (${current.bytes} bytes, ${current.sha256})\n`);
      }
    }
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
