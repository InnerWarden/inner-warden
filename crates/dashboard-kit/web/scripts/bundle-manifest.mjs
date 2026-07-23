import { createHash } from "node:crypto";
import {
  lstat,
  readFile,
  readdir,
  writeFile,
} from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(scriptDirectory, "..");
const distRoot = join(webRoot, "dist");
const manifestPath = join(distRoot, "bundle-manifest.json");
const schema = "innerwarden.dashboard.bundle.v1";
const rootInputs = [
  "index.html",
  "package.json",
  "package-lock.json",
  "tsconfig.json",
  "vitest.config.ts",
  "vite.config.ts",
];

function portablePath(path) {
  return path.split(sep).join("/");
}

async function regularFiles(directory, kind = "input") {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const path = join(directory, entry.name);
    if (entry.isSymbolicLink()) {
      throw new Error(`bundle ${kind} must not be a symbolic link: ${portablePath(relative(webRoot, path))}`);
    }
    if (entry.isDirectory()) files.push(...await regularFiles(path, kind));
    else if (entry.isFile()) files.push(path);
  }
  return files;
}

async function sourceInputs() {
  const files = rootInputs.map((path) => join(webRoot, path));
  files.push(...await regularFiles(join(webRoot, "src")));
  files.push(...await regularFiles(join(webRoot, "scripts")));
  return files.sort((left, right) => portablePath(relative(webRoot, left))
    .localeCompare(portablePath(relative(webRoot, right))));
}

async function sourceDigest() {
  const inputs = [];
  for (const path of await sourceInputs()) {
    inputs.push({
      name: portablePath(relative(webRoot, path)),
      contents: await readFile(path, "utf8"),
    });
  }
  return digestEntries(inputs);
}

export function digestEntries(inputs) {
  const hash = createHash("sha256");
  for (const input of [...inputs].sort((left, right) => left.name.localeCompare(right.name))) {
    hash.update(input.name);
    hash.update("\0");
    hash.update(input.contents.replaceAll("\r\n", "\n"));
    hash.update("\0");
  }
  return `sha256:${hash.digest("hex")}`;
}

function manifestFor(digest, assets) {
  return {
    schema,
    source_digest: digest,
    entrypoint: "index.html",
    assets,
  };
}

export function assetRecord(path, contents) {
  return {
    path,
    sha256: `sha256:${createHash("sha256").update(contents).digest("hex")}`,
    size: contents.byteLength,
  };
}

export function assertExactAssetRecords(expected, actual) {
  const encodedExpected = JSON.stringify(expected);
  const encodedActual = JSON.stringify(actual);
  if (encodedExpected !== encodedActual) {
    throw new Error(`dashboard bundle asset inventory does not match: expected ${encodedExpected}, found ${encodedActual}`);
  }
}

async function distAssetRecords() {
  const paths = (await regularFiles(distRoot, "output"))
    .filter((path) => path !== manifestPath)
    .sort((left, right) => portablePath(relative(distRoot, left))
      .localeCompare(portablePath(relative(distRoot, right))));
  const records = [];
  for (const path of paths) {
    const name = portablePath(relative(distRoot, path));
    if (!safeRelativeAsset(name) || name === "bundle-manifest.json") {
      throw new Error(`unsafe dashboard bundle output path: ${name}`);
    }
    records.push(assetRecord(name, await readFile(path)));
  }
  return records;
}

function referencedAssets(indexHtml) {
  const references = new Set();
  for (const match of indexHtml.matchAll(/(?:src|href)="\.\/([^"?#]+)(?:[?#][^"]*)?"/g)) {
    references.add(match[1]);
  }
  return [...references].sort();
}

function safeRelativeAsset(path) {
  return path !== ""
    && !path.startsWith("/")
    && !path.includes("\\")
    && path.split("/").every((part) => part !== "" && part !== "." && part !== "..");
}

async function assertRegularFile(path, label) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} must be a regular file`);
  }
}

async function writeManifest() {
  await assertRegularFile(join(distRoot, "index.html"), "dist/index.html");
  const manifest = manifestFor(await sourceDigest(), await distAssetRecords());
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  process.stdout.write(`wrote dist/bundle-manifest.json (${manifest.source_digest})\n`);
}

async function checkManifest() {
  await assertRegularFile(manifestPath, "dist/bundle-manifest.json");
  await assertRegularFile(join(distRoot, "index.html"), "dist/index.html");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const expectedSourceDigest = await sourceDigest();
  if (manifest.schema !== schema
    || manifest.entrypoint !== "index.html"
    || manifest.source_digest !== expectedSourceDigest) {
    throw new Error(
      `dashboard bundle is stale: expected ${expectedSourceDigest}, found ${String(manifest.source_digest)}; run npm run build`,
    );
  }
  if (!Array.isArray(manifest.assets)) throw new Error("dashboard bundle manifest assets must be an array");
  const actualAssets = await distAssetRecords();
  assertExactAssetRecords(manifest.assets, actualAssets);

  const indexHtml = await readFile(join(distRoot, manifest.entrypoint), "utf8");
  const references = referencedAssets(indexHtml);
  if (references.length === 0) throw new Error("dist/index.html does not reference any built assets");
  for (const asset of references) {
    if (!safeRelativeAsset(asset)) throw new Error(`unsafe asset reference in dist/index.html: ${asset}`);
    await assertRegularFile(join(distRoot, asset), `dist/${asset}`);
  }
  process.stdout.write(`dashboard bundle is fresh (${manifest.source_digest}; ${manifest.assets.length} hashed files; ${references.length} entrypoint references)\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const mode = process.argv[2];
  try {
    if (mode === "write") await writeManifest();
    else if (mode === "check") await checkManifest();
    else throw new Error("usage: node scripts/bundle-manifest.mjs <write|check>");
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
