import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { existsSync, statSync } from "node:fs";
import { dirname, extname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const testsRoot = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(testsRoot, "..");
const distRoot = join(webRoot, "dist");
const argumentsByName = new Map();
for (let index = 2; index < process.argv.length; index += 2) {
  argumentsByName.set(process.argv[index], process.argv[index + 1]);
}
const fixture = argumentsByName.get("--fixture");
const port = Number.parseInt(argumentsByName.get("--port") ?? "", 10);
if (!(["community", "enterprise"].includes(fixture)) || !Number.isInteger(port) || port < 1024 || port > 65_535) {
  throw new Error("usage: fixture-server.mjs --fixture <community|enterprise> --port <1024..65535>");
}

const fixtureRoot = join(testsRoot, "fixtures", fixture);
// These paths must be the ones the BUNDLE asks for. They drifted: the client
// moved to `api/guard/*` and this map stayed on `/api/*`, so every browser test
// loaded a shell whose overview and meta both 404'd. Fifteen Community specs
// were asserting against "The local dashboard is unavailable" and the browser
// suite is not part of CI, so nothing said so. See `fetchMeta`, `fetchOverview`,
// `fetchAgents` and `fetchTokenIntelligence` in `src/api.ts`.
const apiFiles = fixture === "community"
  ? new Map([
    ["/api/dashboard/v1/bootstrap", "bootstrap.json"],
    ["/api/guard/meta", "meta.json"],
    ["/api/guard/overview", "overview.json"],
    ["/api/guard/agents", "agents.json"],
    ["/api/guard/token-intelligence", "token-intelligence.json"],
    ["/api/guard/protection", "protection.json"],
    ["/api/guard/record-health", "record-health.json"],
    ["/api/guard/suppress", "suppress.json"],
  ])
  : new Map([
    ["/api/dashboard/v1/bootstrap", "bootstrap.json"],
    ["/api/dashboard/v1/posture", "posture.json"],
    ["/api/guard/meta", "meta.json"],
    // The SAME drift the paragraph above describes, left unfixed on this half.
    // The Community map was corrected and this one kept three routes while the
    // shared shell fetches five, so `fetchOverview` 404'd, `Home` rendered its
    // `FullError` ("The local dashboard is unavailable"), and every spec that
    // navigates to this server asserted against that error page instead of
    // against the product. Nineteen specs, and nothing ran them here either.
    ["/api/guard/overview", "overview.json"],
    ["/api/guard/agents", "agents.json"],
    ["/api/guard/token-intelligence", "token-intelligence.json"],
  ]);

// Scenarios: the same screens in the states a reader meets. A request that
// carries the cookie `iw-fixture=<scenario>` is answered from
// `fixtures/community/scenarios/<scenario>/` first and the plain files
// second; a scenario lists the routes its server does not serve in
// `404.json` and those it cannot answer in `503.json`. The CLI's fixture
// writer renders every scenario file it has a builder for
// (`community_fixtures_match_what_the_cli_serves`); the files below are
// written by hand because their route has no pure builder, each with why.
const HAND_WRITTEN = [
  ["enforce/meta.json", "the host mode comes from guard/meta, which has no pure builder: every agent here is in enforce"],
  ["mixed/meta.json", "the host mode comes from guard/meta: one agent in monitor, one in enforce"],
  ["no-agents/meta.json", "the host mode comes from guard/meta: no agent is connected"],
  ["never-screened/meta.json", "the host mode comes from guard/meta: both agents in monitor"],
  ["unknown/meta.json", "the host mode comes from guard/meta: it is unknown while the agents cannot be read"],
  ["exposed/meta.json", "whether the dashboard is open to the network comes from guard/meta"],
  ["ad-installed/meta.json", "whether Active Defence is installed comes from guard/meta"],
  ["not-recording/record-health.json", "guard/record-health reads a live outage file, which has no pure builder"],
];

const scenarioRoot = join(fixtureRoot, "scenarios");
if (fixture === "community") {
  for (const [file] of HAND_WRITTEN) {
    if (!existsSync(join(scenarioRoot, file))) throw new Error(`hand-written scenario file is missing: ${file}`);
  }
}

/** The scenario a request asked for by cookie, or `undefined` for the plain files. */
function scenarioOf(request) {
  for (const part of (request.headers.cookie ?? "").split(";")) {
    const [name, value] = part.trim().split("=");
    if (name !== "iw-fixture" || value === undefined || value === "identity") continue;
    if (!/^[a-z][a-z-]{0,39}$/.test(value)) return undefined;
    try {
      return statSync(join(scenarioRoot, value)).isDirectory() ? value : undefined;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

/** A fixture file: the scenario's own when it has one, else the plain one. */
async function fixtureFile(scenario, name) {
  if (scenario !== undefined) {
    const own = join(scenarioRoot, scenario, name);
    if (existsSync(own)) return regularFile(own);
  }
  return regularFile(join(fixtureRoot, name));
}

/** The routes a scenario lists in `404.json` or `503.json`. */
async function routeList(scenario, name) {
  if (scenario === undefined) return [];
  try {
    const list = JSON.parse(await readFile(join(scenarioRoot, scenario, name), "utf8"));
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

// The paid shell's plan notice: a request that carries the cookie
// `iw-plan=<plan>` is answered a bootstrap with that `plan_notice`.
// `renewed` (or `renewed-run<id>`, so two runs never share a count) is a
// sequence: the first bootstrap read under that cookie is in free mode and
// every later one is active, the move the notice confirms as a renewal.
const PLAN_BOOTSTRAPS = new Map([
  ["free-mode", ["bootstrap-plan-free-mode.json"]],
  ["ending-soon", ["bootstrap-plan-ending-soon.json"]],
  ["renewed", ["bootstrap-plan-renewed-1.json", "bootstrap-plan-renewed-2.json"]],
]);
const planReads = new Map();

/** The bootstrap file a plan cookie asks for, or `undefined` for the plain one. */
function planBootstrap(request) {
  for (const part of (request.headers.cookie ?? "").split(";")) {
    const [name, value] = part.trim().split("=");
    if (name !== "iw-plan" || value === undefined || !/^[a-z][a-z-]{0,39}(?:-[a-z0-9]{1,16})?$/.test(value)) continue;
    const plan = [...PLAN_BOOTSTRAPS.keys()].find((key) => value === key || value.startsWith(`${key}-run`));
    if (plan === undefined) return undefined;
    const files = PLAN_BOOTSTRAPS.get(plan);
    const read = planReads.get(value) ?? 0;
    planReads.set(value, read + 1);
    return files[Math.min(read, files.length - 1)];
  }
  return undefined;
}

const mime = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".svg", "image/svg+xml"],
]);

function write(response, status, contentType, body) {
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": contentType,
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}

async function regularFile(path) {
  const metadata = await stat(path);
  if (!metadata.isFile()) throw new Error("not a regular file");
  return readFile(path);
}

function withinDist(path) {
  const child = relative(distRoot, path);
  return child !== "" && child !== ".." && !child.startsWith(`..${sep}`) && !child.includes(`..${sep}`);
}

const server = createServer(async (request, response) => {
  try {
    if (request.method !== "GET") {
      write(response, 405, "application/json; charset=utf-8", JSON.stringify({ error: "method_not_allowed" }));
      return;
    }
    const address = new URL(request.url ?? "/", `http://127.0.0.1:${port}`);
    const path = address.pathname;
    if (path === "/healthz") {
      write(response, 200, "text/plain; charset=utf-8", "ok\n");
      return;
    }
    // Community's routes that answer by query, from the files the CLI's own
    // fixture writer rendered (`community_fixtures_match_what_the_cli_serves`).
    if (fixture === "community") {
      const json = "application/json; charset=utf-8";
      const scenario = scenarioOf(request);
      if ((await routeList(scenario, "404.json")).includes(path)) {
        write(response, 404, json, JSON.stringify({ error: "not found" }));
        return;
      }
      if ((await routeList(scenario, "503.json")).includes(path)) {
        write(response, 503, json, JSON.stringify({ error: "unavailable" }));
        return;
      }
      // The identity screens: a journey that sets the cookie
      // `iw-fixture=identity` is served what the CLI answers with a profiles
      // file and a launcher's records (the `*-identity` files); every other
      // request gets the plain files, as before.
      const identity = (request.headers.cookie ?? "").split(";").some((part) => part.trim() === "iw-fixture=identity");
      if (identity && path === "/api/guard/agents") {
        write(response, 200, json, await regularFile(join(fixtureRoot, "agents-identity.json")));
        return;
      }
      if (identity && path === "/api/guard/history" && address.searchParams.get("kind") !== "attempt") {
        write(response, 200, json, await regularFile(join(fixtureRoot, "history-identity.json")));
        return;
      }
      if (identity && path === "/api/guard/decision") {
        const all = JSON.parse(await readFile(join(fixtureRoot, "decisions-identity-by-id.json"), "utf8"));
        const found = all[address.searchParams.get("id") ?? ""];
        if (found !== undefined) {
          write(response, 200, json, JSON.stringify(found));
          return;
        }
      }
      if (path === "/api/guard/decisions") {
        const file = address.searchParams.has("cursor") ? "decisions-page-2.json" : "decisions-page-1.json";
        const page = JSON.parse(String(await fixtureFile(scenario, file)));
        // `verdict` (the Overview's newest denies) keeps the rows whose rules
        // said that verdict, as the CLI filters them, and counts what matched.
        const verdict = address.searchParams.get("verdict");
        if (verdict !== null) {
          page.items = page.items.filter((item) => item.recommendation === verdict);
          page.total = page.items.length;
          delete page.next_cursor;
        }
        // A smaller page (the Overview's three) is the first rows of the same
        // page, with the cursor the server would send after them.
        const limit = Number.parseInt(address.searchParams.get("limit") ?? "", 10);
        if (Number.isInteger(limit) && limit > 0 && limit < page.items.length) page.items = page.items.slice(0, limit);
        write(response, 200, json, JSON.stringify(page));
        return;
      }
      if (path === "/api/guard/decision") {
        const all = JSON.parse(String(await fixtureFile(scenario, "decisions-by-id.json")));
        const found = all[address.searchParams.get("id") ?? ""];
        if (found === undefined) write(response, 404, json, JSON.stringify({ error: "decision_not_in_record" }));
        else write(response, 200, json, JSON.stringify(found));
        return;
      }
      if (path === "/api/guard/history") {
        const file = address.searchParams.get("kind") === "attempt" ? "history-attempts.json" : "history.json";
        write(response, 200, json, await fixtureFile(scenario, file));
        return;
      }
      // Bounded as the CLI bounds it: 1 to 50, default 20, otherwise a 400 with its code.
      if (path === "/api/guard/sessions") {
        const raw = address.searchParams.get("limit");
        const limit = raw === null ? 20 : /^\d+$/.test(raw) ? Number.parseInt(raw, 10) : Number.NaN;
        if (!Number.isInteger(limit) || limit < 1 || limit > 50) {
          write(response, 400, json, JSON.stringify({ error: "limit_invalid" }));
          return;
        }
        const page = JSON.parse(String(await fixtureFile(scenario, "sessions.json")));
        page.items = page.items.slice(0, limit);
        write(response, 200, json, JSON.stringify(page));
        return;
      }
      const name = apiFiles.get(path);
      if (name) {
        write(response, 200, json, await fixtureFile(scenario, name));
        return;
      }
    }
    if (fixture === "enterprise" && path === "/api/dashboard/v1/bootstrap") {
      const plan = planBootstrap(request);
      if (plan !== undefined) {
        write(response, 200, "application/json; charset=utf-8", await regularFile(join(fixtureRoot, plan)));
        return;
      }
    }
    const fixtureName = apiFiles.get(path);
    if (fixtureName) {
      write(response, 200, "application/json; charset=utf-8", await regularFile(join(fixtureRoot, fixtureName)));
      return;
    }
    if (path.startsWith("/api/")) {
      write(response, 404, "application/json; charset=utf-8", JSON.stringify({ error: "fixture_endpoint_absent" }));
      return;
    }

    const requested = path === "/" ? join(distRoot, "index.html") : resolve(distRoot, `.${path}`);
    if (!withinDist(requested)) {
      write(response, 404, "text/plain; charset=utf-8", "not found\n");
      return;
    }
    write(response, 200, mime.get(extname(requested)) ?? "application/octet-stream", await regularFile(requested));
  } catch {
    write(response, 404, "text/plain; charset=utf-8", "not found\n");
  }
});

server.listen(port, "127.0.0.1");
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
