import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
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
    const path = new URL(request.url ?? "/", `http://127.0.0.1:${port}`).pathname;
    if (path === "/healthz") {
      write(response, 200, "text/plain; charset=utf-8", "ok\n");
      return;
    }
    const fixtureFile = apiFiles.get(path);
    if (fixtureFile) {
      write(response, 200, "application/json; charset=utf-8", await regularFile(join(fixtureRoot, fixtureFile)));
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
