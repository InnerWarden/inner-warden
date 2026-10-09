import { defineConfig, devices } from "@playwright/test";

const inCi = Boolean(process.env.CI);

export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  forbidOnly: inCi,
  retries: 0,
  workers: 1,
  timeout: 15_000,
  expect: { timeout: 5_000 },
  outputDir: "test-results",
  reporter: inCi ? [["line"], ["html", { open: "never" }]] : "line",
  use: {
    actionTimeout: 5_000,
    navigationTimeout: 10_000,
    colorScheme: "light",
    locale: "en-US",
    timezoneId: "UTC",
    reducedMotion: "reduce",
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "off",
  },
  webServer: [
    {
      command: "node tests/fixture-server.mjs --fixture community --port 4173",
      url: "http://127.0.0.1:4173/healthz",
      timeout: 30_000,
      reuseExistingServer: !inCi,
      stdout: "pipe",
      stderr: "pipe",
    },
    {
      command: "node tests/fixture-server.mjs --fixture enterprise --port 4174",
      url: "http://127.0.0.1:4174/healthz",
      timeout: 30_000,
      reuseExistingServer: !inCi,
      stdout: "pipe",
      stderr: "pipe",
    },
  ],
  // Each project names its directory. A `testMatch` regex is applied to the
  // ABSOLUTE path, so `/community\/.*\.spec\.ts/` matched every spec of a
  // checkout that sits under any directory ending in "community" (a worktree
  // named `...-community` ran the enterprise and acceptance specs in this
  // project, against the wrong server).
  projects: [
    {
      name: "community-chromium",
      testDir: "./tests/community",
      testMatch: /\.spec\.ts$/,
      use: {
        ...devices["Desktop Chrome"],
        baseURL: "http://127.0.0.1:4173",
      },
    },
    {
      name: "enterprise-chromium",
      testDir: "./tests/enterprise",
      testMatch: /\.spec\.ts$/,
      use: {
        ...devices["Desktop Chrome"],
        baseURL: "http://127.0.0.1:4174",
      },
    },
    {
      // T155 acceptance/performance. Serves the production dist/ from the
      // community fixture server; each test page.route()s the exact API it needs
      // (community or enterprise), so it stays deterministic and fixture-only.
      name: "acceptance-chromium",
      testDir: "./tests/acceptance",
      testMatch: /\.spec\.ts$/,
      use: {
        ...devices["Desktop Chrome"],
        baseURL: "http://127.0.0.1:4173",
      },
    },
  ],
});
