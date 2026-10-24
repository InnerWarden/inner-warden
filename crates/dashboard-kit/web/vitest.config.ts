import { defineConfig } from "vitest/config";

// Every time the pages print is in the reader's own zone, so the unit suite
// runs in one zone, as the browser suite does (`timezoneId: "UTC"`): a test
// that passes in UTC then passes on every machine, east of UTC+10 too. A test
// about another zone pins it itself (`test-support/zone.ts`).
process.env.TZ = "UTC";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    env: { TZ: "UTC" },
  },
});
