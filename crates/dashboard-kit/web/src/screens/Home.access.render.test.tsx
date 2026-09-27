import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { Overview } from "../api";
import type { DashboardAccess } from "../api/v1";
import { parseDashboardBootstrap } from "../api/validate";
import { setTechnicalDetail } from "../components/TechnicalDetail";
import { CONFIRMED_CHANGES_CLAIM, OverviewScreen, READ_ONLY_CLAIM, dashboardAccessClaim } from "./Home";
import communityOverview from "../../tests/fixtures/community/overview.json";
import enterpriseBootstrap from "../../tests/fixtures/enterprise/bootstrap.json";

/**
 * "This dashboard only reads; it changes nothing" was ticked on every host,
 * and the paid dashboard offers block, unblock, exclusions and a verdict on
 * each case. A tick that is false on the edition in front of a reviewer costs
 * every other tick on the page.
 */

const noop = () => undefined;

function render(edition: "community" | "enterprise", dashboardAccess?: DashboardAccess): string {
  return renderToStaticMarkup(
    <OverviewScreen
      overview={communityOverview as unknown as Overview}
      meta={{ edition }}
      edition={edition}
      dashboardAccess={dashboardAccess}
      onOpenActivity={noop}
    />,
  );
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date("2026-09-25T12:00:00Z"));
  setTechnicalDetail(false);
});

afterEach(() => {
  vi.useRealTimers();
});

describe("what the Overview says this dashboard changes", () => {
  it("follows the server's word when it gave one", () => {
    expect(dashboardAccessClaim("enterprise", "read_only")).toBe(READ_ONLY_CLAIM);
    expect(dashboardAccessClaim("community", "confirmed_changes")).toBe(CONFIRMED_CHANGES_CLAIM);
  });

  it("reads an older server by its edition, and claims nothing without one", () => {
    expect(dashboardAccessClaim("community", undefined)).toBe(READ_ONLY_CLAIM);
    expect(dashboardAccessClaim("enterprise", undefined)).toBe(CONFIRMED_CHANGES_CLAIM);
    expect(dashboardAccessClaim(undefined, undefined)).toBeUndefined();
  });

  /**
   * FAILS ON REVERT: hard-code the read-only line in the hero again and the
   * paid page ticks it.
   */
  it("never ticks the read-only line on a paid dashboard that did not say it", () => {
    const html = render("enterprise");
    expect(html).not.toContain(READ_ONLY_CLAIM);
    expect(html).toContain(CONFIRMED_CHANGES_CLAIM);
  });

  it("keeps the read-only line where it is true", () => {
    expect(render("community")).toContain(READ_ONLY_CLAIM);
    expect(render("enterprise", "read_only")).toContain(READ_ONLY_CLAIM);
    expect(render("enterprise", "read_only")).not.toContain(CONFIRMED_CHANGES_CLAIM);
  });
});

describe("the bootstrap's dashboard_access", () => {
  it("is kept when the server sends a value this bundle knows", () => {
    expect(parseDashboardBootstrap({ ...enterpriseBootstrap, dashboard_access: "read_only" }).dashboard_access).toBe("read_only");
    expect(parseDashboardBootstrap({ ...enterpriseBootstrap, dashboard_access: "confirmed_changes" }).dashboard_access).toBe("confirmed_changes");
  });

  it("is read as not sent when unknown, and never refuses the bootstrap over it", () => {
    const parsed = parseDashboardBootstrap({ ...enterpriseBootstrap, dashboard_access: "admin" });
    expect("dashboard_access" in parsed).toBe(false);
    expect(parsed.edition).toBe("enterprise");
  });

  it("adds no key to an older server's bootstrap", () => {
    expect("dashboard_access" in parseDashboardBootstrap(enterpriseBootstrap)).toBe(false);
  });
});
