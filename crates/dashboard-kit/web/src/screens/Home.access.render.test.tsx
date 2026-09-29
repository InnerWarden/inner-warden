import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { Overview } from "../api";
import type { DashboardAccess } from "../api/v1";
import { auditTrailViewOf, parseDashboardBootstrap } from "../api/validate";
import { auditTrailOpener } from "../App";
import { setTechnicalDetail } from "../components/TechnicalDetail";
import { CONFIRMED_CHANGES_CLAIM, OverviewScreen, READ_ONLY_CLAIM, dashboardAccessClaim } from "./Home";
import communityOverview from "../../tests/fixtures/community/overview-no-lanes.json";
import enterpriseBootstrap from "../../tests/fixtures/enterprise/bootstrap.json";

/**
 * "This dashboard only reads; it changes nothing" was ticked on every host,
 * and the paid dashboard offers block, unblock, exclusions and a verdict on
 * each case. A tick that is false on the edition in front of a reviewer costs
 * every other tick on the page.
 */

const noop = () => undefined;

function render(edition: "community" | "enterprise", dashboardAccess?: DashboardAccess, onOpenAuditTrail?: () => void): string {
  return renderToStaticMarkup(
    <OverviewScreen
      overview={communityOverview as unknown as Overview}
      meta={{ edition }}
      edition={edition}
      dashboardAccess={dashboardAccess}
      onOpenActivity={noop}
      onOpenAuditTrail={onOpenAuditTrail}
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

/**
 * The claim says every change "lands in the admin audit trail". Where the
 * server names the screen that lists that trail (`audit_trail_view`) and the
 * shell offers it, the claim links to it; otherwise it reads as it did.
 */
describe("the way to the audit trail", () => {
  it("links the claim to the trail when the shell can open it", () => {
    const html = render("enterprise", undefined, noop);
    expect(html).toContain(`${CONFIRMED_CHANGES_CLAIM}<button type="button"`);
    expect(html).toContain(">See the audit trail</button>");
  });

  it("reads exactly as before without it, and never links a read-only claim", () => {
    expect(render("enterprise")).not.toContain("See the audit trail");
    expect(render("enterprise", "read_only", noop)).not.toContain("See the audit trail");
    expect(render("community", undefined, noop)).not.toContain("See the audit trail");
  });

  /**
   * FAILS ON REVERT: link any route the server names and the claim can lead
   * to a tab that does not exist, which lands back on the Overview.
   */
  it("opens only a screen the shell offers as a tab", () => {
    const opened: string[] = [];
    const navigation = [{ route: "overview", label: "Overview" }, { route: "audit", label: "Audit" }];
    auditTrailOpener("audit", navigation, (route) => void opened.push(route))?.();
    expect(opened).toEqual(["audit"]);
    expect(auditTrailOpener("history", navigation, noop)).toBeUndefined();
    expect(auditTrailOpener(undefined, navigation, noop)).toBeUndefined();
  });

  it("is read leniently from the bootstrap: a route name or nothing", () => {
    expect(parseDashboardBootstrap({ ...enterpriseBootstrap, audit_trail_view: "audit" }).audit_trail_view).toBe("audit");
    for (const bad of ["", "Audit", "../x", "a b", "x".repeat(65), 7, null]) {
      expect(auditTrailViewOf(bad), JSON.stringify(bad)).toBeUndefined();
      const parsed = parseDashboardBootstrap({ ...enterpriseBootstrap, audit_trail_view: bad });
      expect("audit_trail_view" in parsed).toBe(false);
      expect(parsed.edition).toBe("enterprise");
    }
    expect("audit_trail_view" in parseDashboardBootstrap(enterpriseBootstrap)).toBe(false);
  });
});
