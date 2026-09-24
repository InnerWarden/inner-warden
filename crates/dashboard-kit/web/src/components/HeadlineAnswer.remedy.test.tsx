import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { deriveShellNavigation } from "../App";
import type { DashboardBootstrap } from "../api/v1";
import { VERDICTS } from "../screens/Activity";
import { decisionRecordCta } from "../screens/Home";
import casesBootstrap from "../../tests/fixtures/enterprise/cases-bootstrap.json";
import { CaseFilters, EMPTY_CASE_VIEW } from "./CaseFilters";
import { headline } from "./HeadlineAnswer";

/**
 * THE DEFECT THESE PIN
 *
 * When the agent guardrail had actions flagged for review, the headline told
 * EVERY reader "Open Activity and filter by Needs review.". Enterprise has no
 * Activity tab, so a paid reader was sent to a screen that does not exist, and
 * the only "Needs review" they could find was the Cases status filter: a case
 * status, not a guardrail verdict, and a different count from the number in
 * the headline.
 *
 * Each remedy is checked against the controls the reader actually has, read
 * from the code that draws them (the shell's navigation, Activity's filter
 * buttons, the rendered Cases filters), not against a copy of the sentence.
 */

const queued = {
  needsReview: 3,
  recentShowsDecisions: true,
  denyVerdicts: 0,
  blockedBeforeExecution: 0,
  wouldBlock: 0,
  screened: 0,
  outcomesUnknown: 0,
  deniesWithoutBlock: 0,
  monitorOnly: false,
  unprovenAgents: 0,
};

function tabLabels(navigation: { label: string }[]): string[] {
  return navigation.map((item) => item.label);
}

const casesFilters = renderToStaticMarkup(
  <CaseFilters value={EMPTY_CASE_VIEW} onApply={() => undefined} onClear={() => undefined} />,
);

/**
 * The options of the ONE select whose visible label is `label`, as rendered.
 *
 * Matching an option's text anywhere in the form is not enough: "The agent
 * guardrail" is the text of two options, one under Decision authority
 * (`agent-guard`) and one under Capability (`agent_boundary`). A remedy that
 * says "set Capability" has to be checked against a control labelled
 * Capability that holds that option, or renaming the control leaves the
 * sentence naming something the reader cannot find.
 */
function optionsOf(markup: string, label: string): string {
  const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const found = new RegExp(`>${escaped}<select[^>]*>(.*?)</select>`, "s").exec(markup);
  if (found === null) throw new Error(`no select labelled ${label} in the rendered Cases filters`);
  return found[1];
}

describe("the review remedy names a control the reader has", () => {
  it("sends Community to Activity and the verdict filter that lists exactly these", () => {
    const where = decisionRecordCta("community", false).kind;
    const next = headline({ ...queued, reviewListedIn: where }).next ?? "";

    // The tab and the button it names both exist on Community.
    expect(tabLabels(deriveShellNavigation(undefined, "community"))).toContain("Activity");
    expect(VERDICTS.find(([value]) => value === "review")?.[1]).toBe("Needs review");
    expect(next).toContain("Open Activity");
    expect(next).toContain("Needs review");
  });

  it("never sends Enterprise to Activity, which its shell does not offer", () => {
    const where = decisionRecordCta("enterprise", true).kind;
    const next = headline({ ...queued, reviewListedIn: where }).next ?? "";

    // The reason: a paid shell has no Activity tab to open.
    const enterpriseTabs = tabLabels(
      deriveShellNavigation(casesBootstrap as unknown as DashboardBootstrap, "enterprise"),
    );
    expect(enterpriseTabs).not.toContain("Activity");
    expect(next).not.toContain("Activity");
  });

  it("sends Enterprise through the Cases button and the agent guardrail filter, never the host status", () => {
    const cta = decisionRecordCta("enterprise", true);
    const next = headline({ ...queued, reviewListedIn: cta.kind }).next ?? "";

    // The button it names is the one beside the headline.
    expect(next).toContain(cta.label);
    // The control it names is a select labelled Capability, and the option it
    // names is inside THAT select, not merely somewhere in the form.
    expect(next).toContain('set Capability to "The agent guardrail"');
    expect(optionsOf(casesFilters, "Capability")).toContain('<option value="agent_boundary">The agent guardrail</option>');
    // "Needs review" on Cases is a case status, not a guardrail verdict.
    // Naming it here is the exact collision this remedy replaced.
    expect(optionsOf(casesFilters, "Status")).toContain('<option value="needs_review">Needs review</option>');
    expect(next).not.toContain("Needs review");
    expect(next).toContain("not host cases");
  });

  it("names no screen when the shell has nowhere to list them", () => {
    const where = decisionRecordCta("enterprise", false).kind;
    expect(where).toBe("hidden");
    const next = headline({ ...queued, reviewListedIn: where }).next ?? "";
    expect(next).not.toContain("Activity");
    expect(next).not.toContain("Cases");
    expect(next).toContain("no screen in this installation lists them all");
  });

  /**
   * The 'hidden' remedy pointed at "Recent activity below" on every host. An
   * older host sends only `recent_blocks`, which holds deny verdicts alone, so
   * a review verdict never shows there; and an empty list renders "No recent
   * decisions are available yet." directly under the sentence. The pointer is
   * made only when the section really lists decisions with their verdicts.
   */
  it("points at Recent activity only when it lists decisions", () => {
    const listed = headline({ ...queued, reviewListedIn: "hidden", recentShowsDecisions: true }).next ?? "";
    expect(listed).toContain("Recent activity below shows the latest decisions");

    const nothingListed = headline({ ...queued, reviewListedIn: "hidden", recentShowsDecisions: false }).next ?? "";
    expect(nothingListed).not.toContain("Recent activity");
    // Still says why no screen is named, rather than going quiet.
    expect(nothingListed).toContain("agent guardrail's verdicts");
    expect(nothingListed).toContain("No screen in this installation lists them");
  });

  it("says the number is the agent's, on every product", () => {
    for (const where of ["activity", "cases", "hidden"] as const) {
      const result = headline({ ...queued, reviewListedIn: where });
      expect(result.answer).toBe("3 agent actions were flagged for review");
      expect(result.tone).toBe("attention");
    }
  });
});
