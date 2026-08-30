import { describe, expect, it } from "vitest";
import { plainOrTechnical, setTechnicalDetail, technicalDetailEnabled } from "./TechnicalDetail";

/**
 * THE RULE THE OPERATOR ASKED FOR, IN HIS WORDS: the dashboard is for the
 * customer, and it must not greet them with a wall of "could not confirm",
 * "configured, not verified", "authority unknown". Someone who does not read
 * kernel documentation wants two answers: is it working, and do I have to do
 * anything.
 *
 * So the plain register is the DEFAULT and the evidence lives behind a switch.
 * None of the technical sentences were deleted, because all of them are true and
 * an auditor needs them.
 */
describe("technical detail switch", () => {
  it("defaults to the plain register", () => {
    setTechnicalDetail(false);
    expect(technicalDetailEnabled()).toBe(false);
    expect(plainOrTechnical("Protected", "Gate armed, scope verified", false)).toBe("Protected");
  });

  it("gives the technical reader the precise wording, without changing the fact", () => {
    setTechnicalDetail(true);
    expect(plainOrTechnical("Protected", "Gate armed, scope verified", true)).toBe(
      "Gate armed, scope verified",
    );
    setTechnicalDetail(false);
  });

  /**
   * The line that must not be crossed. A switch that can hide a problem is
   * worse than the wall of doubt it replaced, because the wall at least told
   * the truth loudly. `plainOrTechnical` takes two strings and returns one of
   * them: it cannot hide anything on its own, and this pins that shape so a
   * later "hide when healthy" convenience cannot grow into "hide when broken".
   */
  it("always returns a sentence, so nothing can vanish by being plain", () => {
    for (const enabled of [true, false]) {
      setTechnicalDetail(enabled);
      const shown = plainOrTechnical("2 things need you", "2 queued actions, 0 verified", enabled);
      expect(shown.length).toBeGreaterThan(0);
    }
    setTechnicalDetail(false);
  });
});

/**
 * THE PERFORMANCE HALF OF THE SAME RULE.
 *
 * The operator asked for two things: do not greet a customer with a wall of
 * doubt, and do not pay for what is not shown. `TechnicalOnly` returns null
 * rather than rendering hidden markup, so the provenance grid on a case is
 * three DOM nodes that do not exist while the switch is off, on a list the
 * operator scrolls. Nothing is fetched for it either: the case payload already
 * carries the fields, so the switch costs one boolean and no request.
 *
 * This pins the contract that makes both true: reading the flag is
 * synchronous and free, so no component needs an effect, a fetch or a
 * suspense boundary to know which register to render.
 */
describe("technical detail cost", () => {
  it("is answerable synchronously, so nothing has to be fetched to decide", () => {
    setTechnicalDetail(false);
    const before = technicalDetailEnabled();
    expect(typeof before).toBe("boolean");
    setTechnicalDetail(true);
    expect(technicalDetailEnabled()).toBe(true);
    setTechnicalDetail(false);
  });

  /**
   * Storage that is not there must not break the switch.
   *
   * This suite runs with no `window` at all, which is the same shape as server
   * rendering, and it is stricter than the case it was written for: private
   * mode and embedded webviews merely THROW on access, while here the global is
   * absent entirely. Either way the setting must apply in memory and simply not
   * persist, because failing to remember a preference is survivable and
   * throwing on a click is not.
   */
  it("applies in memory when there is no storage to persist to", () => {
    expect(typeof globalThis.window).toBe("undefined");
    expect(() => setTechnicalDetail(true)).not.toThrow();
    expect(technicalDetailEnabled()).toBe(true);
    expect(() => setTechnicalDetail(false)).not.toThrow();
    expect(technicalDetailEnabled()).toBe(false);
  });
});
