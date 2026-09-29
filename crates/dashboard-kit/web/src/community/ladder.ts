import type { Step } from "../components/viz";
import { DECIDER_WORDS, type DecisionOutcomeKey } from "./words";

/**
 * How far InnerWarden got with one case, in the four stages every case on
 * every edition is drawn in: Seen, Decided, Enforced, Verified.
 *
 * A pure function of structured fields only; nothing here reads a sentence.
 * Two marks can never appear on a Community case, and the tests pin both:
 * `verified` (emerald), because Community reads nothing back after the fact
 * and so confirms nothing, and `waiting` (amber), because nothing in
 * Community waits on a person to decide a case.
 */
export type LadderInput = {
  outcomeKey: DecisionOutcomeKey;
  mode: string;
  decidedBy: string;
};

type Stage = Pick<Step, "mark" | "words"> & { caption?: string };

function enforced(input: LadderInput): Stage {
  switch (input.outcomeKey) {
    case "refused_before_run":
      return { mark: "done", caption: "refused", words: "refused before it ran" };
    case "unsafe_may_have_run":
      return { mark: "no", caption: "it ran", words: "judged unsafe, and it ran" };
    case "would_have_refused":
      return { mark: "not_applicable", caption: "monitor", words: "not refused: monitor mode records and does not refuse" };
    case "flagged_ran":
      return input.mode === "monitor"
        ? { mark: "not_applicable", caption: "monitor", words: "not refused: monitor mode records and does not refuse" }
        : { mark: "not_applicable", caption: "not refused", words: "not refused: only a deny is refused" };
    case "checked_only":
      return { mark: "not_applicable", caption: "nothing ran", words: "a check by hand runs nothing" };
    case "allowed":
      return { mark: "not_applicable", caption: "allowed", words: "allowed, so nothing to refuse" };
    case "unplaced":
      return { mark: "unknown", caption: "not recorded", words: "not on record whether it was refused" };
  }
}

/**
 * The four stages, with a caption under each. `seenCaption` is the time the
 * case was recorded, as the page prints it (the kit's clock), or nothing.
 */
export function caseLadder(input: LadderInput, seenCaption?: string): Step[] {
  const decider = DECIDER_WORDS[input.decidedBy];
  const enforce = enforced(input);
  const verified: Stage = enforce.mark === "done"
    ? { mark: "unknown", caption: "not checked", words: "not checked by a second part of InnerWarden; Community records the guard's own answer" }
    : { mark: "not_applicable", words: "nothing to check" };
  return [
    { key: "seen", label: "Seen", mark: "done", words: "on record", ...(seenCaption === undefined ? {} : { caption: seenCaption, captionWords: seenCaption }) },
    { key: "decided", label: "Decided", mark: "done", words: decider === undefined ? "decided" : `decided by ${decider}`, caption: "+0 s" },
    { key: "enforced", label: "Enforced", mark: enforce.mark, words: enforce.words, ...(enforce.caption === undefined ? {} : { caption: enforce.caption, captionWords: enforce.caption }) },
    { key: "verified", label: "Verified", mark: verified.mark, words: verified.words, ...(verified.caption === undefined ? {} : { caption: verified.caption, captionWords: verified.caption }) },
  ];
}

/**
 * The ladder of a message someone sent the agent: seen and decided (by the
 * agent itself, or by InnerWarden), never enforced, because observing a
 * conversation records it and does not block it.
 */
export function messageLadder(declinedByAgent: boolean, seenCaption?: string): Step[] {
  return [
    { key: "seen", label: "Seen", mark: "done", words: "on record", ...(seenCaption === undefined ? {} : { caption: seenCaption, captionWords: seenCaption }) },
    { key: "decided", label: "Decided", mark: declinedByAgent ? "done" : "unknown", words: declinedByAgent ? "your agent declined" : "who decided was not recorded" },
    { key: "enforced", label: "Enforced", mark: "not_applicable", words: "observe records and does not block" },
    { key: "verified", label: "Verified", mark: "not_applicable", words: "nothing to check" },
  ];
}
