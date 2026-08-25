import { useEffect, useRef, useState, type CSSProperties, type KeyboardEvent as ReactKeyboardEvent } from "react";
import { createPortal } from "react-dom";

/**
 * The guided product tour: one engine, one step table per edition.
 *
 * A hand-rolled overlay: the bundle's only runtime dependencies are react and
 * react-dom, deliberately, so no tour library is used. A dimmed backdrop with a
 * spotlight cutout is drawn around each step's anchor, and a small card walks
 * the operator through the views in their own language.
 *
 * The engine holds NO step table. Steps and the storage key are parameters, so
 * this file is shared: Community passes `COMMUNITY_TOUR_STEPS`, and the Active
 * Defence bundle passes those same steps with its own screens appended. The
 * alternative was a second copy of 300 lines of overlay code that would drift
 * the moment one of them was fixed.
 *
 * Anchors are found by CSS selector. Markup we own carries a `data-tour`
 * attribute; the stable ids and aria labels the screens already ship are listed
 * after it as fallbacks. A step whose screen is not mounted first drives
 * navigation there, waits for the screen to render, and if the anchor still
 * never appears the card centers itself instead of pointing at nothing.
 */

export type TourStep = {
  key: string;
  title: string;
  body: string;
  /** The `?view=` route whose screen holds the anchor; undefined = stay put. */
  route?: string;
  /** Selectors tried in order; undefined = a centered card with no spotlight. */
  selectors?: readonly string[];
};

/** Community's own gate key. Each edition tracks its own dismissal. */
export const COMMUNITY_TOUR_STORAGE_KEY = "iw-community-tour-v1";

/**
 * The key of the step that offers Active Defence.
 *
 * Exported so the paid bundle can drop it by key when it composes its own
 * table: selling the product to someone who already bought it is noise.
 */
export const COMMUNITY_UPGRADE_STEP_KEY = "upgrade";

/** The key of the closing step, so a composed table can keep it last. */
export const TOUR_FINISH_STEP_KEY = "finish";

/**
 * The Community tour.
 *
 * ONE rule decides what is in here: the Community shell renders Overview and
 * Activity and NOTHING else (`deriveShellNavigation` in App.tsx returns exactly
 * those two for edition "community"; every other route is bounced back to
 * overview). Posture, Agents and Tokens are Enterprise tabs whose screen files
 * merely live in this kit, so a step pointing at them would be dead for every
 * free user. Same for the sensor panel: `SensorActivity` renders null with no
 * host sensor, which the free product does not have. A tour that walks a user
 * to a screen they do not have is worse than no tour.
 */
/**
 * Steps for screens whose files live in this kit but which ONLY the paid shell
 * renders (Posture, Agents, Tokens, and the host sensor panel). They are not in
 * the Community table because the Community shell offers neither the tabs nor
 * the sensor, and a step that walks a user to a screen they do not have is
 * worse than no step. The paid bundle composes these in.
 */
export const PAID_SCREEN_TOUR_STEPS: readonly TourStep[] = [
  {
    key: "overview-sensor",
    title: "Sensor activity",
    body: "What the host sensor saw today, collector by collector, so silence from a collector is visible rather than assumed.",
    route: "overview",
    selectors: ['[data-tour="overview-sensor"]', 'section[aria-labelledby="sensor-activity-title"]'],
  },
  {
    key: "posture",
    title: "Protection posture",
    body: "The protection layers actually in effect here: what is switched on, what is only watching, and where the gaps are.",
    route: "posture",
    selectors: [
      '[data-tour="posture"]',
      'section[aria-labelledby="posture-verdict-title"]',
      'section[aria-labelledby="posture-controls-title"]',
    ],
  },
  {
    key: "agents",
    title: "Per-agent detail",
    body: "Every agent in one place, with its runtime, its model and the evidence that its guardrail was really running.",
    route: "agents",
    selectors: ['[data-tour="agents"]'],
  },
  {
    key: "tokens",
    title: "Token usage",
    body: "How much each agent has spent, read from the history it keeps on this machine. It explains activity, it is not a security score.",
    route: "tokens",
    selectors: ['[data-tour="tokens"]'],
  },
];

export const COMMUNITY_TOUR_STEPS: readonly TourStep[] = [
  {
    key: "welcome",
    title: "Welcome to InnerWarden",
    body: "A quick tour of what this dashboard shows you. It takes under a minute.",
  },
  {
    key: "nav",
    title: "Getting around",
    body: "Every screen lives behind these tabs. Which ones appear depends on what this installation can actually show you.",
    selectors: ['[data-tour="nav"]', 'nav[aria-label="Dashboard views"]'],
  },
  {
    key: "overview-agents",
    title: "Agents on this machine",
    body: "The AI agents found on this machine, whether they are running, and whether a guardrail has been seen protecting each one.",
    route: "overview",
    selectors: ['[data-tour="overview-agents"]', 'section[aria-labelledby="local-agents-title"]'],
  },
  {
    key: "activity",
    title: "What your agents did",
    body: "Every command an agent tried, grouped by session, with the verdict for each one. Open a line to see why it was decided that way.",
    route: "activity",
    selectors: ['[data-tour="activity"]'],
  },
  {
    key: COMMUNITY_UPGRADE_STEP_KEY,
    // Anchored on the upsell card the Overview ALREADY renders for Community,
    // rather than restating the offer in tour copy. The product then makes its
    // pitch once, in one voice, and a change to the card cannot leave a second
    // stale version of it behind in here.
    title: "Going further: Active Defence",
    body: "Community screens what your agents try to run. Active Defence is the paid tier that adds host protection: its own telemetry, incident triage, evidence-backed response and, on supported Linux hosts, kernel enforcement. This card links to the details.",
    route: "overview",
    selectors: ['[data-tour="upgrade"]', 'aside[aria-labelledby="active-defence-title"]'],
  },
  {
    key: TOUR_FINISH_STEP_KEY,
    title: "That's the tour",
    body: "Reopen it any time from the Tour button in the header.",
  },
];

/**
 * The Community steps for a host, with the Active Defence pitch dropped when
 * that host already runs Active Defence.
 *
 * The upgrade step is anchored on the upsell card so the pitch is made once, in
 * one voice (see the comment on that step). That cuts both ways: once the card
 * stops offering, this step has to stop too, or the tour becomes the second,
 * stale copy the anchoring was meant to prevent. A missing anchor is not enough
 * on its own -- `findTarget` returning null leaves the step rendered, just
 * unanchored, so the pitch would still be read out to someone who already owns
 * the product.
 *
 * Pure, and takes the answer as an argument, so both outcomes are reachable
 * from a test without a server.
 */
export function communityTourSteps(activeDefenceInstalled: boolean): readonly TourStep[] {
  if (!activeDefenceInstalled) return COMMUNITY_TOUR_STEPS;
  return COMMUNITY_TOUR_STEPS.filter((step) => step.key !== COMMUNITY_UPGRADE_STEP_KEY);
}

/** The storage surface the gate needs; narrowed so tests can hand in a fake. */
export type TourStorage = {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
};

/** Where Back/Next land: always inside [0, total - 1]. */
export function clampStep(current: number, delta: number, total: number): number {
  const next = current + delta;
  if (next < 0) return 0;
  if (next > total - 1) return total - 1;
  return next;
}

/**
 * First visit only. A throwing storage (private mode, disabled cookies) reads
 * as "seen": a tour that pops up on every load because it cannot remember being
 * closed is worse than one that never auto-opens.
 */
export function shouldAutoOpen(storage: TourStorage, storageKey: string): boolean {
  try {
    return storage.getItem(storageKey) === null;
  } catch {
    return false;
  }
}

/** Finish and Skip both call this, so the tour never reappears uninvited. */
export function markTourSeen(storage: TourStorage, storageKey: string): void {
  try {
    storage.setItem(storageKey, new Date().toISOString());
  } catch {
    // Nothing to do: shouldAutoOpen already treats unusable storage as seen.
  }
}

/**
 * The per-screen query parameters the shell's own navigation clears. Cleared
 * here too so the tour lands each screen on its default view, not on whatever
 * filter or selection the operator left behind.
 */
const SCREEN_PARAMS = [
  "q", "outcome", "severity", "mode", "authority", "capability", "scope_kind",
  "scope", "window", "cursor", "case", "decision", "session", "verdict", "action",
] as const;

function currentRoute(): string {
  return new URLSearchParams(window.location.search).get("view") ?? "overview";
}

/**
 * Drive the shell to a screen without reaching into its internals: write the
 * address the same way the nav does, then dispatch popstate, which the shell
 * already listens to for restoring its route from the address bar.
 */
function driveNavigation(route: string): void {
  if (currentRoute() === route) return;
  const url = new URL(window.location.href);
  if (route === "overview") url.searchParams.delete("view");
  else url.searchParams.set("view", route);
  for (const name of SCREEN_PARAMS) url.searchParams.delete(name);
  window.history.pushState({}, "", url);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

function findTarget(selectors: readonly string[]): HTMLElement | null {
  for (const selector of selectors) {
    const found = document.querySelector<HTMLElement>(selector);
    if (found !== null) return found;
  }
  return null;
}

type SpotRect = { top: number; left: number; width: number; height: number };

const SPOT_PADDING = 6;
const CARD_WIDTH = 352;
const CARD_MARGIN = 12;
/** Rough card height used only to pick above vs below; never to size it. */
const CARD_CLEARANCE = 240;
const NARROW_VIEWPORT = 640;

function cardStyle(rect: SpotRect | null, narrow: boolean): CSSProperties {
  if (narrow) {
    // Phone: dock the card to the bottom edge, full width, above the home
    // indicator. A floating card beside the anchor does not fit at 375px.
    return {
      position: "fixed",
      left: 0,
      right: 0,
      bottom: 0,
      borderRadius: "16px 16px 0 0",
      padding: "16px 16px calc(16px + env(safe-area-inset-bottom, 0px))",
      maxHeight: "50vh",
      overflowY: "auto",
      boxSizing: "border-box",
    };
  }
  if (rect === null) {
    return {
      position: "fixed",
      left: "50%",
      top: "50%",
      transform: "translate(-50%, -50%)",
      width: CARD_WIDTH,
      maxWidth: "92vw",
      borderRadius: 16,
      padding: 20,
      boxSizing: "border-box",
    };
  }
  const vw = window.innerWidth;
  const vh = window.innerHeight;
  const style: CSSProperties = {
    position: "fixed",
    left: Math.min(Math.max(rect.left, CARD_MARGIN), Math.max(vw - CARD_WIDTH - CARD_MARGIN, CARD_MARGIN)),
    width: CARD_WIDTH,
    maxWidth: "92vw",
    borderRadius: 16,
    padding: 20,
    boxSizing: "border-box",
  };
  const spaceBelow = vh - (rect.top + rect.height);
  if (spaceBelow >= CARD_CLEARANCE) {
    style.top = rect.top + rect.height + CARD_MARGIN;
  } else if (rect.top >= CARD_CLEARANCE) {
    // Anchored by its bottom edge so the card grows upward from the target
    // whatever its real height turns out to be.
    style.bottom = vh - rect.top + CARD_MARGIN;
  } else {
    style.bottom = CARD_MARGIN;
  }
  return style;
}

export function ProductTour({ steps, onClose }: { steps: readonly TourStep[]; onClose: () => void }) {
  const [stepIndex, setStepIndex] = useState(0);
  const [target, setTarget] = useState<HTMLElement | null>(null);
  const [rect, setRect] = useState<SpotRect | null>(null);
  const [narrow, setNarrow] = useState(() => window.innerWidth < NARROW_VIEWPORT);
  const cardRef = useRef<HTMLDivElement | null>(null);
  const primaryRef = useRef<HTMLButtonElement | null>(null);
  // The effect below reads the step for the index it runs on; keeping the table
  // in a ref means a caller passing a fresh array literal cannot restart it.
  const stepsRef = useRef(steps);
  stepsRef.current = steps;

  const total = steps.length;
  const step = steps[stepIndex];
  const lastStep = stepIndex === total - 1;

  const advance = (delta: number) => {
    if (delta > 0 && lastStep) {
      onClose();
      return;
    }
    setStepIndex((current) => clampStep(current, delta, total));
  };

  // Navigate, then locate the anchor. The screen behind a step may still be
  // fetching when we arrive, so a quick burst of retries is followed by a slow
  // poll for as long as the step is showing; until something is found the card
  // renders centered over a plain dim, which is the graceful floor.
  useEffect(() => {
    setTarget(null);
    const current = stepsRef.current[stepIndex];
    if (current === undefined) return;
    if (current.route !== undefined) driveNavigation(current.route);
    const selectors = current.selectors;
    if (selectors === undefined) return;
    let cancelled = false;
    let attempts = 0;
    const locate = () => {
      if (cancelled) return;
      const found = findTarget(selectors);
      if (found !== null) {
        found.scrollIntoView({ block: "center" });
        setTarget(found);
        return;
      }
      attempts += 1;
      window.setTimeout(locate, attempts < 15 ? 120 : 600);
    };
    window.setTimeout(locate, 80);
    return () => {
      cancelled = true;
    };
  }, [stepIndex]);

  // Track the anchor while it is on screen: layout shifts, scrolling and
  // rotation all move it, and the spotlight must follow.
  useEffect(() => {
    if (target === null) {
      setRect(null);
      return;
    }
    const measure = () => {
      const measured = target.getBoundingClientRect();
      if (!target.isConnected || (measured.width === 0 && measured.height === 0)) {
        setRect(null);
        return;
      }
      setRect((previous) =>
        previous !== null &&
        previous.top === measured.top &&
        previous.left === measured.left &&
        previous.width === measured.width &&
        previous.height === measured.height
          ? previous
          : { top: measured.top, left: measured.left, width: measured.width, height: measured.height },
      );
    };
    measure();
    const timer = window.setInterval(measure, 200);
    window.addEventListener("resize", measure);
    window.addEventListener("scroll", measure, true);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener("resize", measure);
      window.removeEventListener("scroll", measure, true);
    };
  }, [target]);

  useEffect(() => {
    const onResize = () => setNarrow(window.innerWidth < NARROW_VIEWPORT);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  // Keyboard: ArrowRight/Enter forward, ArrowLeft back, Escape closes. Enter
  // is left alone when a button has focus, or it would fire twice: once as the
  // button's own click and once here.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      const onButton = event.target instanceof HTMLElement && event.target.closest("button") !== null;
      if (event.key === "ArrowRight" || (event.key === "Enter" && !onButton)) {
        event.preventDefault();
        advance(1);
      } else if (event.key === "ArrowLeft") {
        event.preventDefault();
        advance(-1);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // advance closes over lastStep, which changes with the step.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stepIndex]);

  // The card is a dialog: focus lands on the primary control each step, stays
  // trapped inside, and returns to wherever it came from on close.
  useEffect(() => {
    primaryRef.current?.focus();
  }, [stepIndex]);

  useEffect(() => {
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    return () => previous?.focus();
  }, []);

  const trapFocus = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    if (event.key !== "Tab") return;
    const card = cardRef.current;
    if (card === null) return;
    const controls = Array.from(card.querySelectorAll<HTMLElement>("button:not(:disabled)"));
    if (controls.length === 0) return;
    const first = controls[0];
    const last = controls[controls.length - 1];
    const active = document.activeElement;
    if (event.shiftKey && (active === first || !card.contains(active))) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (active === last || !card.contains(active))) {
      event.preventDefault();
      first.focus();
    }
  };

  // A table with no steps draws nothing rather than crashing on `step.title`.
  if (step === undefined) return null;

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 70 }} role="presentation">
      {rect !== null ? (
        // The spotlight: a rounded box over the anchor whose oversized shadow
        // is the dim, so the target stays at full brightness inside a cutout.
        <div
          aria-hidden="true"
          style={{
            position: "fixed",
            top: rect.top - SPOT_PADDING,
            left: rect.left - SPOT_PADDING,
            width: rect.width + SPOT_PADDING * 2,
            height: rect.height + SPOT_PADDING * 2,
            borderRadius: 12,
            boxShadow: "0 0 0 9999px rgba(2, 6, 23, 0.55)",
            border: "2px solid rgba(34, 211, 238, 0.9)",
            pointerEvents: "none",
            transition: "top 160ms ease, left 160ms ease, width 160ms ease, height 160ms ease",
          }}
        />
      ) : (
        <div aria-hidden="true" style={{ position: "fixed", inset: 0, background: "rgba(2, 6, 23, 0.55)" }} />
      )}
      <div
        ref={cardRef}
        role="dialog"
        aria-modal="true"
        aria-label={`Product tour, step ${stepIndex + 1} of ${total}: ${step.title}`}
        onKeyDown={trapFocus}
        className="border border-slate-200 bg-white text-slate-950 shadow-2xl"
        style={cardStyle(rect, narrow)}
      >
        <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-cyan-700">Product tour</p>
        <h2 className="mt-1 text-base font-semibold text-slate-950">{step.title}</h2>
        <p className="mt-1.5 text-sm leading-6 text-slate-600">{step.body}</p>
        <div className="mt-4 flex items-center gap-2">
          <span className="text-xs tabular-nums text-slate-500">{stepIndex + 1} / {total}</span>
          <div className="ml-auto flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg px-2.5 py-1.5 text-sm font-semibold text-slate-500 hover:bg-slate-100 hover:text-slate-700"
            >
              Skip
            </button>
            <button
              type="button"
              disabled={stepIndex === 0}
              onClick={() => advance(-1)}
              className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm font-semibold text-slate-700 shadow-sm hover:bg-slate-50 disabled:opacity-40"
            >
              Back
            </button>
            <button
              ref={primaryRef}
              type="button"
              onClick={() => advance(1)}
              className="rounded-lg bg-slate-900 px-3.5 py-1.5 text-sm font-semibold text-white shadow-sm hover:bg-slate-800"
            >
              {lastStep ? "Done" : "Next"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/**
 * The launch layer `main.tsx` mounts beside the App: auto-opens the tour on a
 * first visit, and keeps a small Tour button in the header so it can always be
 * reopened. The button rides in the header's status area via a portal; if that
 * slot cannot be found it falls back to a floating button rather than
 * disappearing.
 */
export function TourLauncher({
  steps,
  storageKey,
}: {
  steps: readonly TourStep[];
  storageKey: string;
}) {
  const [open, setOpen] = useState(false);
  const [slot, setSlot] = useState<Element | "fallback" | null>(null);

  useEffect(() => {
    // An automated browser (Playwright and friends set navigator.webdriver)
    // never gets the uninvited tour: a modal overlay that swallows every click
    // would fail each scripted journey before it starts. The Tour button still
    // opens it on demand, there and everywhere else.
    if (window.navigator.webdriver) return;
    if (!shouldAutoOpen(window.localStorage, storageKey)) return;
    // Let the shell paint first so the welcome card appears over a real page.
    const timer = window.setTimeout(() => setOpen(true), 600);
    return () => window.clearTimeout(timer);
  }, [storageKey]);

  useEffect(() => {
    const find = () => document.querySelector("header div.ml-auto");
    const existing = find();
    if (existing !== null) {
      setSlot(existing);
      return;
    }
    let attempts = 0;
    const timer = window.setInterval(() => {
      const found = find();
      if (found !== null) {
        setSlot(found);
        window.clearInterval(timer);
        return;
      }
      attempts += 1;
      if (attempts >= 12) {
        setSlot("fallback");
        window.clearInterval(timer);
      }
    }, 250);
    return () => window.clearInterval(timer);
  }, []);

  const close = () => {
    markTourSeen(window.localStorage, storageKey);
    setOpen(false);
  };

  const button = (
    <button
      type="button"
      onClick={() => setOpen(true)}
      aria-label="Open the product tour"
      className="rounded-lg border border-slate-300 bg-white px-2.5 py-1 text-xs font-semibold text-slate-600 shadow-sm transition-colors hover:bg-slate-100 hover:text-slate-900"
    >
      Tour
    </button>
  );

  return (
    <>
      {slot === null ? null : slot === "fallback" ? (
        <div style={{ position: "fixed", right: 12, bottom: 12, zIndex: 60 }}>{button}</div>
      ) : (
        createPortal(button, slot)
      )}
      {open ? <ProductTour steps={steps} onClose={close} /> : null}
    </>
  );
}
