import type { ReactNode } from "react";
import type { CaseLane, CaseListWindow } from "../api/cases";
import { LANE_COPY, LANE_WINDOW_PHRASE, laneCountNoun, latestCaseWindow, type LaneCard, type LanePart } from "../lanes";
import { formatCount, formatDay } from "../presentation";
import { countWords } from "../readCount";
import { windowWords } from "../windows";
import { When } from "./When";
import { gridColumnsClass, gridSpanClass, joinClasses } from "./cardGrid";
import { TechnicalOnly } from "./TechnicalDetail";
import { Bar, Swatch, type Part } from "./viz";

/**
 * What happened to each command or message, as a colour with a job:
 * InnerWarden stopping it is the accent (before it ran darker, the kernel
 * lighter), a command that may have run while judged unsafe is the one bad
 * outcome, what was only watched, declined by the agent itself or allowed is
 * grey, and what nobody answered or nobody could place is hatched so it
 * never reads as a settled state. A key this bundle does not know is plain
 * grey: it still counts, and it claims nothing.
 */
export type OutcomeTone = Pick<Part, "tone" | "hatched" | "hollow">;

const OUTCOME_TONES: Record<string, OutcomeTone> = {
  refused_before_run: { tone: "accent" },
  kernel_stopped: { tone: "accentLight" },
  unsafe_may_have_run: { tone: "bad" },
  would_have_refused: { tone: "watch" },
  held_for_review: { tone: "other", hatched: true },
  unplaced: { tone: "other", hatched: true },
  allowed: { tone: "watchLight" },
  // Community's own two: a flagged command that ran (the rules asked for a
  // review, or monitor mode only watched), and a command a person checked by
  // hand, which ran nothing.
  flagged_ran: { tone: "other" },
  checked_only: { tone: "watchLight" },
  // Messages to the agent (the paid host's messages card).
  stopped_by_innerwarden: { tone: "accent" },
  declined_by_agent: { tone: "watch" },
  filtered_by_provider: { tone: "other" },
  answered: { tone: "watchLight" },
  // A case's own outcome (`SecurityOutcome`), in the same jobs: InnerWarden
  // blocking it is the accent, the kernel refusing it before it ran the
  // lighter accent (never rose: nothing bad happened), only watched or let
  // through is grey, a failed action is the one bad outcome, what nobody saw
  // is hatched and what the record does not say is an outline, never a fill.
  contained: { tone: "accent" },
  blocked_before_execution: { tone: "accentLight" },
  would_block: { tone: "watch" },
  observed_only: { tone: "watchLight" },
  reverted: { tone: "other" },
  failed: { tone: "bad" },
  not_observed: { tone: "other", hatched: true },
  unknown: { tone: "unknown", hollow: true },
};

/**
 * The tone of one outcome, by the key the host counts it under, on every
 * screen that draws one: a lane's bar, a case's row, a flow's end. A key this
 * bundle does not know is plain grey: it still counts, and it claims nothing.
 */
export function outcomeTone(key: string): OutcomeTone {
  return OUTCOME_TONES[key] ?? { tone: "other" };
}

export function outcomeParts(parts: readonly LanePart[]): Part[] {
  return parts.map((part) => ({
    key: part.key,
    value: part.count,
    label: `${part.label}: ${formatCount(part.count)}`,
    ...outcomeTone(part.key),
  }));
}

/**
 * The split of a count as a bar and its legend: every part with something in
 * it, each with its own swatch and number, adding up to the count. The zeros
 * are not drawn; the caller says them where it needs to.
 */
export function OutcomeBreakdown({ parts, label, className = "" }: { parts: readonly LanePart[]; label: string; className?: string }) {
  const counted = parts.filter((part) => part.count > 0);
  const drawn = outcomeParts(counted);
  return (
    <div className={className}>
      <Bar parts={drawn} label={label} />
      <ul data-lane-breakdown className="mt-3 space-y-1 text-sm text-slate-700">
        {counted.map((part, index) => (
          <li key={part.key} data-part={part.key} className="flex items-baseline gap-2">
            <Swatch part={drawn[index]} className="h-2.5 w-2.5 self-center" />
            <span className="min-w-6 text-right font-semibold tabular-nums text-slate-950">{formatCount(part.count)}</span>
            {" "}
            <span className="min-w-0 break-words">{part.label}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export type LaneOpenOptions = { window: CaseListWindow; status?: "waiting" };

/**
 * Where a lane card's link goes.
 *
 * - `cases`: the shell has a Cases screen, and the card opens it on this lane,
 *   in the window the card counted.
 * - `activity`: Community has no Cases screen, and its Activity screen is its
 *   record of what the agent did, so the agent's lane opens that.
 * - `none`: nowhere lists this lane's cases. The card is then a statement, not
 *   a link: a link that lands back on the Overview teaches a reader that the
 *   links here go nowhere.
 */
export function laneLink(
  lane: CaseLane,
  edition: "community" | "enterprise" | undefined,
  canOpenLane: boolean,
): "cases" | "activity" | "none" {
  if (canOpenLane) return "cases";
  if (edition === "community" && lane === "agent_actions") return "activity";
  return "none";
}

/**
 * The three questions, one card each: a number with what it counts, the span
 * it covers, the host's sentence, the newest case and the way into the cases
 * behind it.
 *
 * Every word a reader sees about what HAPPENED is the host's (`sentence`,
 * `latest.title`); the card adds only what the lane is and where it leads.
 * A lane with no source has no number at all, never a zero.
 *
 * Something waiting on a person is never behind the technical switch: the
 * waiting count renders in both views, and as plain text when there is no
 * Cases screen to open.
 */
/** The span a card counts, named after "over": "over the last 7 days". */
export const LANE_SPAN_NAME: Record<CaseListWindow, string> = windowWords("span");

/**
 * The line under the page heading: whose records these are, over what span,
 * and whether every card leads somewhere.
 *
 * The span is named ONCE when every card counts the same one, so a reader
 * knows the three numbers can be read side by side. When they do not (a host
 * that counts the server's lane over 24 hours and the agent's over 7 days),
 * the line says so rather than letting three numbers over three spans read as
 * one picture; each card still names its own.
 */
export function lanesIntro(cards: readonly LaneCard[], everyCardLeads: boolean): string {
  const spans = new Set(cards.flatMap((card) => (card.state === "available" ? [card.window] : [])));
  const [only] = spans;
  const base = spans.size === 1 && only !== undefined
    ? `Answered from this host's own records, over ${LANE_SPAN_NAME[only]}.`
    : spans.size > 1
      ? "Answered from this host's own records. The cards count different spans, and each one says which."
      : "Answered from this host's own records.";
  return everyCardLeads ? `${base} Each card opens what is behind it.` : base;
}

export function LaneCards({
  cards,
  edition,
  onOpenLane,
  onOpenCase,
  onOpenActivity,
  intro,
  linkLabel,
  footer,
  align,
  title,
  blurb,
  beforeCards,
}: {
  cards: LaneCard[];
  /** The line under the heading, in place of `lanesIntro`. Absent: `lanesIntro`. */
  intro?: string;
  /** A card's heading, in place of the lane's own name (`LANE_COPY`). Absent, or `undefined` for a lane: the lane's own. */
  title?: (lane: CaseLane) => string | undefined;
  /** The line under a card's heading, in place of the lane's own (`LANE_COPY`). Absent, or `undefined` for a lane: the lane's own. */
  blurb?: (lane: CaseLane) => string | undefined;
  /** Drawn between the heading and the cards (a first run's own steps). Absent: nothing. */
  beforeCards?: ReactNode;
  /** A card's link words, in place of the lane's own (`LANE_COPY`). Absent, or `undefined` for a lane: the lane's own. */
  linkLabel?: (lane: CaseLane) => string | undefined;
  /** Drawn at a card's foot, above its link row. Absent: nothing. */
  footer?: (card: LaneCard) => ReactNode;
  /**
   * "start": each card keeps its own height, for a row where one card holds
   * much more than another (a card with nothing to count beside a full one
   * would otherwise stretch into an empty box). Absent: the cards stretch.
   */
  align?: "start";
  edition?: "community" | "enterprise";
  onOpenLane?: (lane: CaseLane, options: LaneOpenOptions) => void;
  /**
   * Opens one case inside its lane, in the window the card counted when the
   * case is inside it (`latestCaseWindow`), so the list beside the case is
   * the one the card was about.
   */
  onOpenCase?: (caseId: string, lane: CaseLane, window: CaseListWindow) => void;
  onOpenActivity?: () => void;
}) {
  // The promise is about EVERY card, so it is made only when every card keeps
  // it: a card with no source, or with nowhere to open, has no link, and the
  // sentence above it must not say it has one.
  const everyCardLeads = cards.length > 0 && cards.every(
    (card) => card.state === "available" && laneLink(card.lane, edition, onOpenLane !== undefined) !== "none",
  );
  return (
    <section aria-labelledby="lanes-title" data-tour="overview-lanes" className="min-w-0">
      <h1 id="lanes-title" className="text-2xl font-semibold tracking-tight text-slate-950 sm:text-3xl">
        What is happening here
      </h1>
      <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
        {intro ?? lanesIntro(cards, everyCardLeads)}
      </p>
      {beforeCards === undefined || beforeCards === null ? null : <div className="mt-5">{beforeCards}</div>}
      <div className={joinClasses("mt-5 grid gap-4", gridColumnsClass("trio", cards.length), align === "start" && "items-start")}>
        {cards.map((card, index) => (
          <LaneCardView
            key={card.lane}
            card={card}
            spanClass={gridSpanClass("trio", index, cards.length)}
            link={laneLink(card.lane, edition, onOpenLane !== undefined)}
            onOpenLane={onOpenLane}
            onOpenCase={onOpenCase}
            onOpenActivity={onOpenActivity}
            linkWords={linkLabel?.(card.lane)}
            footer={footer?.(card)}
            titleWords={title?.(card.lane)}
            blurbWords={blurb?.(card.lane)}
          />
        ))}
      </div>
    </section>
  );
}

function LaneCardView({
  card,
  spanClass,
  link,
  onOpenLane,
  onOpenCase,
  onOpenActivity,
  linkWords,
  footer,
  titleWords,
  blurbWords,
}: {
  card: LaneCard;
  spanClass: string;
  link: ReturnType<typeof laneLink>;
  onOpenLane?: (lane: CaseLane, options: LaneOpenOptions) => void;
  onOpenCase?: (caseId: string, lane: CaseLane, window: CaseListWindow) => void;
  onOpenActivity?: () => void;
  linkWords?: string;
  footer?: ReactNode;
  titleWords?: string;
  blurbWords?: string;
}) {
  const copy = LANE_COPY[card.lane];
  const titleId = `lane-${card.lane}-title`;
  const available = card.state === "available";
  const waiting = available ? card.waiting ?? 0 : 0;
  // A capped read's waiting count is a floor: "At least 4 waiting on you".
  const waitingWords = available ? countWords(waiting, card.waitingComplete !== false, "floor", "sentence") : "";
  const latest = available ? card.latest : undefined;
  const noun = available ? laneCountNoun(card.countOf, card.count) : undefined;
  // The record starts inside the window: the count covers "since" that day.
  const since = available && card.since !== undefined ? formatDay(card.since) : undefined;
  const span = available ? (since === undefined ? LANE_WINDOW_PHRASE[card.window] : `since ${since}`) : "";
  const split = available && card.breakdown !== undefined && card.breakdown.some((part) => part.count > 0);
  const open = () => {
    if (link === "cases" && available) onOpenLane?.(card.lane, { window: card.window });
    else if (link === "activity") onOpenActivity?.();
  };
  return (
    <section
      aria-labelledby={titleId}
      data-lane={card.lane}
      data-lane-state={card.state}
      className={joinClasses("flex min-w-0 flex-col rounded-2xl border border-slate-200 bg-white p-5 shadow-sm", spanClass)}
    >
      <h2 id={titleId} className="text-base font-semibold text-slate-950">{titleWords ?? copy.name}</h2>
      <p className="mt-1 text-xs leading-5 text-slate-500">{blurbWords ?? copy.blurb}</p>
      {available ? (
        <p className="mt-4 flex flex-wrap items-baseline gap-x-2">
          <span data-lane-count className="text-3xl font-semibold tabular-nums text-slate-950">{formatCount(card.count)}</span>
          {/* A real space, so the number and its unit are one phrase to a
              screen reader and in copied text; the flex gap draws it. */}
          {" "}
          <span className="text-xs text-slate-500">
            {noun === undefined ? span : `${noun} ${span}`}
          </span>
        </p>
      ) : null}
      {available && split ? (
        // The split of the number above, each part counted once, adding up
        // to it exactly: the host's split is dropped whole when it does not.
        // A split with nothing in any part draws no list at all, not an
        // empty one a screen reader announces as a list of no items.
        <OutcomeBreakdown
          parts={card.breakdown ?? []}
          label={`${copy.name}: what happened to each of the ${formatCount(card.count)}`}
          className="mt-4"
        />
      ) : null}
      {split ? (
        // The list above says the host's sentence part by part, so the
        // sentence is the evidence behind it, one switch away.
        <TechnicalOnly>
          <p className="mt-3 break-words text-sm leading-6 text-slate-700 [overflow-wrap:anywhere]">{card.sentence}</p>
        </TechnicalOnly>
      ) : (
        <p className="mt-3 break-words text-sm leading-6 text-slate-700 [overflow-wrap:anywhere]">{card.sentence}</p>
      )}
      {latest ? (
        <p className="mt-3 break-words rounded-lg bg-slate-50 px-3 py-2 text-xs leading-5 text-slate-600 [overflow-wrap:anywhere]">
          <span className="font-semibold text-slate-800">Latest: </span>
          {latest.caseId !== undefined && onOpenCase !== undefined ? (
            <button
              type="button"
              onClick={() => available && onOpenCase(latest.caseId as string, card.lane, latestCaseWindow(latest, card.window, Date.now()))}
              className="text-left font-medium text-cyan-800 underline decoration-cyan-300 underline-offset-2 [overflow-wrap:anywhere] hover:text-cyan-950"
            >
              {latest.title}
            </button>
          ) : (
            <span className="font-medium text-slate-800">{latest.title}</span>
          )}
          <span className="text-slate-500">
            {" · "}
            <When at={latest.at} relative />
          </span>
        </p>
      ) : null}
      {footer === undefined || footer === null ? null : <div className="mt-4">{footer}</div>}
      {(waiting > 0 || (link !== "none" && available)) && (
        <div className="mt-auto flex flex-wrap items-center gap-x-4 gap-y-2 pt-4">
          {waiting > 0 ? (
            link === "cases" ? (
              // The host counts what is waiting inside the card's own window,
              // so the list it opens is that window too: the number on the
              // chip and the rows behind it describe the same span.
              <button
                type="button"
                onClick={() => available && onOpenLane?.(card.lane, { window: card.window, status: "waiting" })}
                className="rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-xs font-semibold text-amber-900 hover:border-amber-300 hover:bg-amber-100"
              >
                {waitingWords} waiting on you <span aria-hidden="true">→</span>
              </button>
            ) : (
              <span className="rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-xs font-semibold text-amber-900">
                {waitingWords} waiting on you
              </span>
            )
          ) : null}
          {link !== "none" && available ? (
            <button type="button" onClick={open} className="text-sm font-semibold text-cyan-700 hover:text-cyan-900">
              {linkWords ?? (link === "activity" ? "See every command in Activity" : copy.link)} <span aria-hidden="true">→</span>
            </button>
          ) : null}
        </div>
      )}
    </section>
  );
}
