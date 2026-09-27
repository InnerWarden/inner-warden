import type { CaseLane, CaseListWindow } from "../api/cases";
import { LANE_COPY, LANE_WINDOW_PHRASE, laneCountNoun, type LaneCard } from "../lanes";
import { formatCount } from "../presentation";
import { When } from "./When";
import { gridColumnsClass, gridSpanClass, joinClasses } from "./cardGrid";

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
export const LANE_SPAN_NAME: Record<CaseListWindow, string> = {
  "1h": "the last hour",
  "24h": "the last 24 hours",
  "7d": "the last 7 days",
  "30d": "the last 30 days",
  all: "everything this host has kept",
};

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
}: {
  cards: LaneCard[];
  edition?: "community" | "enterprise";
  onOpenLane?: (lane: CaseLane, options: LaneOpenOptions) => void;
  /**
   * Opens one case inside its lane, in the window the card counted, so the
   * list beside the case is the one the card was about (and the case, the
   * newest in that window, is in it).
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
        {lanesIntro(cards, everyCardLeads)}
      </p>
      <div className={joinClasses("mt-5 grid gap-4", gridColumnsClass("trio", cards.length))}>
        {cards.map((card, index) => (
          <LaneCardView
            key={card.lane}
            card={card}
            spanClass={gridSpanClass("trio", index, cards.length)}
            link={laneLink(card.lane, edition, onOpenLane !== undefined)}
            onOpenLane={onOpenLane}
            onOpenCase={onOpenCase}
            onOpenActivity={onOpenActivity}
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
}: {
  card: LaneCard;
  spanClass: string;
  link: ReturnType<typeof laneLink>;
  onOpenLane?: (lane: CaseLane, options: LaneOpenOptions) => void;
  onOpenCase?: (caseId: string, lane: CaseLane, window: CaseListWindow) => void;
  onOpenActivity?: () => void;
}) {
  const copy = LANE_COPY[card.lane];
  const titleId = `lane-${card.lane}-title`;
  const available = card.state === "available";
  const waiting = available ? card.waiting ?? 0 : 0;
  const latest = available ? card.latest : undefined;
  const noun = available ? laneCountNoun(card.countOf, card.count) : undefined;
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
      <h2 id={titleId} className="text-base font-semibold text-slate-950">{copy.name}</h2>
      <p className="mt-1 text-xs leading-5 text-slate-500">{copy.blurb}</p>
      {available ? (
        <p className="mt-4 flex flex-wrap items-baseline gap-x-2">
          <span data-lane-count className="text-3xl font-semibold tabular-nums text-slate-950">{formatCount(card.count)}</span>
          {/* A real space, so the number and its unit are one phrase to a
              screen reader and in copied text; the flex gap draws it. */}
          {" "}
          <span className="text-xs text-slate-500">
            {noun === undefined ? LANE_WINDOW_PHRASE[card.window] : `${noun} ${LANE_WINDOW_PHRASE[card.window]}`}
          </span>
        </p>
      ) : null}
      {available && card.breakdown !== undefined ? (
        // The split of the number above, each part counted once, adding up
        // to it exactly: the host's split is dropped whole when it does not.
        <ul data-lane-breakdown className="mt-3 space-y-1 text-sm text-slate-700">
          {card.breakdown.filter((part) => part.count > 0).map((part) => (
            <li key={part.key} data-part={part.key} className="flex items-baseline gap-2">
              <span className="min-w-8 text-right font-semibold tabular-nums text-slate-950">{formatCount(part.count)}</span>
              {" "}
              <span className="min-w-0 break-words">{part.label}</span>
            </li>
          ))}
        </ul>
      ) : null}
      <p className="mt-3 break-words text-sm leading-6 text-slate-700 [overflow-wrap:anywhere]">{card.sentence}</p>
      {latest ? (
        <p className="mt-3 break-words rounded-lg bg-slate-50 px-3 py-2 text-xs leading-5 text-slate-600 [overflow-wrap:anywhere]">
          <span className="font-semibold text-slate-800">Latest: </span>
          {latest.caseId !== undefined && onOpenCase !== undefined ? (
            <button
              type="button"
              onClick={() => available && onOpenCase(latest.caseId as string, card.lane, card.window)}
              className="text-left font-medium text-cyan-800 underline decoration-cyan-300 underline-offset-2 hover:text-cyan-950"
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
                {formatCount(waiting)} waiting on you <span aria-hidden="true">→</span>
              </button>
            ) : (
              <span className="rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-xs font-semibold text-amber-900">
                {formatCount(waiting)} waiting on you
              </span>
            )
          ) : null}
          {link !== "none" && available ? (
            <button type="button" onClick={open} className="text-sm font-semibold text-cyan-700 hover:text-cyan-900">
              {link === "activity" ? "See every command in Activity" : copy.link} <span aria-hidden="true">→</span>
            </button>
          ) : null}
        </div>
      )}
    </section>
  );
}
