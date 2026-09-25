import type { CaseLane, CaseListWindow } from "../api/cases";
import { LANE_COPY, LANE_WINDOW_PHRASE, type LaneCard } from "../lanes";
import { formatAbsolute, formatTimestamp } from "../presentation";
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
  if (edition === "community" && lane === "agent") return "activity";
  return "none";
}

/**
 * The three questions, one card each: a number, the span it covers, the host's
 * sentence, the newest case and the way into the cases behind it.
 *
 * Every word a reader sees about what HAPPENED is the host's (`sentence`,
 * `latest.title`); the card adds only what the lane is and where it leads.
 * A lane with no source has no number at all, never a zero.
 *
 * Something waiting on a person is never behind the technical switch: the
 * waiting count renders in both views, and as plain text when there is no
 * Cases screen to open.
 */
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
  onOpenCase?: (caseId: string, lane: CaseLane) => void;
  onOpenActivity?: () => void;
}) {
  const leadsSomewhere = cards.some(
    (card) => card.state === "available" && laneLink(card.lane, edition, onOpenLane !== undefined) !== "none",
  );
  return (
    <section aria-labelledby="lanes-title" data-tour="overview-lanes" className="min-w-0">
      <h1 id="lanes-title" className="text-2xl font-semibold tracking-tight text-slate-950 sm:text-3xl">
        What is happening here
      </h1>
      <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
        {leadsSomewhere
          ? "Answered from this host's own records. Each card opens what is behind it."
          : "Answered from this host's own records."}
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
  onOpenCase?: (caseId: string, lane: CaseLane) => void;
  onOpenActivity?: () => void;
}) {
  const copy = LANE_COPY[card.lane];
  const titleId = `lane-${card.lane}-title`;
  const available = card.state === "available";
  const waiting = available ? card.waiting ?? 0 : 0;
  const latest = available ? card.latest : undefined;
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
          <span data-lane-count className="text-3xl font-semibold tabular-nums text-slate-950">{card.count.toLocaleString()}</span>
          <span className="text-xs text-slate-500">{LANE_WINDOW_PHRASE[card.window]}</span>
        </p>
      ) : null}
      <p className="mt-3 break-words text-sm leading-6 text-slate-700 [overflow-wrap:anywhere]">{card.sentence}</p>
      {latest ? (
        <p className="mt-3 break-words rounded-lg bg-slate-50 px-3 py-2 text-xs leading-5 text-slate-600 [overflow-wrap:anywhere]">
          <span className="font-semibold text-slate-800">Latest: </span>
          {latest.caseId !== undefined && onOpenCase !== undefined ? (
            <button
              type="button"
              onClick={() => onOpenCase(latest.caseId as string, card.lane)}
              className="text-left font-medium text-cyan-800 underline decoration-cyan-300 underline-offset-2 hover:text-cyan-950"
            >
              {latest.title}
            </button>
          ) : (
            <span className="font-medium text-slate-800">{latest.title}</span>
          )}
          <span className="text-slate-500">
            {" · "}
            <time dateTime={latest.at} title={formatAbsolute(latest.at)}>{formatTimestamp(Date.parse(latest.at))}</time>
          </span>
        </p>
      ) : null}
      {(waiting > 0 || (link !== "none" && available)) && (
        <div className="mt-auto flex flex-wrap items-center gap-x-4 gap-y-2 pt-4">
          {waiting > 0 ? (
            link === "cases" ? (
              <button
                type="button"
                onClick={() => onOpenLane?.(card.lane, { window: "all", status: "waiting" })}
                className="rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-xs font-semibold text-amber-900 hover:border-amber-300 hover:bg-amber-100"
              >
                {waiting.toLocaleString()} waiting on you <span aria-hidden="true">→</span>
              </button>
            ) : (
              <span className="rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-xs font-semibold text-amber-900">
                {waiting.toLocaleString()} waiting on you
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
