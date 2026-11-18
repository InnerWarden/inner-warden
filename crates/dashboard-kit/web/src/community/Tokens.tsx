import { TechnicalOnly } from "../components/TechnicalDetail";
import { formatCount } from "../presentation";
import { StaleLine } from "./parts";
import { useSource } from "./store";
import { tokenScales, tokenViews, tokenWords, noCountWords, type TokenView } from "./tokensView";
import { BODY_TEXT, Disclosure, META_TEXT, NotRead, PAGE_TITLE, PANEL, Pending, ReadAt, SMALL_TEXT, SourceLine } from "./ui/blocks";
import { TokenBars } from "./ui/charts";
import { Icon } from "./ui/Icon";
import { shortDay } from "./words";

/**
 * Community's Tokens (spec 6.5): what each agent's own local history says it
 * used. A sample, not a bill, and not a security score. The headline leaves
 * cache reads out (they are said apart); counters that overlap are never
 * stacked; a source that does not exist is said, never drawn as zero. No time
 * series: the history has no per-day totals.
 */
export function CommunityTokens() {
  const report = useSource("tokens");
  const data = report.data;
  const views = tokenViews(data);
  const scales = tokenScales(views);
  let body;
  if (data === undefined) {
    body = report.error === undefined ? (
      <Pending label="Reading token history" className="h-48" />
    ) : (
      <NotRead alert onRetry={report.refresh}>Token history did not answer. Nothing here is counted as zero.</NotRead>
    );
  } else if (data.availability === "loading") {
    body = <Pending label="Reading token history" className="h-48" />;
  } else if (views.length === 0) {
    body = <p className={`${PANEL} ${BODY_TEXT}`}>No agent on this machine keeps a token history this can read.</p>;
  } else {
    body = (
      <section aria-labelledby="tokens-list-title" className="min-w-0">
        <h2 id="tokens-list-title" className="sr-only">Tokens by agent</h2>
        <ul className="grid min-w-0 grid-cols-1 gap-6 lg:grid-cols-2">
          {views.map((view) => <TokenCard key={view.id} view={view} scales={scales} />)}
        </ul>
      </section>
    );
  }
  return (
    <div data-tokens className="min-w-0 space-y-8" data-tour="tokens">
      <div className="space-y-1">
        <h1 id="tokens-title" tabIndex={-1} className={PAGE_TITLE}>Tokens</h1>
        <p className={BODY_TEXT}>What your agents' own local history says they used. A sample, not a bill.</p>
      </div>
      {report.stale ? <StaleLine onRetry={report.refresh} /> : null}
      {body}
      <SourceLine>Read from each agent's own history on this machine; prompts and responses never reach this dashboard.</SourceLine>
      <TechnicalOnly>
        <p data-tokens-technical className={META_TEXT}>Per-day totals are not recorded.</p>
      </TechnicalOnly>
      <ReadAt data={data} path="/api/guard/token-intelligence" />
    </div>
  );
}

function TokenCard({ view, scales }: { view: TokenView; scales: { fresh: bigint; cache: bigint } }) {
  const meta = [
    view.sessions === null ? undefined : `${formatCount(view.sessions)} ${view.sessions === 1 ? "session" : "sessions"}`,
    view.lastUsedAt === undefined ? undefined : `last used ${shortDay(new Date(view.lastUsedAt).toISOString()) ?? ""}`,
  ].filter((part): part is string => part !== undefined);
  return (
    <li data-token-agent={view.id} data-token-status={view.status} className={`${PANEL} space-y-3`}>
      <article aria-labelledby={`token-${view.id}-title`} className="min-w-0 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
          <h3 id={`token-${view.id}-title`} className="text-[15px] leading-[22px] font-semibold text-(--iw-ink)">{view.name}</h3>
          <ProvenanceChip view={view} />
        </div>
        {view.headline === undefined ? (
          <p data-token-none className={`flex items-start gap-2 ${BODY_TEXT}`}>
            <span className="mt-0.5 text-(--iw-unknown)"><Icon name="dashed-circle" /></span>
            {noCountWords(view)}
          </p>
        ) : (
          <>
            <div>
              <p data-token-headline className="flex flex-wrap items-baseline gap-x-2">
                <span className="text-[28px] leading-8 font-semibold tabular-nums text-(--iw-ink)" title={`${formatCount(view.headline.value)} tokens`}>
                  {tokenWords(view.headline.value)}
                </span>
                <span className={BODY_TEXT}>{view.headline.words}</span>
              </p>
              {view.cacheReads === undefined ? null : (
                <p data-token-cache className={`${SMALL_TEXT} text-(--iw-ink-2)`} title={`${formatCount(view.cacheReads)} tokens`}>
                  plus {tokenWords(view.cacheReads)} re-read from cache
                </p>
              )}
            </div>
            {view.disjoint ? (
              view.parts.length === 0 ? null : (
                <>
                  <TokenBars agent={view.name} parts={view.parts} cacheReads={view.cacheReads} scale={scales.fresh} cacheScale={scales.cache} />
                  <p data-token-parts className={META_TEXT}>
                    {view.parts.map((part) => `${tokenWords(part.value)} ${part.label.toLowerCase()}`).join(", ")}.
                  </p>
                </>
              )
            ) : (
              <>
                <ul data-token-lines className={`space-y-0.5 ${BODY_TEXT}`}>
                  {view.lines.map((line) => <li key={line}>{line}</li>)}
                </ul>
                <Disclosure summary="Show the exact counts">
                  <ExactTable view={view} />
                </Disclosure>
              </>
            )}
          </>
        )}
        {view.provenance.note === "" ? null : <p data-token-note className={META_TEXT}>{view.provenance.note}</p>}
        {view.coverage === undefined ? null : <p data-token-coverage className={META_TEXT}>{view.coverage}</p>}
        {meta.length === 0 ? null : <p className={META_TEXT}>{meta.join(", ")}</p>}
        <TechnicalOnly>
          <div data-token-technical className="space-y-2 border-t border-(--iw-line) pt-3">
            <p className={META_TEXT}>
              Availability: {view.availability}. Source: {view.source}. Quality: {view.provenance.quality}.
            </p>
            <ExactTable view={view} />
          </div>
        </TechnicalOnly>
      </article>
    </li>
  );
}

/** The provenance in a chip, from the CLI's own `quality`: what kind of count this is. */
function ProvenanceChip({ view }: { view: TokenView }) {
  const dashed = view.status !== "counted";
  return (
    <span
      data-provenance={view.provenance.quality}
      data-pill={dashed ? "unknown" : "off"}
      className="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-semibold"
    >
      {view.provenance.words}
    </span>
  );
}

/** Every counter exactly as the CLI sent it; one it does not report says so, never zero. */
function ExactTable({ view }: { view: TokenView }) {
  return (
    <table className={`w-full text-left ${SMALL_TEXT} text-(--iw-ink-2)`}>
      <caption className="sr-only">{view.name}: every counter, exact</caption>
      <tbody>
        {view.counters.map((counter) => (
          <tr key={counter.key} className="border-t border-(--iw-line) first:border-t-0">
            <th scope="row" className="py-1 pr-3 font-normal text-(--iw-ink-3)">{counter.label}</th>
            <td className="py-1 text-right font-mono tabular-nums [overflow-wrap:anywhere]">{counter.value === null ? "not reported" : formatExact(counter.value)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** A decimal string with thousands separators, exact at any length. */
function formatExact(value: string): string {
  return /^(0|[1-9]\d*)$/.test(value) ? formatCount(BigInt(value)) : value;
}
