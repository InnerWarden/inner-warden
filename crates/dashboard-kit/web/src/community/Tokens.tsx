import { fetchTokenIntelligence } from "../api";
import { MachineIntelligence } from "../components/MachineIntelligence";
import { TechnicalOnly } from "../components/TechnicalDetail";
import { Swatch, TONE_HEX } from "../components/viz";
import { compactCount, formatCount, formatDay } from "../presentation";
import { CARD, PageHeader, Skeleton, StaleLine, Unreadable } from "./parts";
import { usePolled } from "./poll";
import { share, tokenRows, type TokenRow } from "./tokensView";

export const TOKENS_PAGE_POLL_MS = 300_000;

/**
 * Community's Tokens: how much each agent used, from the history it keeps on
 * this machine. Context for activity; not a security score and not a bill.
 */
export function CommunityTokens() {
  const report = usePolled(fetchTokenIntelligence, TOKENS_PAGE_POLL_MS, "tokens");
  const rows = tokenRows(report.data);
  const largest = rows.reduce((max, row) => (row.total !== null && row.total > max ? row.total : max), 0n);
  return (
    <div className="min-w-0 space-y-5" data-tour="tokens">
      <PageHeader
        eyebrow="Tokens"
        title="Tokens"
        titleId="tokens-title"
        description="How much each agent used, from the history it keeps on this machine. Context for activity, not a security score and not a bill."
      />
      {report.stale ? <StaleLine onRetry={report.refresh} /> : null}
      {report.data === undefined ? (
        report.error === undefined ? <Skeleton className="h-48" /> : <Unreadable title="Token history did not answer" onRetry={report.refresh} />
      ) : report.data.availability === "loading" ? (
        <Skeleton className="h-48" />
      ) : rows.length === 0 ? (
        <p className={`${CARD} text-sm text-slate-600`}>No agent on this machine keeps a token history this can read.</p>
      ) : (
        <section aria-labelledby="tokens-list-title" className={CARD}>
          <h2 id="tokens-list-title" className="sr-only">Tokens by agent</h2>
          <ul className="divide-y divide-slate-100">
            {rows.map((row) => <TokenRowView key={row.id} row={row} largest={largest} />)}
          </ul>
        </section>
      )}
      <p className="text-xs leading-5 text-slate-500">Read from each agent's own history on this machine; prompts and responses never reach this dashboard.</p>
      <TechnicalOnly>
        <MachineIntelligence edition="community" showAgents={false} showTokens />
      </TechnicalOnly>
    </div>
  );
}

function TokenRowView({ row, largest }: { row: TokenRow; largest: bigint }) {
  if (!row.available || row.total === null) {
    return (
      <li data-token-agent={row.id} className="py-4 first:pt-0 last:pb-0">
        <p className="text-sm font-semibold text-slate-950">{row.name}</p>
        <p className="mt-0.5 text-sm text-slate-600">Keeps no token history InnerWarden can read.</p>
      </li>
    );
  }
  const whole = row.total;
  // The bar's length is this agent's share of the largest, so two agents
  // read side by side; its parts are this agent's own split.
  const width = Math.max(0.02, share(whole, largest));
  const meta = [
    `${formatCount(row.sessions ?? 0)} ${row.sessions === 1 ? "session" : "sessions"}`,
    row.lastUsedAt === undefined ? undefined : `last used ${formatDay(row.lastUsedAt)}`,
  ].filter((part): part is string => part !== undefined);
  return (
    <li data-token-agent={row.id} className="py-4 first:pt-0 last:pb-0">
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5">
        <p className="text-sm font-semibold text-slate-950">{row.name}</p>
        <p className="text-sm text-slate-700"><span className="font-semibold text-slate-950">{compactCount(whole)}</span> tokens</p>
        <p className="text-xs text-slate-500">{meta.join(" · ")}</p>
      </div>
      {row.parts.length === 0 ? null : (
        <div className="mt-2 flex h-3 w-full overflow-hidden rounded bg-slate-100" role="img" aria-label={`${row.name}: ${row.parts.map((part) => `${part.label} ${formatCount(part.value)}`).join(", ")}`}>
          <div className="flex h-full gap-[2px]" style={{ width: `${width * 100}%` }}>
            {row.parts.map((part) => (
              <span
                key={part.key}
                data-segment={part.key}
                title={`${part.label}: ${formatCount(part.value)}`}
                className="h-full min-w-[2px] first:rounded-l last:rounded-r"
                style={{ width: `${share(part.value, whole) * 100}%`, background: TONE_HEX[part.tone] }}
              />
            ))}
          </div>
        </div>
      )}
      <ul className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-xs text-slate-600">
        {row.lines.map((line) => {
          const drawn = row.parts.find((part) => part.key === line.key);
          return (
            <li key={line.key} className="inline-flex items-center gap-1.5">
              {drawn === undefined ? null : <Swatch part={{ tone: drawn.tone }} className="h-2.5 w-2.5" />}
              {line.value === null ? (
                <span>{line.label}: not reported</span>
              ) : (
                <span>
                  <span className="font-semibold tabular-nums text-slate-900">{formatCount(line.value)}</span> {line.label}
                  {line.within === undefined ? null : <span className="text-slate-500"> ({line.within})</span>}
                </span>
              )}
            </li>
          );
        })}
      </ul>
    </li>
  );
}
