import type { TokenAgent, TokenIntelligenceResponse } from "../api";
import type { Tone } from "../components/viz";

/**
 * One agent's token history as a bar and a legend.
 *
 * The counters arrive as decimal strings because a total can pass what a
 * JavaScript number holds exactly; the legend prints them exact (BigInt),
 * and only the bar widths are scaled as numbers. A counter the provider does
 * not report is "not reported", never a zero segment.
 *
 * Parts are STACKED only where they do not overlap. Claude Code reports
 * input, cache writes and cache reads apart; Codex reports cached input
 * inside input and reasoning inside output, so its bar is input and output,
 * and the two subsets are legend lines. The CLI says which (`parts_disjoint`).
 */
export type TokenPart = { key: string; label: string; value: bigint; tone: Tone };
export type TokenLine = { key: string; label: string; value: bigint | null; within?: string };

export type TokenRow = {
  id: string;
  name: string;
  available: boolean;
  total: bigint | null;
  sessions: number | null;
  lastUsedAt?: number;
  /** Stacked in the bar; they add up to `total` or the bar is not drawn. */
  parts: TokenPart[];
  /** Everything the provider reported, in the legend, exact. */
  lines: TokenLine[];
};

function big(value: string | null): bigint | null {
  return value === null || !/^(0|[1-9]\d*)$/.test(value) ? null : BigInt(value);
}

const TONES: Tone[] = ["fact", "watch", "other", "watchLight"];

export function tokenRow(agent: TokenAgent & { parts_disjoint?: unknown }): TokenRow {
  const total = big(agent.total_tokens);
  const input = big(agent.input_tokens);
  const output = big(agent.output_tokens);
  const cacheRead = big(agent.cache_read_input_tokens);
  const cacheWrite = big(agent.cache_creation_input_tokens);
  const cached = big(agent.cached_input_tokens);
  const reasoning = big(agent.reasoning_output_tokens);
  const disjoint = agent.parts_disjoint === true;
  const lines: TokenLine[] = [];
  let parts: TokenPart[] = [];
  if (disjoint) {
    const candidates: [string, string, bigint | null][] = [
      ["cache_read", "read from cache", cacheRead],
      ["cache_write", "written to cache", cacheWrite],
      ["output", "output", output],
      ["input", "input", input],
    ];
    for (const [key, label, value] of candidates) lines.push({ key, label, value });
    parts = candidates.flatMap(([key, label, value], index) => (value === null || value === 0n ? [] : [{ key, label, value, tone: TONES[index] }]));
  } else {
    lines.push({ key: "input", label: "input", value: input });
    if (cached !== null) lines.push({ key: "cached", label: "cached input", value: cached, within: "inside input" });
    lines.push({ key: "output", label: "output", value: output });
    if (reasoning !== null) lines.push({ key: "reasoning", label: "reasoning", value: reasoning, within: "inside output" });
    parts = ([["input", "input", input], ["output", "output", output]] as [string, string, bigint | null][])
      .flatMap(([key, label, value], index) => (value === null || value === 0n ? [] : [{ key, label, value, tone: TONES[index] }]));
  }
  const sum = parts.reduce((acc, part) => acc + part.value, 0n);
  if (total === null || sum !== total) parts = [];
  return {
    id: agent.agent_id,
    name: agent.display_name,
    available: agent.availability === "available" && total !== null,
    total,
    sessions: agent.sessions,
    ...(agent.last_observed_at_ms === null ? {} : { lastUsedAt: agent.last_observed_at_ms }),
    parts,
    lines: lines.filter((line) => line.value !== null || line.key === "cache_write" || line.key === "input" || line.key === "output"),
  };
}

export function tokenRows(report: TokenIntelligenceResponse | undefined): TokenRow[] {
  return report === undefined ? [] : report.agents.map((agent) => tokenRow(agent));
}

/** Every available agent's total, exact, and how many agents it covers. */
export function tokenTotal(rows: readonly TokenRow[]): { total: bigint; agents: number } | undefined {
  const counted = rows.filter((row) => row.total !== null && row.available);
  if (counted.length === 0) return undefined;
  return { total: counted.reduce((sum, row) => sum + (row.total ?? 0n), 0n), agents: counted.length };
}

/** A bigint scaled to a share of `whole` for a bar width; exact enough for pixels. */
export function share(value: bigint, whole: bigint): number {
  if (whole <= 0n) return 0;
  return Number((value * 1_000_000n) / whole) / 1_000_000;
}
