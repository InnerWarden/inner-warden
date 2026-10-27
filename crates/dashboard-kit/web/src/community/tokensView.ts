import type { TokenAgent, TokenIntelligenceResponse } from "../api";
import { compactCount, formatCount, humanizeToken } from "../presentation";
import type { TokenPart } from "./ui/charts";

/**
 * One agent's token history, as the Tokens page says it (spec 6.5).
 *
 * The counters arrive as decimal strings because a total can pass what a
 * JavaScript number holds exactly; every sum here is a BigInt. A counter the
 * provider does not report is left out, never a zero.
 *
 * The headline leaves cache reads out: a prompt read back from the cache on
 * every turn would otherwise dwarf what the agent actually sent and got back.
 * Where the CLI says the counters are disjoint (`parts_disjoint`: Claude Code
 * reports input, output, cache writes and cache reads apart), the headline is
 * input + output + cache writes (+ reasoning when reported), and the cache
 * reads are a line of their own. Where they overlap (Codex counts cached
 * input inside input and reasoning inside output), nothing is stacked or
 * subtracted: the total is said as sent, and the overlaps in words.
 */
export type TokenStatus = "counted" | "no_source" | "no_history" | "not_read" | "reading";

export type TokenView = {
  id: string;
  name: string;
  status: TokenStatus;
  disjoint: boolean;
  /** The headline count and what it counts; absent where nothing was counted. */
  headline?: { value: bigint; words: string };
  /** Cache reads, apart from the headline (disjoint counters only). */
  cacheReads?: bigint;
  /** Stacked in the bar: disjoint counters only, each one the provider reported. */
  parts: TokenPart[];
  /** The overlaps in words, for counters that are not disjoint. */
  lines: string[];
  provenance: { quality: string; words: string; note: string };
  /** "Read 4,641 of 4,641 files." or, for a capped scan, that only the newest history was read. */
  coverage?: string;
  sessions: number | null;
  lastUsedAt?: number;
  /** Every counter exactly as sent, for the technical view and the table. */
  counters: { key: string; label: string; value: string | null }[];
  availability: string;
  source: string;
};

/** The provenance chip's words, by the CLI's `quality`; an unknown one is said in its own words. */
export const QUALITY_WORDS: Record<string, string> = {
  sample: "A sample",
  partial: "Partial",
  unsupported: "No local source",
  no_data: "No history yet",
  error: "Not read",
  loading: "Reading",
};

export function qualityWords(quality: string): string {
  return QUALITY_WORDS[quality] ?? humanizeToken(quality);
}

function big(value: string | null): bigint | null {
  return value === null || !/^(0|[1-9]\d*)$/.test(value) ? null : BigInt(value);
}

/** A count in words: exact below a million ("353,850"), then "68.6 million". */
export function tokenWords(value: bigint): string {
  return value < 1_000_000n ? formatCount(value) : compactCount(value);
}

function coverageLine(coverage: TokenAgent["coverage"]): string | undefined {
  if (coverage === undefined) return undefined;
  const read = `Read ${formatCount(coverage.files_read)} of ${formatCount(coverage.files_found)} ${coverage.files_found === 1 ? "file" : "files"}`;
  return coverage.complete ? `${read}.` : `${read}: the newest history only.`;
}

function statusOf(agent: TokenAgent, total: bigint | null): TokenStatus {
  if (agent.availability === "unsupported" || agent.provenance.quality === "unsupported") return "no_source";
  if (agent.availability === "loading") return "reading";
  if (agent.availability === "no_data") return "no_history";
  if (agent.availability === "available" && total !== null) return "counted";
  return "not_read";
}

export function tokenView(agent: TokenAgent & { parts_disjoint?: unknown }): TokenView {
  const total = big(agent.total_tokens);
  const input = big(agent.input_tokens);
  const output = big(agent.output_tokens);
  const cacheRead = big(agent.cache_read_input_tokens);
  const cacheWrite = big(agent.cache_creation_input_tokens);
  const cached = big(agent.cached_input_tokens);
  const reasoning = big(agent.reasoning_output_tokens);
  const disjoint = agent.parts_disjoint === true;
  const status = statusOf(agent, total);
  const counters = [
    { key: "total", label: "Total", value: agent.total_tokens },
    { key: "input", label: "Input", value: agent.input_tokens },
    { key: "output", label: "Output", value: agent.output_tokens },
    { key: "cache_write", label: "Written to cache", value: agent.cache_creation_input_tokens },
    { key: "cache_read", label: "Read from cache", value: agent.cache_read_input_tokens },
    { key: "cached", label: "Cached input (inside input)", value: agent.cached_input_tokens },
    { key: "reasoning", label: "Reasoning (inside output)", value: agent.reasoning_output_tokens },
  ];
  const view: TokenView = {
    id: agent.agent_id,
    name: agent.display_name,
    status,
    disjoint,
    parts: [],
    lines: [],
    provenance: { quality: agent.provenance.quality, words: qualityWords(agent.provenance.quality), note: agent.provenance.note },
    ...(coverageLine(agent.coverage) === undefined ? {} : { coverage: coverageLine(agent.coverage) }),
    sessions: agent.sessions,
    ...(agent.last_observed_at_ms === null ? {} : { lastUsedAt: agent.last_observed_at_ms }),
    counters,
    availability: agent.availability,
    source: agent.provenance.source,
  };
  if (status !== "counted" || total === null) return view;

  if (disjoint && input !== null && output !== null) {
    const parts: TokenPart[] = [
      { key: "input", label: "Input", value: input },
      { key: "output", label: "Output", value: output },
      ...(cacheWrite === null ? [] : [{ key: "cache_write", label: "Written to cache", value: cacheWrite }]),
      ...(reasoning === null ? [] : [{ key: "reasoning", label: "Reasoning", value: reasoning }]),
    ];
    const fresh = parts.reduce((sum, part) => sum + part.value, 0n);
    return {
      ...view,
      headline: { value: fresh, words: "tokens, not counting cache reads" },
      ...(cacheRead === null ? {} : { cacheReads: cacheRead }),
      parts: parts.filter((part) => part.value > 0n),
    };
  }

  // Counters that overlap: nothing stacked.
  const lines: string[] = [];
  if (input !== null) lines.push(cached === null ? `${tokenWords(input)} input` : `${tokenWords(input)} input, of which ${tokenWords(cached)} cached`);
  if (output !== null) lines.push(reasoning === null ? `${tokenWords(output)} output` : `${tokenWords(output)} output, of which ${tokenWords(reasoning)} reasoning`);
  // Cached input is reported as part of input (its counter says so), so the
  // headline can leave it out and be on the same basis as an agent whose
  // parts are apart: "not counting cache reads", the cached part said under
  // it. Two headlines side by side then compare like with like.
  if (input !== null && output !== null && cached !== null && cached <= input) {
    return { ...view, headline: { value: input - cached + output, words: "tokens, not counting cache reads" }, cacheReads: cached, lines };
  }
  return { ...view, headline: { value: total, words: cached === null ? "tokens in all" : "tokens in all, cached input included" }, lines };
}

export function tokenViews(report: TokenIntelligenceResponse | undefined): TokenView[] {
  return report === undefined ? [] : report.agents.map((agent) => tokenView(agent));
}

/** The largest headline and the largest cache reads, so every agent is drawn on one scale. */
export function tokenScales(views: readonly TokenView[]): { fresh: bigint; cache: bigint } {
  let fresh = 0n;
  let cache = 0n;
  for (const view of views) {
    if (!view.disjoint || view.headline === undefined) continue;
    if (view.headline.value > fresh) fresh = view.headline.value;
    if ((view.cacheReads ?? 0n) > cache) cache = view.cacheReads ?? 0n;
  }
  return { fresh, cache };
}

/** What to say for an agent nothing was counted for: never a zero. */
export function noCountWords(view: TokenView): string {
  switch (view.status) {
    case "no_source":
      return `No local source for ${view.name}'s tokens.`;
    case "no_history":
      return `No token history from ${view.name} on this machine yet.`;
    case "reading":
      return `Still reading ${view.name}'s history.`;
    default:
      return `Not read: ${view.name}'s history could not be counted.`;
  }
}
