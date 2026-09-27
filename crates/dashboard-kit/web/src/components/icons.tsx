import type { CaseLaneChoice } from "../lanes";

/**
 * One small glyph per product concept, nothing decorative: 16 by 16, one
 * stroked path in the text colour, hidden from screen readers because the
 * name beside it says the same thing.
 */
export const GLYPHS = {
  gate: "M2 3.5h12v9H2zM2 6h12M5 9.25h6",
  key: "M6.5 8a2.5 2.5 0 1 1-5 0 2.5 2.5 0 0 1 5 0zM6.5 8h8M12.5 8v2.5M10.25 8v2",
  globe: "M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13zM1.5 8h13M8 1.5c-2.3 2.4-2.3 10.6 0 13M8 1.5c2.3 2.4 2.3 10.6 0 13",
  eye: "M1 8s2.5-4.5 7-4.5S15 8 15 8s-2.5 4.5-7 4.5S1 8 1 8zM8 6a2 2 0 1 0 0 4 2 2 0 0 0 0-4z",
  shield: "M8 1.5l5.5 2v4c0 3.4-2.3 5.9-5.5 7-3.2-1.1-5.5-3.6-5.5-7v-4zM5.5 8l1.75 1.75L10.75 6.5",
  waves: "M1.5 4.5c1.5-1.3 2.8-1.3 4.3 0s2.8 1.3 4.3 0 2.8-1.3 4.4 0M1.5 8c1.5-1.3 2.8-1.3 4.3 0s2.8 1.3 4.3 0 2.8-1.3 4.4 0M1.5 11.5c1.5-1.3 2.8-1.3 4.3 0s2.8 1.3 4.3 0 2.8-1.3 4.4 0",
  bell: "M4 11V7a4 4 0 0 1 8 0v4l1.5 1.5h-11zM6.5 14.25h3",
  camera: "M1.5 5.5h3l1.5-2h4l1.5 2h3v8h-13zM8 7a2.5 2.5 0 1 0 0 5 2.5 2.5 0 0 0 0-5z",
  server: "M2 2.5h12V7H2zM2 9h12v4.5H2zM4.5 4.75h1M4.5 11.25h1",
  cloud: "M4.5 12.5H12a2.75 2.75 0 0 0 .4-5.5A4.25 4.25 0 0 0 4.1 6.9 2.8 2.8 0 0 0 4.5 12.5z",
  // Cases: who asked, what ran, who it was, and what it touched.
  chat: "M2 2.5h12v8.5H7.5L4.5 13.5V11H2z",
  prompt: "M1.5 2.5h13v11h-13zM4.5 6l2 2-2 2M8 10.5h3.5",
  target: "M8 3a5 5 0 1 0 0 10A5 5 0 0 0 8 3zM8 1v3.5M8 11.5V15M1 8h3.5M11.5 8H15",
  person: "M8 1.75a2.75 2.75 0 1 0 0 5.5 2.75 2.75 0 0 0 0-5.5zM2.5 14.5c.6-3 2.8-4.75 5.5-4.75s4.9 1.75 5.5 4.75",
  decoy: "M10.5 1.5v8.25a3.25 3.25 0 0 1-6.5 0V7.5l2.25 2.25M9 1.5h3",
  egress: "M9 2.5H2.5v11H9M6 8h8.5M11.5 5l3 3-3 3",
  file: "M3.5 1.5h6l3 3v10h-9zM9.5 1.5v3h3",
} as const;

export type GlyphName = keyof typeof GLYPHS;

/**
 * The glyph for a lane of cases, on its tab and its card: a speech bubble for
 * the messages to the agent, a prompt for what the agent ran, a server for
 * the attacks on it. The whole list is no one concept and gets none.
 */
export function laneGlyph(lane: CaseLaneChoice): GlyphName | undefined {
  switch (lane) {
    case "agent_messages":
      return "chat";
    case "agent_actions":
      return "prompt";
    case "server_attacks":
      return "server";
    default:
      return undefined;
  }
}

export function Glyph({ name, className = "h-4 w-4" }: { name: GlyphName; className?: string }) {
  return (
    <svg viewBox="0 0 16 16" aria-hidden="true" className={`shrink-0 ${className}`} fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d={GLYPHS[name]} />
    </svg>
  );
}

/**
 * The glyph for a host control, matched on the ids the host sends (the
 * layer's id or a capability id), never on its label. A control this table
 * does not know gets no glyph rather than a guessed one.
 */
const CONTROL_GLYPHS: readonly { ids: readonly string[]; glyph: GlyphName }[] = [
  { ids: ["independent_host_execution", "kernel_execution_control"], glyph: "gate" },
  { ids: ["secret_access_control", "secret_read_guard"], glyph: "key" },
  { ids: ["dns_resolution_control", "dns_guard"], glyph: "globe" },
  { ids: ["host_visibility"], glyph: "eye" },
  { ids: ["response_controls"], glyph: "shield" },
];

export function controlGlyph(ids: readonly string[]): GlyphName | undefined {
  return CONTROL_GLYPHS.find((entry) => ids.some((id) => entry.ids.includes(id)))?.glyph;
}
