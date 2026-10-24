import { useId, useState } from "react";
import type { OwnTools } from "./api";
import { dismiss, dismissed } from "./dismiss";
import { BODY_TEXT, LINK_TEXT, META_TEXT } from "./ui/blocks";

/** The one link the suggestion carries, and where it goes. */
export const PRO_PRICING_URL = "https://www.innerwarden.com/pricing";

/** What the card says about OpenClaw's own tools, in the person's words. */
export function ownToolsLine(tools: OwnTools): string {
  if (tools.turnedOff) return "Its own tools (exec, process, write, edit, apply_patch): the guard plugin is turned off in OpenClaw's config.";
  if (!tools.screened) return "Its own tools (exec, process, write, edit, apply_patch) are not screened: innerwarden agents connect openclaw installs the guard plugin.";
  return tools.mode === "enforce"
    ? "Its own tools (exec, process, write, edit, apply_patch) are screened: a deny is refused, a review asks you."
    : "Its own tools (exec, process, write, edit, apply_patch) are screened in monitor: recorded, never refused.";
}

/**
 * The suggestion's text and its one link, split so the link is a link. The
 * CLI sends the whole line; a line without the pricing link is shown as
 * words only.
 */
export function suggestionParts(line: string): { words: string; href?: string } {
  const at = line.indexOf(PRO_PRICING_URL);
  if (at < 0) return { words: line };
  return { words: line.slice(0, at).trim(), href: PRO_PRICING_URL };
}

/**
 * OpenClaw's own tools on its card: the guard's state, what the paid edition
 * says about this host, and the suggestion, which "Not now" hides in this
 * browser (the `agents` slot of `dismiss.ts`). Read by the person on this
 * machine only: the dashboard is local.
 */
export function OwnToolsBlock({ tools }: { tools: OwnTools }) {
  const [hidden, setHidden] = useState(() => dismissed("agents"));
  const lineId = useId();
  const suggestion = tools.suggestion === undefined ? undefined : suggestionParts(tools.suggestion);
  return (
    <div data-own-tools className="space-y-2">
      <p className={BODY_TEXT}>{ownToolsLine(tools)}</p>
      {tools.proLine === undefined ? null : <p data-pro-status className={META_TEXT}>{tools.proLine}</p>}
      {suggestion === undefined || hidden ? null : (
        <aside data-offer="agents" aria-labelledby={lineId} className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <p id={lineId} className={META_TEXT}>
            {suggestion.words}
            {suggestion.href === undefined ? null : (
              <>
                {" "}
                <a href={suggestion.href} target="_blank" rel="noreferrer" className={LINK_TEXT}>
                  Pricing <span aria-hidden="true">↗</span>
                  <span className="sr-only"> (opens innerwarden.com)</span>
                </a>
              </>
            )}
          </p>
          <button
            type="button"
            onClick={() => {
              dismiss("agents");
              setHidden(true);
            }}
            aria-label="Not now: hide this suggestion"
            className="text-sm font-semibold text-(--iw-ink-2) hover:text-(--iw-ink) pointer-coarse:min-h-11"
          >
            Not now
          </button>
        </aside>
      )}
    </div>
  );
}
