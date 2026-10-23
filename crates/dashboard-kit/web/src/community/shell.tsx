import { useEffect, useRef, type ReactNode } from "react";
import { PROTECTION_LABEL, type CommunityScreenContext, type CommunityShell } from "../App";
import { TechnicalOnly } from "../components/TechnicalDetail";
import { CommunityAgents } from "./Agents";
import { CommunityDecisions } from "./Decisions";
import { HeaderStatus } from "./HeaderStatus";
import { PageNotices } from "./Notices";
import { CommunityOverview } from "./Overview";
import { CommunityProtection } from "./Protection";
import { CommunityTokens } from "./Tokens";
import { HatchDefs } from "./ui/marks";
// Community's tokens and tone rules. Imported here and nowhere else, so only
// the Community entry point, which mounts this shell, loads them.
import "./theme.css";

/** How long a page's heading is waited for after a route change: a page draws it once its first answer lands. */
export const HEADING_WAIT_MS = 5_000;

/**
 * Moves focus to the page's heading when the route changes, never on the
 * first load: someone who moved between pages lands on the new page's title,
 * and someone who just opened the dashboard is not moved anywhere. A page
 * that draws its heading only once its first answer lands is waited for, a
 * few seconds at most.
 */
/** Whether a render of `route` after `previous` is a move between pages: never the first load, never a re-render. */
export function movedBetweenPages(previous: string | undefined, route: string): boolean {
  return previous !== undefined && previous !== route;
}

export function useFocusOnRouteChange(route: string) {
  const root = useRef<HTMLDivElement>(null);
  const previous = useRef<string | undefined>(undefined);
  useEffect(() => {
    const before = previous.current;
    previous.current = route;
    const page = root.current;
    if (!movedBetweenPages(before, route) || page === null) return;
    const focusHeading = (): boolean => {
      // Someone already working inside the new page keeps their place.
      if (document.activeElement !== null && document.activeElement !== document.body && page.contains(document.activeElement)) return true;
      const heading = page.querySelector<HTMLHeadingElement>("h1");
      if (heading === null) return false;
      if (!heading.hasAttribute("tabindex")) heading.setAttribute("tabindex", "-1");
      heading.focus();
      return true;
    };
    if (focusHeading() || typeof MutationObserver === "undefined") return;
    const observer = new MutationObserver(() => {
      if (focusHeading()) stop();
    });
    const timer = setTimeout(() => stop(), HEADING_WAIT_MS);
    const stop = () => {
      observer.disconnect();
      clearTimeout(timer);
    };
    observer.observe(page, { childList: true, subtree: true });
    return stop;
  }, [route]);
  return root;
}

/**
 * Every Community page: the notices first, then the page, then (technical
 * view) whether this dashboard answers only on this machine, which used to be
 * a second header chip. The hatch patterns every mark and chart draws with
 * are defined here, once.
 */
function Page({ context, route, children }: { context: CommunityScreenContext; route: string; children: ReactNode }) {
  const root = useFocusOnRouteChange(route);
  return (
    <div ref={root} data-community-page={route} className="min-w-0 space-y-6">
      <HatchDefs />
      <PageNotices meta={context.meta} route={route} onOverview={() => context.navigate("overview")} />
      {children}
      {context.meta?.exposed === false ? (
        <TechnicalOnly>
          <p data-local-only className="border-t border-slate-200 pt-4 text-xs text-slate-500">
            Local only: this dashboard answers on this machine and nowhere else.
          </p>
        </TechnicalOnly>
      ) : null}
    </div>
  );
}

/**
 * An address written for the paid Cases (`?view=cases&case=<id>`), rewritten
 * for Community's (`?view=activity&decision=<id>`), so a link shared from the
 * paid edition opens the same decision here. A lane Community does not have
 * is dropped rather than left to select nothing.
 */
export function communityAlias(search: string): string | undefined {
  const params = new URLSearchParams(search);
  if (params.get("view") !== "cases") return undefined;
  params.set("view", "activity");
  const caseId = params.get("case");
  params.delete("case");
  if (caseId !== null && caseId.length > 0 && caseId.length <= 256) params.set("decision", caseId);
  const lane = params.get("lane");
  if (lane !== null && lane !== "agent_messages") params.delete("lane");
  for (const name of ["window", "status", "severity", "capability", "scope", "scope_kind", "authority"]) params.delete(name);
  return `?${params.toString()}`;
}

/** The Community edition's screens, in the nav's order. Only `main.tsx` imports this. */
export const COMMUNITY_SHELL: CommunityShell = {
  screens: [
    { route: "overview", label: "Overview", render: (context) => <Page context={context} route="overview"><CommunityOverview context={context} /></Page> },
    { route: "posture", label: PROTECTION_LABEL, render: (context) => <Page context={context} route="posture"><CommunityProtection context={context} /></Page> },
    { route: "activity", label: "Decisions", render: (context) => <Page context={context} route="activity"><CommunityDecisions context={context} /></Page> },
    { route: "agents", label: "Agents", render: (context) => <Page context={context} route="agents"><CommunityAgents context={context} /></Page> },
    { route: "tokens", label: "Tokens", render: (context) => <Page context={context} route="tokens"><CommunityTokens /></Page> },
  ],
  status: (meta, metaStatus) => <HeaderStatus meta={meta} metaStatus={metaStatus} />,
  alias: communityAlias,
};
