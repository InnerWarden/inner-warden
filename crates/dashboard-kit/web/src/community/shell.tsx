import type { ReactNode } from "react";
import { PROTECTION_LABEL, type CommunityScreenContext, type CommunityShell } from "../App";
import { TechnicalOnly } from "../components/TechnicalDetail";
import { CommunityAgents } from "./Agents";
import { CommunityCases } from "./Cases";
import { HeaderStatus } from "./HeaderStatus";
import { PageNotices } from "./Notices";
import { CommunityOverview } from "./Overview";
import { CommunityProtection } from "./Protection";
import { CommunityTokens } from "./Tokens";

/**
 * Every Community page: the notices first, then the page, then (technical
 * view) whether this dashboard answers only on this machine, which used to be
 * a second header chip.
 */
function Page({ context, children }: { context: CommunityScreenContext; children: ReactNode }) {
  return (
    <div className="min-w-0 space-y-6">
      <PageNotices meta={context.meta} />
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
    { route: "overview", label: "Overview", render: (context) => <Page context={context}><CommunityOverview context={context} /></Page> },
    { route: "posture", label: PROTECTION_LABEL, render: (context) => <Page context={context}><CommunityProtection context={context} /></Page> },
    { route: "activity", label: "Cases", render: (context) => <Page context={context}><CommunityCases context={context} /></Page> },
    { route: "agents", label: "Agents", render: (context) => <Page context={context}><CommunityAgents /></Page> },
    { route: "tokens", label: "Tokens", render: (context) => <Page context={context}><CommunityTokens /></Page> },
  ],
  status: (meta, metaStatus) => <HeaderStatus meta={meta} metaStatus={metaStatus} />,
  alias: communityAlias,
};
