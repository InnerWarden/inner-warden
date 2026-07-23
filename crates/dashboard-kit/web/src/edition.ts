import type { DashboardBootstrap } from "./api/v1";

export type EditionBootstrapStatus = "loading" | "ready" | "unavailable" | "error";
export type EditionMetaStatus = "loading" | "ready" | "error";

export function resolveDashboardEdition(
  bootstrap: Pick<DashboardBootstrap, "edition"> | undefined,
  bootstrapStatus: EditionBootstrapStatus,
  metaEdition: string | undefined,
  metaStatus: EditionMetaStatus,
): DashboardBootstrap["edition"] | undefined {
  if (bootstrap) return bootstrap.edition;
  // The legacy endpoint is not an authenticated versioned Enterprise
  // negotiation surface. It may establish compatibility with an older
  // Community binary, but it must never select the privileged edition.
  if (bootstrapStatus === "unavailable" && metaStatus === "ready" && metaEdition === "community") return "community";
  return undefined;
}
