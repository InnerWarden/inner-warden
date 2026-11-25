import type { DashboardMeta } from "./api";

/**
 * The host install on this machine, named by its licence the way the CLI
 * names it (`HostInstall` in the CLI): the host installer installs it with
 * or without a licence, so "installed" alone never says InnerWarden Pro.
 *
 * - `pro`: a licence is there;
 * - `free_tier`: none is, the host install's free tier;
 * - `unknown`: whether one is there could not be read, or the server is
 *   older than `host_install` and said only `active_defence_installed`.
 */
export type HostInstall = "pro" | "free_tier" | "unknown";

/**
 * PURE. The host install the meta reports, `undefined` where there is none.
 * Only the server's own `pro` names it InnerWarden Pro: anything else it
 * says, or nothing, is a host install without a tier.
 */
export function hostInstallOf(meta: Pick<DashboardMeta, "active_defence_installed" | "host_install"> | undefined): HostInstall | undefined {
  if (meta?.active_defence_installed !== true) return undefined;
  return meta.host_install === "pro" || meta.host_install === "free_tier" ? meta.host_install : "unknown";
}
