import { useEffect, useRef, useState, type ReactNode } from "react";
import { fetchMeta, type DashboardMeta } from "./api";
import {
  dashboardV1Client,
  retainDashboardResource,
  type DashboardResource,
} from "./api/client";
import type { AgentInventory, DashboardBootstrap, DashboardPosture, TokenIntelligence as TokenIntelligenceContract } from "./api/v1";
import { CapabilityBoundary } from "./components/CapabilityBoundary";
import { Header, type HeaderNavigationItem } from "./components/Header";
import { StatusBadge } from "./components/StatusBadge";
import { resolveDashboardEdition } from "./edition";
import { pollChain } from "./hooks/pollChain";
import { hasControlCharacters } from "./presentation";
import { POSTURE_REFRESH_MS } from "./posture/refresh";
import { isCaseListWindow } from "./windows";
import { Home, type MachinePanels, type QueueOpenOptions } from "./screens/Home";
import { isCaseLane, type CaseLane } from "./api/lanes";
import type { CaseListWindow } from "./api/cases";
import type { LaneOpenOptions } from "./components/LaneCards";
import { Agents } from "./screens/Agents";
import { Posture } from "./screens/Posture";
import { TokenIntelligence } from "./screens/TokenIntelligence";

/**
 * The routes this repository builds. A contributed screen widens the type but
 * can never take one of these names -- see `contributedScreens`.
 */
export type BaseShellRoute = "overview" | "activity" | "posture" | "agents" | "tokens";
export type ShellRoute = BaseShellRoute | (string & {});

/** How often the posture surfaces re-fetch; see `posture/refresh.ts`. */
export { POSTURE_REFRESH_MS };

const BASE_ROUTES: readonly string[] = ["overview", "activity", "posture", "agents", "tokens"];

/** The Enterprise tab for the `posture` route. */
export const PROTECTION_LABEL = "Protection";

/**
 * Context the shell hands to a contributed screen.
 *
 * Deliberately narrow. The shell keeps ownership of the bootstrap fetch, the
 * session boundary, navigation and history; a contributed screen owns only what
 * it draws, and looks up its own capability record from `bootstrap`.
 */
export type ScreenContext = {
  bootstrap: DashboardBootstrap;
  evaluatedAt: string;
};

/**
 * A screen contributed by a build that is not this repository -- today, the
 * Active Defence bundle's Cases, Evaluation and Proof screens.
 *
 * This exists so that adding a screen does not mean forking `App.tsx`. The fork
 * it replaces drifted on two files it never intended to change: an upsell URL in
 * `Home.tsx`, and an empty-state fix in `Posture.tsx` that was written, reviewed
 * and then stranded in the fork for months without reaching a user.
 */
export type ScreenModule = {
  /** The `?view=` value. Must not be a base route. */
  route: string;
  label: string;
  /**
   * Whether the tab is offered at all.
   *
   * Contributed screens follow the same rule the base routes follow: a
   * capability that is published but not `available` is an inventory entry, not
   * a screen, so it earns no tab.
   */
  offersTab: (bootstrap: DashboardBootstrap) => boolean;
  /**
   * When true, an explicit `?view=` still mounts the screen even though
   * `offersTab` returned false, because the screen renders its own honest
   * unavailable state.
   *
   * Without this the shell would bounce an explicit deep link to Overview,
   * silently discarding what the operator asked for and replacing a stated
   * reason with no reason at all.
   */
  rendersOwnUnavailableState?: boolean;
  render: (context: ScreenContext) => ReactNode;
};

/** How often the shell re-reads `guard/meta`, counted from the previous answer. */
export const META_POLL_MS = 5_000;

type MetaStatus = "loading" | "ready" | "error";

/**
 * What the shell hands a Community screen: the facts it already read, and
 * the way to move between screens. Deliberately narrow, like `ScreenContext`.
 */
export type CommunityScreenContext = {
  meta?: DashboardMeta;
  metaStatus: MetaStatus;
  bootstrap?: DashboardBootstrap;
  /**
   * Go to one of the shell's routes, with that screen's own address
   * parameters. Every other screen parameter is cleared, as the nav does.
   */
  navigate: (route: ShellRoute, params?: Readonly<Record<string, string>>) => void;
  /** The address's query string, so a screen re-reads its own parameters when they change. */
  search: string;
};

export type CommunityScreen = {
  route: BaseShellRoute;
  label: string;
  render: (context: CommunityScreenContext) => ReactNode;
};

/**
 * The Community edition's own screens, handed in by the Community entry point
 * (`main.tsx`). The paid shell never passes it; a Community shell without it
 * renders the kit Overview alone, which only a test ever does.
 *
 * Its screens take BASE routes (`activity`, `posture`, `agents`, `tokens`),
 * so every existing link and tour step keeps working, and `BASE_ROUTES` and
 * `contributedScreens` are untouched.
 */
export type CommunityShell = {
  screens: readonly CommunityScreen[];
  /** The header's status, from the shell's own `guard/meta` reading. */
  status: (meta: DashboardMeta | undefined, metaStatus: MetaStatus) => ReactNode;
  /**
   * An address written for another edition, rewritten for this one: the
   * query string to use instead, or `undefined` to leave it. Applied once,
   * with `history.replaceState`, as soon as the edition is known.
   */
  alias?: (search: string) => string | undefined;
};

/**
 * Contributed screens that are safe to mount: a module may not shadow a route
 * the shell itself owns, so a bad or stale contribution cannot capture
 * Overview, Posture, Agents or Tokens.
 */
function contributedScreens(extraScreens: readonly ScreenModule[]): ScreenModule[] {
  return extraScreens.filter((screen) => !BASE_ROUTES.includes(screen.route));
}

type BootstrapLoadStatus = "loading" | "ready" | "unavailable" | "error";

export function deriveShellNavigation(
  bootstrap: DashboardBootstrap | undefined,
  edition: DashboardBootstrap["edition"] | undefined,
  extraScreens: readonly ScreenModule[] = [],
  communityScreens?: readonly Pick<CommunityScreen, "route" | "label">[],
): HeaderNavigationItem<ShellRoute>[] {
  if (edition === "community") {
    // Community navigation never depends on an Enterprise producer or
    // entitlement record: it is Overview plus the screens the Community entry
    // point hands in, in its order.
    const items: HeaderNavigationItem<ShellRoute>[] = [{ route: "overview", label: "Overview" }];
    for (const screen of communityScreens ?? []) {
      if (screen.route !== "overview" && !items.some((item) => item.route === screen.route)) {
        items.push({ route: screen.route, label: screen.label });
      }
    }
    return items;
  }
  if (edition !== "enterprise" || bootstrap === undefined) return [];

  const items: HeaderNavigationItem<ShellRoute>[] = [{ route: "overview", label: "Overview" }];
  if (bootstrap.capabilities.some((capability) => capability.tier === "enterprise_core")) {
    // "Protection", not "Posture": the screen answers what is switched on to
    // protect this host, and "posture" is our word for it, not a reader's.
    // The route stays `posture`, so every link and bookmark keeps working.
    // Community's navigation never offers this screen, so it has no name to
    // keep there.
    items.push({ route: "posture", label: PROTECTION_LABEL });
  }
  // Availability, not mere presence. The capability contract requires the
  // Enterprise superset to PUBLISH every Community id, so an id being in the
  // bootstrap payload is guaranteed by design and says nothing about whether
  // the screen behind it can render. Keying tabs on presence offered screens
  // whose endpoint reports the source does not exist -- the operator clicks a
  // tab that can only ever say "no data".
  //
  // `community.token_intelligence` is exactly that today: it draws a screen
  // reading LLM token CONSUMPTION from a usage history no runtime wires.
  if (
    bootstrap.capabilities.some(
      (capability) =>
        capability.id === "community.agent_discovery" && capability.availability === "available",
    )
  ) {
    items.push({ route: "agents", label: "Agents" });
  }
  if (
    bootstrap.capabilities.some(
      (capability) =>
        capability.id === "community.token_intelligence" && capability.availability === "available",
    )
  ) {
    items.push({ route: "tokens", label: "Tokens" });
  }
  for (const screen of contributedScreens(extraScreens)) {
    if (screen.offersTab(bootstrap)) items.push({ route: screen.route, label: screen.label });
  }
  return items;
}

/**
 * Which route a query string asks for. Pure so it can be tested without a DOM;
 * `routeFromLocation` is the one-line window wrapper.
 */
export function resolveRoute(search: string, extraScreens: readonly ScreenModule[] = []): ShellRoute {
  const candidate = new URLSearchParams(search).get("view");
  if (candidate === null) return "overview";
  if (candidate !== "overview" && BASE_ROUTES.includes(candidate)) return candidate;
  if (contributedScreens(extraScreens).some((screen) => screen.route === candidate)) return candidate;
  return "overview";
}

/**
 * Whether a route the navigation does not offer should fall back to Overview.
 *
 * A contributed screen that renders its own unavailable state is exempt: it
 * answers "why is this empty" itself, and bouncing would replace that answer
 * with silence. Pure so the rule is testable without a DOM.
 */
export function shouldResetToOverview(
  route: ShellRoute,
  navigation: readonly HeaderNavigationItem<ShellRoute>[],
  extraScreens: readonly ScreenModule[] = [],
): boolean {
  const contributed = contributedScreens(extraScreens).find((screen) => screen.route === route);
  if (contributed?.rendersOwnUnavailableState === true) return false;
  return navigation.length > 0 && !navigation.some((item) => item.route === route);
}

function routeFromLocation(extraScreens: readonly ScreenModule[]): ShellRoute {
  return resolveRoute(window.location.search, extraScreens);
}

/**
 * Every query parameter a screen owns. Navigation clears them so a filter set
 * on one screen does not leak into the next; each screen re-writes its own.
 */
const SCREEN_PARAMS = [
  "q", "outcome", "severity", "status", "mode", "authority", "capability", "scope_kind",
  "scope", "window", "cursor", "case", "decision", "session", "verdict", "action", "lane",
  "reason",
] as const;

const ACTIVITY_PARAM_LIMIT = 256;

/**
 * The Activity selection carried by the address bar.
 *
 * The selection used to live only in React state: clicking a Home entry opened
 * the right decision, and then a reload, a shared link or the back button lost
 * it. Community's Activity screen is its case surface, so a decision there
 * deserves an address exactly like a paid case gets `?view=cases&case=<id>`.
 * Pure so it is testable without a DOM.
 */
export function activityTargetFromSearch(
  search: string,
): { id?: string; session?: string; verdict?: string; action?: string } | undefined {
  const parameters = new URLSearchParams(search);
  if (parameters.get("view") !== "activity") return undefined;
  const bounded = (name: string): string | undefined => {
    const value = parameters.get(name) ?? "";
    return value.length > 0 && value.length <= ACTIVITY_PARAM_LIMIT ? value : undefined;
  };
  const target = {
    id: bounded("decision"),
    session: bounded("session"),
    verdict: bounded("verdict"),
    action: bounded("action"),
  };
  if (!target.id && !target.session && !target.action) return undefined;
  return target;
}

/** The URL for one Activity selection; the inverse of `activityTargetFromSearch`. */
export function activityUrl(
  target: { id?: string; session?: string; verdict?: string; action?: string } | undefined,
  current: string,
): URL {
  const url = new URL(current);
  for (const name of SCREEN_PARAMS) url.searchParams.delete(name);
  url.searchParams.set("view", "activity");
  const bounded = (value?: string) =>
    value !== undefined && value.length > 0 && value.length <= ACTIVITY_PARAM_LIMIT
      ? value
      : undefined;
  const values: [string, string | undefined][] = [
    ["decision", bounded(target?.id)],
    ["session", bounded(target?.session)],
    ["verdict", bounded(target?.verdict)],
    ["action", bounded(target?.action)],
  ];
  for (const [name, value] of values) {
    if (value !== undefined) url.searchParams.set(name, value);
  }
  return url;
}

/**
 * The URL that opens the Cases screen, optionally on one case: the
 * click-through target for anything on Home that shows a decision or an event
 * with a case behind it.
 */
export function caseUrl(caseId: string | undefined, current: string, lane?: CaseLane, window?: CaseListWindow): URL {
  const url = new URL(current);
  for (const name of SCREEN_PARAMS) url.searchParams.delete(name);
  url.searchParams.set("view", "cases");
  if (caseId !== undefined && caseId.length > 0 && caseId.length <= 256) {
    url.searchParams.set("case", caseId);
    // A case opened from a lane card opens inside that lane, so the list
    // beside it is the one the card was about.
    if (isCaseLane(lane)) url.searchParams.set("lane", lane);
    // The window has to travel with the case, and this used to return before
    // setting it. A deep link names ONE case; the Cases list then applied its
    // default window to it, so opening anything older landed on a list the
    // case was not in, with nothing selected. The operator read that as a
    // broken link. A link that names its target must not be filtered out by a
    // default the operator never chose.
    //
    // A link that knows the span its case was counted in, and that the case
    // falls in (a lane card's newest case, `latestCaseWindow`), opens that
    // span instead: the list beside it is the one the card described. Every
    // other link opens every day.
    url.searchParams.set("window", isCaseListWindow(window) ? window : "all");
    return url;
  }
  // No case named: this is Home's "View all in Cases", clicked from beside a
  // tile counting the WHOLE decision record. The Cases list defaults to the
  // last 24 hours (`readCaseViewState`), so that click used to answer a
  // narrower question than the one the operator had just read, and the drop
  // from 17 decisions to 1 case looked like lost data. Handing it the same span
  // makes the two screens answer the same question, and the span lands in the
  // address bar like every other Cases filter, so it can be narrowed from the
  // controls on that screen.
  url.searchParams.set("window", "all");
  return url;
}

/**
 * The Cases screen narrowed to what is waiting on a person, over every lane.
 *
 * This is where the Overview's waiting line sends the reader. `waiting` is
 * every case whose latest decision is absent or awaiting confirmation, the
 * pair that line counts; and all time rather than the list's default,
 * because a case waiting since yesterday is still waiting, unless the server
 * said which span it counted.
 *
 * `lane=everything`, because the count is every lane's. With no lane in the
 * address the Cases screen opens ONE lane (the one this viewer last used, or
 * the agent's or the server's), so "See the 145 waiting cases" listed the
 * waiting cases of one lane under a count of all of them, the same mismatch
 * (145 on one screen, 257 on the next) the one count was meant to end. On a
 * server older than lanes the word is no lane at all, which is the whole
 * list it always opened.
 */
export function caseQueueUrl(current: string, window: CaseListWindow = "all"): URL {
  const url = caseUrl(undefined, current);
  url.searchParams.set("lane", "everything");
  url.searchParams.set("status", "waiting");
  // The span the server counted its waiting cases in, when it said: the
  // number on the line and the list behind the link are then one thing.
  url.searchParams.set("window", isCaseListWindow(window) ? window : "all");
  return url;
}

/**
 * The Cases screen opened on one lane: where each Overview lane card sends
 * its reader, in the window the card counted, so the list and the number
 * describe the same span. `status` narrows it to what is waiting on a person
 * within the lane.
 */
export function caseLaneUrl(
  lane: CaseLane,
  options: { window?: CaseListWindow; status?: "waiting" },
  current: string,
): URL {
  const url = caseUrl(undefined, current);
  url.searchParams.set("lane", lane);
  url.searchParams.set("window", options.window ?? "all");
  if (options.status !== undefined) url.searchParams.set("status", options.status);
  return url;
}

/**
 * The way to the admin audit trail, when the server named its screen
 * (`audit_trail_view`) and this shell offers that screen as a tab. A route
 * the navigation does not offer gets no link: a link that lands back on the
 * Overview is worse than the claim alone.
 */
export function auditTrailOpener<Route extends string>(
  view: string | undefined,
  navigation: readonly HeaderNavigationItem<Route>[],
  navigate: (route: Route) => void,
): (() => void) | undefined {
  const offered = view === undefined ? undefined : navigation.find((item) => item.route === view);
  return offered === undefined ? undefined : () => navigate(offered.route);
}

/**
 * Which of the Overview's agent and token panels an Enterprise shell offers.
 *
 * The same availability rule as the nav: a source the host reports as
 * `not_configured` earns no tab, and on the lanes Overview no panel either.
 * An absent capability keeps the panel, as before.
 */
export function machinePanelsFor(bootstrap: DashboardBootstrap | undefined): MachinePanels | undefined {
  if (bootstrap === undefined) return undefined;
  const configured = (id: string) =>
    bootstrap.capabilities.find((capability) => capability.id === id)?.availability !== "not_configured";
  return {
    agents: configured("community.agent_discovery"),
    tokens: configured("community.token_intelligence"),
  };
}

function resourceData<T>(resource: DashboardResource<T>): T | undefined {
  return resource.state === "ready" || resource.state === "stale" ? resource.data : undefined;
}

function bootstrapLoadStatus(resource: DashboardResource<DashboardBootstrap>): BootstrapLoadStatus {
  if (resource.state === "loading" || resource.state === "idle") return "loading";
  if (resource.state === "ready") return "ready";
  if (resource.state === "unavailable") return "unavailable";
  return "error";
}

/** A Home entry's selection, carried to the Activity route by `activityUrl`. */
type ActivityLink = { id?: string; session?: string; verdict?: string; action?: string };

export function App({
  extraScreens = [],
  onMeta,
  communityScreens,
}: {
  extraScreens?: readonly ScreenModule[];
  /** The Community edition's screens; see `CommunityShell`. The paid shell never passes it. */
  communityScreens?: CommunityShell;
  /**
   * Called with each successful `guard/meta` reading, so a sibling of the shell
   * can use a fact the shell has already fetched.
   *
   * It exists because the tour renders outside this component and needs to know
   * whether this host runs Active Defence. Fetching that itself cost a SECOND
   * request for the same fact, and a second request is not free: `guard/meta` is
   * polled, and a consumer that counts the sequence -- as the posture journey
   * does, failing the second reading to prove a stale claim gets withdrawn --
   * silently had its 503 answered into the wrong caller. The dashboard read the
   * same endpoint twice and the two readers disagreed about which answer was
   * theirs.
   */
  onMeta?: (meta: DashboardMeta) => void;
} = {}) {
  const contributed = contributedScreens(extraScreens);
  // The popstate listener is registered once and must not resubscribe when a
  // caller passes a fresh array literal on every render.
  const contributedRef = useRef(contributed);
  // Handles to the two posture fetchers, so "Check now" can force the answer
  // instead of the operator waiting out a poll they cannot see the length of.
  const postureRefreshRef = useRef<{ bootstrap?: () => Promise<void>; posture?: () => Promise<void> }>({});
  const refreshPostureNow = async () => {
    await Promise.all([
      postureRefreshRef.current.bootstrap?.(),
      postureRefreshRef.current.posture?.(),
    ]);
  };
  contributedRef.current = contributed;

  const [route, setRoute] = useState<ShellRoute>(() => routeFromLocation(extraScreens));
  // Held in a ref so a caller passing a fresh closure on every render cannot
  // restart the poll, the same reason `contributed` is held above.
  const onMetaRef = useRef(onMeta);
  onMetaRef.current = onMeta;
  const [meta, setMeta] = useState<DashboardMeta>();
  const [metaStatus, setMetaStatus] = useState<MetaStatus>("loading");
  const [bootstrapResource, setBootstrapResource] = useState<DashboardResource<DashboardBootstrap>>({ state: "loading" });
  const [postureResource, setPostureResource] = useState<DashboardResource<DashboardPosture>>({ state: "idle" });
  const [agentsResource, setAgentsResource] = useState<DashboardResource<AgentInventory>>({ state: "idle" });
  const [tokensResource, setTokensResource] = useState<DashboardResource<TokenIntelligenceContract>>({ state: "idle" });
  const [consumerEvaluatedAt, setConsumerEvaluatedAt] = useState(() => new Date().toISOString());

  const bootstrap = resourceData(bootstrapResource);
  const enterpriseConfirmed = bootstrap?.edition === "enterprise";
  const enterpriseAuthorized = enterpriseConfirmed
    && bootstrapResource.state === "ready"
    && bootstrap.session.authenticated === true;
  const enterpriseCapabilities = bootstrap?.capabilities.filter((capability) => capability.tier === "enterprise_core") ?? [];
  const agentDiscovery = bootstrap?.capabilities.find((capability) => capability.id === "community.agent_discovery");
  const tokenIntelligence = bootstrap?.capabilities.find((capability) => capability.id === "community.token_intelligence");

  useEffect(() => {
    if (!enterpriseConfirmed) return;
    const tick = () => setConsumerEvaluatedAt(new Date().toISOString());
    tick();
    const timer = setInterval(tick, 1_000);
    return () => clearInterval(timer);
  }, [enterpriseConfirmed]);

  useEffect(() => {
    if (enterpriseConfirmed) return;
    let active = true;
    // A chain, not an interval: the next reading is asked for exactly
    // `META_POLL_MS` after the previous one settles, so there is one request
    // per interval by construction and never two in flight (`pollChain`).
    const stop = pollChain(async () => {
      try {
        const next = await fetchMeta();
        if (!active) return;
        setMeta(next);
        setMetaStatus("ready");
        // Published rather than re-fetched by the caller. See `onMeta`.
        onMetaRef.current?.(next);
      } catch {
        if (active) setMetaStatus("error");
      }
    }, META_POLL_MS);
    return () => {
      active = false;
      stop();
    };
  }, [enterpriseConfirmed]);

  useEffect(() => {
    let active = true;
    let inFlight = false;
    let controller: AbortController | undefined;
    const load = async () => {
      if (inFlight) return;
      inFlight = true;
      controller = new AbortController();
      try {
        const result = await dashboardV1Client.getBootstrap(controller.signal);
        if (active) setBootstrapResource((previous) => retainDashboardResource(previous, result));
      } catch {
        // Navigation/unmount aborts do not create a producer state.
      } finally {
        inFlight = false;
      }
    };
    void load();
    postureRefreshRef.current.bootstrap = load;
    const timer = setInterval(() => void load(), POSTURE_REFRESH_MS);
    return () => {
      active = false;
      controller?.abort("dashboard-unmount");
      clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    if (!enterpriseAuthorized || enterpriseCapabilities.length === 0) {
      setPostureResource({ state: "idle" });
      return;
    }
    let active = true;
    let inFlight = false;
    let controller: AbortController | undefined;
    setPostureResource({ state: "loading" });
    const load = async () => {
      if (inFlight) return;
      inFlight = true;
      controller = new AbortController();
      try {
        const result = await dashboardV1Client.getPosture(controller.signal);
        if (active) setPostureResource((previous) => retainDashboardResource(previous, result));
      } catch {
        // An abort is scoped to the previous shell/navigation lifecycle.
      } finally {
        inFlight = false;
      }
    };
    void load();
    postureRefreshRef.current.posture = load;
    const timer = setInterval(() => void load(), POSTURE_REFRESH_MS);
    return () => {
      active = false;
      controller?.abort("posture-disabled");
      clearInterval(timer);
    };
  }, [enterpriseAuthorized, enterpriseCapabilities.length]);

  useEffect(() => {
    if (!enterpriseAuthorized || agentDiscovery === undefined) {
      setAgentsResource({ state: "idle" });
      return;
    }
    let active = true;
    let inFlight = false;
    let controller: AbortController | undefined;
    setAgentsResource({ state: "loading" });
    const load = async () => {
      if (inFlight) return;
      inFlight = true;
      controller = new AbortController();
      try {
        const result = await dashboardV1Client.getAgents(controller.signal);
        if (active) setAgentsResource((previous) => retainDashboardResource(previous, result));
      } catch {
        // An aborted agent request does not synthesize an empty inventory.
      } finally {
        inFlight = false;
      }
    };
    void load();
    const timer = setInterval(() => void load(), 5_000);
    return () => {
      active = false;
      controller?.abort("agent-inventory-disabled");
      clearInterval(timer);
    };
  }, [agentDiscovery, enterpriseAuthorized]);

  useEffect(() => {
    if (!enterpriseAuthorized || tokenIntelligence === undefined) {
      setTokensResource({ state: "idle" });
      return;
    }
    let active = true;
    let inFlight = false;
    let controller: AbortController | undefined;
    setTokensResource({ state: "loading" });
    const load = async () => {
      if (inFlight) return;
      inFlight = true;
      controller = new AbortController();
      try {
        const result = await dashboardV1Client.getTokenIntelligence(controller.signal);
        if (active) setTokensResource((previous) => retainDashboardResource(previous, result));
      } catch {
        // An aborted token request does not synthesize zero usage.
      } finally {
        inFlight = false;
      }
    };
    void load();
    const timer = setInterval(() => void load(), 60_000);
    return () => {
      active = false;
      controller?.abort("token-intelligence-disabled");
      clearInterval(timer);
    };
  }, [enterpriseAuthorized, tokenIntelligence]);

  const freshMeta = metaStatus === "ready" ? meta : undefined;
  const edition = resolveDashboardEdition(
    bootstrap,
    bootstrapLoadStatus(bootstrapResource),
    meta?.edition,
    metaStatus,
  );
  const editionLabel = edition === "enterprise" ? "Enterprise" : edition === "community" ? "Community" : "Dashboard";
  const version = bootstrap?.product_version ?? (edition === "community" ? meta?.version : undefined);
  const community = edition === "community" ? communityScreens : undefined;
  const navigation = deriveShellNavigation(bootstrap, edition, contributed, community?.screens);
  // The address's query string, kept in state so a Community screen re-reads
  // its own parameters when they change without the route changing.
  const [search, setSearch] = useState(() => window.location.search);

  useEffect(() => {
    if (shouldResetToOverview(route, navigation, contributedRef.current)) setRoute("overview");
  }, [navigation, route]);

  useEffect(() => {
    const restore = () => {
      setRoute(routeFromLocation(contributedRef.current));
      setSearch(window.location.search);
    };
    window.addEventListener("popstate", restore);
    return () => window.removeEventListener("popstate", restore);
  }, []);

  // An address written for another edition (`?view=cases&case=...`),
  // rewritten once the edition is known, in place, so the back button does
  // not return to an address this shell cannot open.
  const alias = community?.alias;
  useEffect(() => {
    if (alias === undefined) return;
    const rewritten = alias(window.location.search);
    if (rewritten === undefined || rewritten === window.location.search) return;
    const url = new URL(window.location.href);
    url.search = rewritten;
    window.history.replaceState({}, "", url);
    setRoute(routeFromLocation(contributedRef.current));
    setSearch(window.location.search);
  }, [alias]);

  useEffect(() => {
    document.title = `InnerWarden ${editionLabel}: Agent Security`;
  }, [editionLabel]);

  const navigate = (next: ShellRoute, params?: Readonly<Record<string, string>>) => {
    const url = new URL(window.location.href);
    if (next === "overview") url.searchParams.delete("view");
    else url.searchParams.set("view", next);
    for (const key of SCREEN_PARAMS) url.searchParams.delete(key);
    for (const [key, value] of Object.entries(params ?? {})) {
      if (value.length > 0 && value.length <= 256) url.searchParams.set(key, value);
    }
    window.history.pushState({}, "", url);
    setSearch(url.search);
    setRoute(next);
  };
  const openActivity = (target?: ActivityLink) => {
    window.history.pushState({}, "", activityUrl(target, window.location.href));
    setSearch(window.location.search);
    setRoute("activity");
  };
  const openCase = (caseId?: string, lane?: CaseLane, span?: CaseListWindow) => {
    window.history.pushState({}, "", caseUrl(caseId, window.location.href, lane, span));
    setRoute("cases");
  };
  const openLane = (lane: CaseLane, options: LaneOpenOptions) => {
    window.history.pushState({}, "", caseLaneUrl(lane, options, window.location.href));
    setRoute("cases");
  };
  const openQueue = (options?: QueueOpenOptions) => {
    window.history.pushState({}, "", caseQueueUrl(window.location.href, options?.window));
    setRoute("cases");
  };
  // Only a shell that actually mounts a Cases screen may hand out case links;
  // without one, `?view=cases` resolves straight back to Overview.
  const casesAvailable = contributed.some((screen) => screen.route === "cases");
  const openAuditTrail = auditTrailOpener(bootstrap?.audit_trail_view, navigation, navigate);

  return (
    <div className="min-h-screen bg-slate-50 text-slate-950">
      <a
        href="#main-content"
        className="sr-only z-50 rounded-md bg-white px-3 py-2 font-semibold text-slate-950 shadow focus:not-sr-only focus:fixed focus:left-3 focus:top-3"
      >
        Skip to content
      </a>
      <Header
        editionLabel={editionLabel}
        version={version}
        navigation={navigation}
        activeRoute={route}
        homeRoute="overview"
        onNavigate={navigate}
        account={edition === "enterprise" ? signedInAccount(bootstrapResource) : undefined}
        status={edition === "community"
          // `data-meta-status` says which reading the status is drawn from:
          // a test waits on it, never on a default the page shows before
          // `guard/meta` has answered.
          ? <span data-meta-status={metaStatus} className="flex min-w-0 items-center gap-2">{community?.status(freshMeta ?? meta, metaStatus)}</span>
          : edition === "enterprise"
            ? <EnterpriseSessionStatus resource={bootstrapResource} />
            : <BootstrapContractStatus resource={bootstrapResource} />}
      />

      <main id="main-content" className="mx-auto max-w-6xl px-4 py-6 sm:px-6 sm:py-8 lg:px-8">
        {edition === "enterprise" && bootstrap && enterpriseAuthorized ? (
          <EnterpriseRoute
            route={route}
            bootstrap={bootstrap}
            postureResource={postureResource}
            agentsResource={agentsResource}
            tokensResource={tokensResource}
            enterpriseDeclared={enterpriseCapabilities.length > 0}
            agentDiscovery={agentDiscovery}
            tokenIntelligence={tokenIntelligence}
            meta={freshMeta}
            onOpenActivity={openActivity}
            onOpenCase={casesAvailable ? openCase : undefined}
            onOpenQueue={casesAvailable ? openQueue : undefined}
            onOpenLane={casesAvailable ? openLane : undefined}
            evaluatedAt={consumerEvaluatedAt}
            extraScreens={contributed}
            onCheckNow={refreshPostureNow}
            onOpenAuditTrail={openAuditTrail}
          />
        ) : edition === "enterprise" && bootstrap ? (
          <DashboardContractState resource={bootstrapResource} />
        ) : edition === "community" ? (
          <CommunityRoute
            route={route}
            shell={community}
            context={{ meta: freshMeta, metaStatus, bootstrap, navigate, search }}
            onOpenActivity={openActivity}
          />
        ) : (
          <DashboardContractState resource={bootstrapResource} />
        )}
      </main>
    </div>
  );
}

function EnterpriseRoute({
  route,
  bootstrap,
  postureResource,
  agentsResource,
  tokensResource,
  enterpriseDeclared,
  agentDiscovery,
  tokenIntelligence,
  meta,
  onOpenActivity,
  onOpenCase,
  onOpenQueue,
  onOpenLane,
  evaluatedAt,
  extraScreens,
  onCheckNow,
  onOpenAuditTrail,
}: {
  route: ShellRoute;
  bootstrap: DashboardBootstrap;
  postureResource: DashboardResource<DashboardPosture>;
  agentsResource: DashboardResource<AgentInventory>;
  tokensResource: DashboardResource<TokenIntelligenceContract>;
  enterpriseDeclared: boolean;
  agentDiscovery?: DashboardBootstrap["capabilities"][number];
  tokenIntelligence?: DashboardBootstrap["capabilities"][number];
  meta?: DashboardMeta;
  onOpenActivity: (target?: ActivityLink) => void;
  onOpenCase?: (caseId?: string, lane?: CaseLane, window?: CaseListWindow) => void;
  /** Opens the Cases screen on the waiting queue; see `caseQueueUrl`. */
  onOpenQueue?: (options?: QueueOpenOptions) => void;
  /** Opens the Cases screen on one lane; see `caseLaneUrl`. */
  onOpenLane?: (lane: CaseLane, options: LaneOpenOptions) => void;
  evaluatedAt: string;
  extraScreens: readonly ScreenModule[];
  /** Force a posture re-read on demand; see `POSTURE_REFRESH_MS`. */
  onCheckNow?: () => void | Promise<void>;
  /** Opens the admin audit trail; see `auditTrailOpener`. */
  onOpenAuditTrail?: () => void;
}) {
  const contributed = extraScreens.find((screen) => screen.route === route);
  if (contributed !== undefined) return <>{contributed.render({ bootstrap, evaluatedAt })}</>;

  if (route === "agents") {
    return (
      <CapabilityBoundary
        adapterLabel="Agent inventory"
        declared={agentDiscovery !== undefined}
        capability={agentDiscovery}
        resource={agentsResource}
      >
        {(inventory, stale) => <Agents inventory={inventory} stale={stale} />}
      </CapabilityBoundary>
    );
  }
  if (route === "tokens") {
    return (
      <CapabilityBoundary
        adapterLabel="Token intelligence"
        declared={tokenIntelligence !== undefined}
        capability={tokenIntelligence}
        resource={tokensResource}
      >
        {(report, stale) => <TokenIntelligence report={report} stale={stale} />}
      </CapabilityBoundary>
    );
  }

  if (route === "posture") {
    return (
      <CapabilityBoundary
        adapterLabel="Enterprise posture"
        declared={enterpriseDeclared}
        capability={bootstrap.capabilities.find((capability) => capability.tier === "enterprise_core")}
        resource={postureResource}
      >
        {(posture, stale) => (
          <Posture bootstrap={bootstrap} posture={posture} current={!stale} evaluatedAt={evaluatedAt} onCheckNow={onCheckNow} />
        )}
      </CapabilityBoundary>
    );
  }

  return (
    <Home
      meta={meta}
      onOpenActivity={onOpenActivity}
      onOpenCase={onOpenCase}
      onOpenQueue={onOpenQueue}
      onOpenLane={onOpenLane}
      machinePanels={machinePanelsFor(bootstrap)}
      edition="enterprise"
      dashboardAccess={bootstrap.dashboard_access}
      onOpenAuditTrail={onOpenAuditTrail}
    />
  );
}

/**
 * A calm status keeps its symbol and says its words to screen readers only
 * below 400 px, where the words cost the header a row. A status that asks
 * for something keeps its words at every width.
 */
const NARROW_LABEL = "max-[399px]:sr-only";

/**
 * The session badge names who is signed in. A change on the paid dashboard
 * is "recorded under your name", and the page said so without ever showing
 * the name. A name that is not a short plain one (empty, very long, or
 * carrying a control or format character, a bidi override among them) is
 * not printed; the badge then says "Signed in".
 */
export function signedInLabel(actorId: string | null | undefined): string {
  const name = typeof actorId === "string" ? actorId.trim() : "";
  if (name === "" || name.length > 64 || hasControlCharacters(name)) return "Signed in";
  return `Signed in as ${name}`;
}

/** Who is signed in, for the header's small-screen menu; nothing when no one is. */
export function signedInAccount(resource: DashboardResource<DashboardBootstrap>): string | undefined {
  return resource.state === "ready" && resource.data.session.authenticated
    ? signedInLabel(resource.data.session.actor_id)
    : undefined;
}

function EnterpriseSessionStatus({ resource }: { resource: DashboardResource<DashboardBootstrap> }) {
  const account = signedInAccount(resource);
  if (account !== undefined) {
    // A name may be one long token (a 64-character id): it breaks anywhere
    // rather than push the header sideways. Below 400 px the words are for
    // screen readers only, so the check carries them in its title, and the
    // menu says them in full (`Header`'s `account`).
    return (
      <StatusBadge
        status="available"
        label={account}
        title={account}
        className="min-w-0"
        labelClassName={`${NARROW_LABEL} [overflow-wrap:anywhere]`}
      />
    );
  }
  if (resource.state === "ready") return <StatusBadge status="unavailable" label="Authentication required" />;
  if (resource.state === "stale") {
    const label = resource.problem.httpStatus === 401 ? "Authentication required" : "Session status stale";
    return <StatusBadge status="stale" label={label} />;
  }
  if (resource.state === "authentication_required") return <StatusBadge status="unavailable" label="Authentication required" />;
  if (resource.state === "forbidden") return <StatusBadge status="unavailable" label="Session scope forbidden" />;
  return <StatusBadge status={resource.state === "loading" || resource.state === "idle" ? "loading" : "unknown"} label="Session status unknown" />;
}

function BootstrapContractStatus({ resource }: { resource: DashboardResource<DashboardBootstrap> }) {
  if (resource.state === "authentication_required") return <StatusBadge status="unavailable" label="Sign in required" />;
  if (resource.state === "forbidden") return <StatusBadge status="unavailable" label="Not allowed for this session" />;
  if (resource.state === "error") return <StatusBadge status="failed" label="Unreadable reply" />;
  if (resource.state === "unavailable" || resource.state === "unsupported") return <StatusBadge status={resource.state} label="Host not answering" />;
  return <StatusBadge status="loading" label="Connecting" />;
}

/**
 * The very first thing a user can see, so it is written for them.
 *
 * It used to say the dashboard was "resolving a validated dashboard v1
 * bootstrap before mounting an edition-specific surface". Every word of that is
 * accurate and none of it belongs on a screen whose only job, at that instant,
 * is to say whether the thing is working.
 */
function DashboardContractState({ resource }: { resource: DashboardResource<DashboardBootstrap> }) {
  const loading = resource.state === "loading" || resource.state === "idle";
  const auth = resource.state === "authentication_required";
  return (
    <section className="rounded-2xl border border-slate-200 bg-white px-6 py-14 text-center shadow-sm" role={auth ? "alert" : "status"}>
      <div className="flex justify-center"><StatusBadge status={loading ? "loading" : auth ? "unavailable" : "failed"} /></div>
      <h1 className="mt-4 text-xl font-semibold text-slate-950">
        {loading ? "Connecting to InnerWarden on this machine" : auth ? "Sign in to continue" : "InnerWarden is not answering"}
      </h1>
      <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-slate-600">
        {loading
          ? "Asking the local process which edition is running before showing anything."
          : auth
            ? "Sign in through Active Defence on this host. Nothing is shown until that succeeds."
            : "The local process did not answer, or answered with something this dashboard cannot read. Check that InnerWarden is running, then reload. Nothing about your protection is assumed in the meantime."}
      </p>
    </section>
  );
}

/**
 * The Community routes: the entry point's screen for the route, or the kit
 * Overview when the shell was handed no screens (which only a test does).
 */
function CommunityRoute({
  route,
  shell,
  context,
  onOpenActivity,
}: {
  route: ShellRoute;
  shell?: CommunityShell;
  context: CommunityScreenContext;
  onOpenActivity: (target?: ActivityLink) => void;
}) {
  const screen = shell?.screens.find((candidate) => candidate.route === route)
    ?? shell?.screens.find((candidate) => candidate.route === "overview");
  if (screen !== undefined) return <>{screen.render(context)}</>;
  return (
    <Home
      meta={context.meta}
      onOpenActivity={onOpenActivity}
      edition="community"
      dashboardAccess={context.bootstrap?.dashboard_access}
    />
  );
}
