import { useEffect, useRef, useState, type ReactNode } from "react";
import { fetchMeta, type DashboardMeta, type GuardrailMode } from "./api";
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
import { normaliseMode } from "./presentation";
import { Activity, type ActivityTarget } from "./screens/Activity";
import { Home } from "./screens/Home";
import { Agents } from "./screens/Agents";
import { Posture } from "./screens/Posture";
import { TokenIntelligence } from "./screens/TokenIntelligence";

/**
 * The routes this repository builds. A contributed screen widens the type but
 * can never take one of these names -- see `contributedScreens`.
 */
export type BaseShellRoute = "overview" | "activity" | "posture" | "agents" | "tokens";
export type ShellRoute = BaseShellRoute | (string & {});

const BASE_ROUTES: readonly string[] = ["overview", "activity", "posture", "agents", "tokens"];

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

/**
 * Contributed screens that are safe to mount: a module may not shadow a route
 * the shell itself owns, so a bad or stale contribution cannot capture
 * Overview, Posture, Agents or Tokens.
 */
function contributedScreens(extraScreens: readonly ScreenModule[]): ScreenModule[] {
  return extraScreens.filter((screen) => !BASE_ROUTES.includes(screen.route));
}

type BootstrapLoadStatus = "loading" | "ready" | "unavailable" | "error";
type MetaStatus = "loading" | "ready" | "error";

export function deriveShellNavigation(
  bootstrap: DashboardBootstrap | undefined,
  edition: DashboardBootstrap["edition"] | undefined,
  extraScreens: readonly ScreenModule[] = [],
): HeaderNavigationItem<ShellRoute>[] {
  if (edition === "community") {
    // Community navigation is a preserved CJC surface and never depends on an
    // Enterprise producer or entitlement record.
    return [
      { route: "overview", label: "Overview" },
      { route: "activity", label: "Activity" },
    ];
  }
  if (edition !== "enterprise" || bootstrap === undefined) return [];

  const items: HeaderNavigationItem<ShellRoute>[] = [{ route: "overview", label: "Overview" }];
  if (bootstrap.capabilities.some((capability) => capability.tier === "enterprise_core")) {
    items.push({ route: "posture", label: "Posture" });
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

function resourceData<T>(resource: DashboardResource<T>): T | undefined {
  return resource.state === "ready" || resource.state === "stale" ? resource.data : undefined;
}

function bootstrapLoadStatus(resource: DashboardResource<DashboardBootstrap>): BootstrapLoadStatus {
  if (resource.state === "loading" || resource.state === "idle") return "loading";
  if (resource.state === "ready") return "ready";
  if (resource.state === "unavailable") return "unavailable";
  return "error";
}

export function App({ extraScreens = [] }: { extraScreens?: readonly ScreenModule[] } = {}) {
  const contributed = contributedScreens(extraScreens);
  // The popstate listener is registered once and must not resubscribe when a
  // caller passes a fresh array literal on every render.
  const contributedRef = useRef(contributed);
  contributedRef.current = contributed;

  const [route, setRoute] = useState<ShellRoute>(() => routeFromLocation(extraScreens));
  const [meta, setMeta] = useState<DashboardMeta>();
  const [metaStatus, setMetaStatus] = useState<MetaStatus>("loading");
  const [bootstrapResource, setBootstrapResource] = useState<DashboardResource<DashboardBootstrap>>({ state: "loading" });
  const [postureResource, setPostureResource] = useState<DashboardResource<DashboardPosture>>({ state: "idle" });
  const [agentsResource, setAgentsResource] = useState<DashboardResource<AgentInventory>>({ state: "idle" });
  const [tokensResource, setTokensResource] = useState<DashboardResource<TokenIntelligenceContract>>({ state: "idle" });
  const [activityTarget, setActivityTarget] = useState<ActivityTarget>();
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
    let inFlight = false;
    const load = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        const next = await fetchMeta();
        if (!active) return;
        setMeta(next);
        setMetaStatus("ready");
      } catch {
        if (active) setMetaStatus("error");
      } finally {
        inFlight = false;
      }
    };
    void load();
    const timer = setInterval(() => void load(), 5_000);
    return () => {
      active = false;
      clearInterval(timer);
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
    const timer = setInterval(() => void load(), 5_000);
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
    const timer = setInterval(() => void load(), 5_000);
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
  const mode = normaliseMode(freshMeta);
  const edition = resolveDashboardEdition(
    bootstrap,
    bootstrapLoadStatus(bootstrapResource),
    meta?.edition,
    metaStatus,
  );
  const editionLabel = edition === "enterprise" ? "Enterprise" : edition === "community" ? "Community" : "Dashboard";
  const version = bootstrap?.product_version ?? (edition === "community" ? meta?.version : undefined);
  const navigation = deriveShellNavigation(bootstrap, edition, contributed);

  useEffect(() => {
    if (shouldResetToOverview(route, navigation, contributedRef.current)) setRoute("overview");
  }, [navigation, route]);

  useEffect(() => {
    const restore = () => setRoute(routeFromLocation(contributedRef.current));
    window.addEventListener("popstate", restore);
    return () => window.removeEventListener("popstate", restore);
  }, []);

  useEffect(() => {
    document.title = `InnerWarden ${editionLabel}: Agent Security`;
  }, [editionLabel]);

  const navigate = (next: ShellRoute) => {
    if (next !== "activity") setActivityTarget(undefined);
    const url = new URL(window.location.href);
    if (next === "overview") url.searchParams.delete("view");
    else url.searchParams.set("view", next);
    for (const key of ["q", "outcome", "severity", "mode", "authority", "capability", "scope_kind", "scope", "window", "cursor", "case"]) url.searchParams.delete(key);
    window.history.pushState({}, "", url);
    setRoute(next);
  };
  const openActivity = (target?: Omit<ActivityTarget, "requestId">) => {
    setActivityTarget(target ? { ...target, requestId: Date.now() } : undefined);
    const url = new URL(window.location.href);
    url.searchParams.set("view", "activity");
    window.history.pushState({}, "", url);
    setRoute("activity");
  };

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
        status={edition === "community"
          ? <><ModePill mode={mode} /><ExposureStatus status={metaStatus} exposed={meta?.exposed} /></>
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
            evaluatedAt={consumerEvaluatedAt}
            extraScreens={contributed}
          />
        ) : edition === "enterprise" && bootstrap ? (
          <DashboardContractState resource={bootstrapResource} />
        ) : edition === "community" ? (
          route === "activity" ? <Activity initialTarget={activityTarget} /> : <Home meta={freshMeta} onOpenActivity={openActivity} edition="community" />
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
  evaluatedAt,
  extraScreens,
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
  onOpenActivity: (target?: Omit<ActivityTarget, "requestId">) => void;
  evaluatedAt: string;
  extraScreens: readonly ScreenModule[];
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
        {(posture, stale) => <Posture bootstrap={bootstrap} posture={posture} current={!stale} evaluatedAt={evaluatedAt} />}
      </CapabilityBoundary>
    );
  }

  return <Home meta={meta} onOpenActivity={onOpenActivity} edition="enterprise" />;
}

function EnterpriseSessionStatus({ resource }: { resource: DashboardResource<DashboardBootstrap> }) {
  if (resource.state === "ready" && resource.data.session.authenticated) return <StatusBadge status="available" label="Authenticated" />;
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

function ExposureStatus({ status, exposed }: { status: MetaStatus; exposed?: boolean }) {
  if (status === "loading") return <StatusBadge status="loading" label="Checking exposure" />;
  if (status === "error") {
    const label = exposed === true ? "Exposed · status stale" : exposed === false ? "Last known local" : "Exposure unknown";
    return <StatusBadge status={exposed === true ? "failed" : "stale"} label={label} />;
  }
  if (exposed === true) return <StatusBadge status="failed" label="Exposed · no authentication" />;
  if (exposed === false) return <StatusBadge status="available" label="Local · read-only API" />;
  return <StatusBadge status="unknown" label="Exposure unknown" />;
}

function ModePill({ mode }: { mode: GuardrailMode }) {
  const labels: Record<GuardrailMode, string> = {
    not_configured: "Setup needed",
    monitor: "Monitor configured",
    enforce: "Enforce configured",
    mixed: "Mixed configuration",
    partial: "Partial coverage",
    unknown: "Status unknown",
  };
  const status = mode === "mixed" || mode === "partial" ? "degraded" : mode === "unknown" ? "unknown" : mode === "not_configured" ? "not_configured" : "available";
  return <StatusBadge status={status} label={labels[mode]} className="hidden sm:inline-flex" />;
}
