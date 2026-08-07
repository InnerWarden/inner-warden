import type { ReactNode } from "react";
import type { DashboardResource } from "../api/client";
import type { CapabilityStatus } from "../api/v1";
import { StatusBadge } from "./StatusBadge";

type BoundaryState = DashboardResource<unknown>["state"] | "adapter_absent";

/**
 * Why a screen has no data, in words an operator can act on.
 *
 * Every one of these sentences used to be written from the wire's point of
 * view: adapters, bootstraps, projections, contracts, legacy payloads. That
 * vocabulary describes OUR plumbing, and it reached a user precisely when they
 * were staring at an empty screen wanting to know what to do about it. The
 * honesty each sentence carries is untouched, because it is the whole point:
 * nothing missing is ever reported as zero, healthy, allowed or blocked.
 */
export function capabilityBoundaryMessage(
  state: BoundaryState,
  adapterLabel: string,
  capability?: Pick<CapabilityStatus, "availability" | "support" | "reason_code">,
): { title: string; body: string; status: string } {
  if (state === "adapter_absent") {
    return {
      title: `${adapterLabel} is not part of this installation`,
      body: "This host did not offer this feature, so there is nothing to show. Nothing from another edition is shown in its place.",
      status: "unavailable",
    };
  }
  if (state === "unsupported" || capability?.support === "unsupported" || capability?.availability === "unsupported") {
    return {
      title: `${adapterLabel} is not supported on this host`,
      body: "This machine cannot provide it. That says nothing either way about the protection its other controls give you.",
      status: "unsupported",
    };
  }
  if (state === "authentication_required") {
    return {
      title: "Sign in to see this",
      body: "This data stays behind the Active Defence sign-in. Nothing is loaded until that succeeds.",
      status: "unavailable",
    };
  }
  if (state === "forbidden") {
    return {
      title: `Your session cannot see ${adapterLabel.toLowerCase()}`,
      body: "You are signed in, but this session is not allowed to read it.",
      status: "unavailable",
    };
  }
  if (state === "rate_limited") {
    return {
      title: `${adapterLabel} asked to be left alone for a moment`,
      body: "Too many requests too quickly. Whatever was already on screen is kept rather than replaced with an empty one.",
      status: "degraded",
    };
  }
  if (state === "conflict") {
    return {
      title: `${adapterLabel} is mid change`,
      body: "The host is in a different state than this request expected. Nothing was applied and nothing is being guessed at.",
      status: "degraded",
    };
  }
  if (state === "error") {
    return {
      title: `${adapterLabel} sent something this dashboard cannot read`,
      body: "The reply failed or did not match what this version expects. Nothing older is shown in its place.",
      status: "failed",
    };
  }
  if (state === "unavailable") {
    return {
      title: `${adapterLabel} is unavailable`,
      body: "This host did not answer. What is missing stays unknown; it is never shown as zero or as healthy.",
      status: "unavailable",
    };
  }
  return {
    title: `Loading ${adapterLabel.toLowerCase()}`,
    body: "Waiting for this host to answer.",
    status: "loading",
  };
}

export function CapabilityBoundary<T>({
  adapterLabel,
  declared,
  capability,
  resource,
  children,
}: {
  adapterLabel: string;
  declared: boolean;
  capability?: Pick<CapabilityStatus, "availability" | "support" | "reason_code">;
  resource: DashboardResource<T>;
  children: (data: T, stale: boolean) => ReactNode;
}) {
  if (!declared) {
    return <BoundaryPanel {...capabilityBoundaryMessage("adapter_absent", adapterLabel, capability)} />;
  }
  if (resource.state === "ready") return <>{children(resource.data, false)}</>;
  if (resource.state === "stale") {
    return (
      <div className="space-y-4">
        <div role="status" className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-amber-950">
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div>
              <div className="font-semibold">Showing the last good {adapterLabel.toLowerCase()} snapshot</div>
              <p className="mt-0.5 text-sm">The refresh failed, so this may be out of date. What the host is doing right now is unknown until it answers again.</p>
            </div>
            <StatusBadge status="stale" />
          </div>
        </div>
        {children(resource.data, true)}
      </div>
    );
  }
  return <BoundaryPanel {...capabilityBoundaryMessage(resource.state, adapterLabel, capability)} />;
}

function BoundaryPanel({ title, body, status }: { title: string; body: string; status: string }) {
  const isFailure = status === "failed";
  return (
    <section
      className="rounded-2xl border border-slate-200 bg-white px-6 py-12 text-center shadow-sm"
      role={isFailure ? "alert" : "status"}
      aria-live="polite"
    >
      <div className="flex justify-center"><StatusBadge status={status} /></div>
      <h1 className="mt-4 text-xl font-semibold text-slate-950">{title}</h1>
      <p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-slate-600">{body}</p>
    </section>
  );
}
