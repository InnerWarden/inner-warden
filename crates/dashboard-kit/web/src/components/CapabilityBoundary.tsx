import type { ReactNode } from "react";
import type { DashboardResource } from "../api/client";
import type { CapabilityStatus } from "../api/v1";
import { StatusBadge } from "./StatusBadge";

type BoundaryState = DashboardResource<unknown>["state"] | "adapter_absent";

export function capabilityBoundaryMessage(
  state: BoundaryState,
  adapterLabel: string,
  capability?: Pick<CapabilityStatus, "availability" | "support" | "reason_code">,
): { title: string; body: string; status: string } {
  if (state === "adapter_absent") {
    return {
      title: `${adapterLabel} adapter not declared`,
      body: "The validated bootstrap did not declare this capability. Legacy or Community-labelled data is not substituted.",
      status: "unavailable",
    };
  }
  if (state === "unsupported" || capability?.support === "unsupported" || capability?.availability === "unsupported") {
    return {
      title: `${adapterLabel} is unsupported`,
      body: "This host or adapter does not support the capability. No equivalent protection is implied.",
      status: "unsupported",
    };
  }
  if (state === "authentication_required") {
    return {
      title: "Enterprise authentication required",
      body: "Authenticate through the serving Active Defence boundary before this data is mounted.",
      status: "unavailable",
    };
  }
  if (state === "forbidden") {
    return {
      title: `${adapterLabel} is outside this session scope`,
      body: "The authenticated session is not authorized for this adapter or scope.",
      status: "unavailable",
    };
  }
  if (state === "rate_limited") {
    return {
      title: `${adapterLabel} is temporarily rate limited`,
      body: "The previous validated view is not replaced with an empty or inferred state.",
      status: "degraded",
    };
  }
  if (state === "conflict") {
    return {
      title: `${adapterLabel} has a state conflict`,
      body: "The requested projection conflicts with the current server state or a publication gate. Nothing is inferred or applied.",
      status: "degraded",
    };
  }
  if (state === "error") {
    return {
      title: `${adapterLabel} response could not be validated`,
      body: "The adapter returned an error or an incompatible contract. No legacy payload is used as a fallback.",
      status: "failed",
    };
  }
  if (state === "unavailable") {
    return {
      title: `${adapterLabel} is unavailable`,
      body: "The adapter did not provide a current response. Missing values remain unavailable, not zero or healthy.",
      status: "unavailable",
    };
  }
  return {
    title: `Loading ${adapterLabel.toLowerCase()}`,
    body: "Waiting for a validated same-origin dashboard v1 response.",
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
              <div className="font-semibold">Showing the last validated {adapterLabel.toLowerCase()} snapshot</div>
              <p className="mt-0.5 text-sm">The refresh failed. Current runtime state is unknown until a valid response arrives.</p>
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
