import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import type { CaseSeverity } from "../api/cases";
import type { EffectiveMode, SecurityOutcome } from "../api/v1";

export type CaseWindow = "all" | "1h" | "24h" | "7d" | "30d";
export type CaseScopeKind = "all" | "agent" | "host" | "workload" | "resource";

export type CaseViewState = {
  query: string;
  outcome: SecurityOutcome | "";
  severity: CaseSeverity | "";
  mode: EffectiveMode | "";
  authority: string;
  capability: string;
  scopeKind: CaseScopeKind;
  scopeId: string;
  window: CaseWindow;
  cursor: string | null;
  selectedCase: string | null;
};

export const EMPTY_CASE_VIEW: CaseViewState = {
  query: "",
  outcome: "",
  severity: "",
  mode: "",
  authority: "",
  capability: "",
  scopeKind: "all",
  scopeId: "",
  window: "24h",
  cursor: null,
  selectedCase: null,
};

const outcomes = ["observed_only", "allowed", "blocked_before_execution", "would_block", "contained", "failed", "reverted", "not_observed", "unknown"] as const;
const severities = ["critical", "high", "medium", "low", "informational", "unknown"] as const;
// `mixed` is gone for the same reason `resource` is: the mode filter matches
// against `event.mode` on the case timeline, and no projector ever puts
// `EffectiveMode::Mixed` on an event. It exists as a label for capability
// rollups, where several capabilities really can disagree, but a single event
// happened in exactly one mode. Selecting it could only ever return zero.
const modes = ["disabled", "learning", "observe", "rehearse", "enforce", "unknown"] as const;
// Every kind here must be one the host can actually attach to a case, or the
// operator gets an option that returns nothing for ever and reads as "no
// results" rather than "no such thing". `resource` was exactly that: the
// backing `ScopeKind::Resource` is declared and matched for a label, but is
// never constructed anywhere in the agent, so selecting it could only ever
// return zero. `session` is absent on purpose, not by oversight: the host folds
// session scopes into the `agent` filter, so a separate entry would fall back
// to page-only client filtering and find LESS than `agent` already does.
const scopeKinds = ["all", "agent", "host", "workload"] as const;
const windows = ["all", "1h", "24h", "7d", "30d"] as const;

function selected<const T extends readonly string[]>(value: string | null, allowed: T, fallback: T[number] | ""): T[number] | "" {
  return value !== null && allowed.includes(value) ? value as T[number] : fallback;
}

function bounded(parameter: URLSearchParams, name: string, maximum: number): string {
  const value = parameter.get(name) ?? "";
  return value.length <= maximum ? value : "";
}

export function readCaseViewState(search = window.location.search): CaseViewState {
  const parameters = new URLSearchParams(search);
  return {
    query: bounded(parameters, "q", 256),
    outcome: selected(parameters.get("outcome"), outcomes, ""),
    severity: selected(parameters.get("severity"), severities, ""),
    mode: selected(parameters.get("mode"), modes, ""),
    authority: bounded(parameters, "authority", 256),
    capability: bounded(parameters, "capability", 256),
    scopeKind: selected(parameters.get("scope_kind"), scopeKinds, "all") as CaseScopeKind,
    scopeId: bounded(parameters, "scope", 256),
    window: selected(parameters.get("window"), windows, "24h") as CaseWindow,
    cursor: bounded(parameters, "cursor", 2_048) || null,
    selectedCase: bounded(parameters, "case", 256) || null,
  };
}

export function caseViewUrl(state: CaseViewState, current = window.location.href): URL {
  const url = new URL(current);
  url.searchParams.set("view", "cases");
  const values: [string, string, string][] = [
    ["q", state.query, ""], ["outcome", state.outcome, ""], ["severity", state.severity, ""],
    ["mode", state.mode, ""], ["authority", state.authority, ""], ["capability", state.capability, ""],
    ["scope_kind", state.scopeKind, "all"], ["scope", state.scopeId, ""], ["window", state.window, "24h"],
    ["cursor", state.cursor ?? "", ""], ["case", state.selectedCase ?? "", ""],
  ];
  for (const [name, value, defaultValue] of values) {
    if (value === defaultValue) url.searchParams.delete(name);
    else url.searchParams.set(name, value);
  }
  return url;
}

export function writeCaseViewState(state: CaseViewState, mode: "push" | "replace" = "push"): void {
  const url = caseViewUrl(state);
  window.history[mode === "push" ? "pushState" : "replaceState"]({}, "", url);
}

export function CaseFilters({ value, disabled = false, onApply, onClear }: {
  value: CaseViewState;
  disabled?: boolean;
  onApply: (next: CaseViewState) => void;
  onClear: () => void;
}) {
  const [draft, setDraft] = useState(value);
  useEffect(() => setDraft(value), [value]);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    onApply({ ...draft, query: draft.query.trim(), authority: draft.authority.trim(), capability: draft.capability.trim(), scopeId: draft.scopeId.trim(), cursor: null });
  };

  return (
    <form onSubmit={submit} className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm" aria-label="Case filters">
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <label className="text-xs font-semibold text-slate-700 xl:col-span-2">
          Search cases
          <input
            type="search"
            value={draft.query}
            maxLength={256}
            disabled={disabled}
            onChange={(event) => setDraft((current) => ({ ...current, query: event.target.value }))}
            placeholder="Case title or subject"
            className="mt-1 block w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-normal text-slate-950 disabled:bg-slate-100"
          />
        </label>
        <FilterSelect label="Outcome" value={draft.outcome} disabled={disabled} onChange={(outcome) => setDraft((current) => ({ ...current, outcome: outcome as CaseViewState["outcome"] }))}>
          <option value="">All reported outcomes</option>
          {outcomes.map((outcome) => <option key={outcome} value={outcome}>{outcome.replaceAll("_", " ")}</option>)}
        </FilterSelect>
        <FilterSelect label="Severity" value={draft.severity} disabled={disabled} onChange={(severity) => setDraft((current) => ({ ...current, severity: severity as CaseViewState["severity"] }))}>
          <option value="">All severities</option>
          {severities.map((severity) => <option key={severity} value={severity}>{severity}</option>)}
        </FilterSelect>
        <FilterSelect label="Mode" value={draft.mode} disabled={disabled} onChange={(mode) => setDraft((current) => ({ ...current, mode: mode as CaseViewState["mode"] }))}>
          <option value="">All modes</option>
          {modes.map((mode) => <option key={mode} value={mode}>{mode}</option>)}
        </FilterSelect>
        <label className="text-xs font-semibold text-slate-700">
          Decision authority
          {/* Was a free-text box hinting "rule, model, operator". None of those
              three is a value this filter accepts: it compares against the
              authority recorded on a timeline event, which is `host-detector`,
              `action-executor`, `runtime-verifier`, `obvious-gate` and the
              like. Typing what the placeholder suggested returned zero cases
              and taught the operator there were none of that kind.

              A closed list cannot mislead, and the values are the producers
              themselves, named as a person would say them.

              Closing the list was not enough on its own. The first version of
              it offered six values chosen by hand, and it was still missing the
              two most common producers on a live host, `host-sensor` and
              `agent-guard`: an operator asking "what did the guardrail decide?"
              got nothing back. These are now the literals the host really
              writes onto a timeline event, grouped by the question being asked,
              and `case_filter_authorities_are_the_ones_events_really_carry` in
              the agent fails if a producer starts writing one that is not
              here. */}
          <select value={draft.authority} disabled={disabled} onChange={(event) => setDraft((current) => ({ ...current, authority: event.target.value }))} className="mt-1 block w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-normal">
            <option value="">Anything that decided</option>
            <optgroup label="Saw it">
              <option value="host-sensor">Host telemetry</option>
              <option value="host-detector">Host detector</option>
              <option value="agent-guard">The agent guardrail</option>
              <option value="agent-guard-analysis">Agent guardrail analysis</option>
              <option value="community-agent-boundary">Community agent boundary</option>
            </optgroup>
            <optgroup label="Decided it">
              <option value="obvious-gate">Automatic rule</option>
              <option value="community-policy">Community policy</option>
              <option value="operator">An operator</option>
            </optgroup>
            <optgroup label="Acted on it">
              <option value="action-executor">The action executor</option>
              <option value="runtime-verifier">The runtime verifier</option>
              <option value="response-lifecycle">Response lifecycle</option>
            </optgroup>
          </select>
        </label>
        <label className="text-xs font-semibold text-slate-700">
          Capability
          {/* Same trap, worse: the backend match on this field is a CLOSED set
              of four (`community`/`agent_boundary`, `host`/`host_visibility`,
              `response`/`response_control`, or an exact evidence-source id),
              and the box invited "execution, DNS". Neither ever matched. */}
          <select value={draft.capability} disabled={disabled} onChange={(event) => setDraft((current) => ({ ...current, capability: event.target.value }))} className="mt-1 block w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-normal">
            <option value="">Anything that saw it</option>
            <option value="agent_boundary">The agent guardrail</option>
            <option value="host_visibility">Host telemetry</option>
            <option value="response_control">Response controls</option>
          </select>
        </label>
        <FilterSelect label="Time window" value={draft.window} disabled={disabled} onChange={(window) => setDraft((current) => ({ ...current, window: window as CaseWindow }))}>
          <option value="all">All loaded time</option>
          <option value="1h">Last hour</option>
          <option value="24h">Last 24 hours</option>
          <option value="7d">Last 7 days</option>
          <option value="30d">Last 30 days</option>
        </FilterSelect>
        <FilterSelect label="Scope type" value={draft.scopeKind} disabled={disabled} onChange={(scopeKind) => setDraft((current) => ({ ...current, scopeKind: scopeKind as CaseScopeKind, scopeId: scopeKind === "all" ? "" : current.scopeId }))}>
          <option value="all">All scopes</option>
          <option value="agent">Agent</option>
          <option value="host">Host</option>
          <option value="workload">Workload</option>
        </FilterSelect>
        <label className="text-xs font-semibold text-slate-700 md:col-span-2 xl:col-span-3">
          Scope identifier
          <input value={draft.scopeId} maxLength={256} disabled={disabled || draft.scopeKind === "all"} onChange={(event) => setDraft((current) => ({ ...current, scopeId: event.target.value }))} placeholder={draft.scopeKind === "all" ? "Choose a scope type first" : `${draft.scopeKind}:…`} className="mt-1 block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm font-normal disabled:bg-slate-100" />
        </label>
      </div>
      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-4">
        {/* The second sentence here read "Unsupported server dimensions are applied
            only to the current bounded page and labelled as such": our plumbing,
            on every load, for a case that mostly does not apply. The results
            panel already says it, in plain words, exactly when it does. */}
        <p className="text-xs leading-5 text-slate-500">Your filters and time window are kept in the address bar, so this view can be bookmarked or shared.</p>
        <div className="flex gap-2">
          <button type="button" disabled={disabled} onClick={onClear} className="rounded-lg px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-100 disabled:opacity-50">Clear</button>
          <button type="submit" disabled={disabled} className="rounded-lg bg-slate-950 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50">Apply filters</button>
        </div>
      </div>
    </form>
  );
}

function FilterSelect({ label, value, disabled, onChange, children }: {
  label: string;
  value: string;
  disabled: boolean;
  onChange: (value: string) => void;
  children: ReactNode;
}) {
  return (
    <label className="text-xs font-semibold text-slate-700">
      {label}
      <select value={value} disabled={disabled} onChange={(event) => onChange(event.target.value)} className="mt-1 block w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-normal text-slate-950 disabled:bg-slate-100">
        {children}
      </select>
    </label>
  );
}
