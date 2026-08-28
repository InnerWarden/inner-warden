import type {
  CapabilityStatus,
  CoverageGap,
  DashboardBootstrap,
  DashboardPosture,
  EvidenceFreshness,
  LayerDisposition,
  ProtectionLayer,
  RuntimeConvergence,
  ScopeRef,
} from "../api/v1";
import { StatusBadge } from "../components/StatusBadge";
import { layerAssuranceLabel } from "../posture/assurance";

// ─────────────────────────── user-facing projections ─────────────────────────
//
// This screen answers the operator's question: which host controls are on, are
// they working, and what needs my attention. The verification chain that backs
// each answer stays one interaction away in a per-control disclosure; it never
// renders as the screen's primary content.

const ARMED_MODES = ["enforce", "observe", "rehearse"];

/** Effective mode in plain words, from a CLOSED set.
 *
 * This used to render "Enforcing, verifying" whenever the effective mode was
 * unknown but the desired mode was armed. The intent was to avoid a bare
 * "Unknown" on a control that is demonstrably armed. The effect, on a real
 * production host, was a page claiming enforcement directly above a subtitle
 * reading "not checked yet" and a coverage gap reading "Degraded", all about
 * the same control, on the same render.
 *
 * In production there is no half state. A control is enforcing, watching,
 * deliberately off, or not confirmed. "Armed but we could not confirm it" is
 * not a fourth shade of working: it is a check that did not run, which is a
 * bug to fix rather than a phrase to soften. Rendering it as NOT CONFIRMED
 * keeps proven and assumed distinguishable at a glance, which is the whole
 * job of this screen. */
export function plainMode(layer: Pick<ProtectionLayer, "effective_mode" | "desired_mode">): string {
  const words: Record<string, string> = {
    enforce: "Enforcing",
    observe: "Watching",
    rehearse: "Rehearsing",
    learning: "Learning",
    disabled: "Off",
    mixed: "Mixed",
  };
  if (layer.effective_mode !== "unknown") return words[layer.effective_mode] ?? "Not confirmed";
  // Armed intent survives in `desired_mode` and in the disclosure; the summary
  // row does not get to borrow it as a claim.
  if (ARMED_MODES.includes(layer.desired_mode)) return "Not confirmed";
  if (layer.desired_mode === "disabled") return "Off";
  return "Not confirmed";
}

/** Freshness as the user fact: when this control was last checked. The producer
 * budget is contract bookkeeping and lives in the disclosure only. */
export function checkedAt(freshness: EvidenceFreshness): string {
  if (freshness.observed_at === null || freshness.observed_at === undefined) {
    return "never checked";
  }
  const at = new Date(freshness.observed_at);
  if (Number.isNaN(at.getTime())) return "never checked";
  const hh = String(at.getHours()).padStart(2, "0");
  const mm = String(at.getMinutes()).padStart(2, "0");
  return `as of ${hh}:${mm}`;
}

/** Scope as its display name only; kind and verification detail belong to the
 * disclosure, not to every summary row. */
export function scopeDisplay(scopes: ScopeRef[]): string {
  if (scopes.length === 0) return "No scope reported";
  return scopes.map((scope) => scope.display_name ?? scope.id).join("; ");
}

/** The full scope record, for the disclosure. */
export function scopeDetail(scopes: ScopeRef[]): string {
  if (scopes.length === 0) return "No effective scope reported";
  return scopes.map((scope) => `${scope.display_name ?? scope.id} (${scope.kind}; ${humanize(scope.verification)})`).join("; ");
}

/**
 * Which audience a coverage gap addresses.
 *
 * "operator": a control the user turned on is not doing what it says; there is
 * something to run or fix. These render amber, once, in the gaps section.
 *
 * "verification": the SYSTEM still owes its own proof chain (assurance-matrix
 * pinning, scope-membership evidence, producer timestamps). Nothing the
 * operator clicks resolves these; they render as quiet verification-pending
 * lines inside the owning control's disclosure, never as amber cards.
 */
export function gapAudience(gap: Pick<CoverageGap, "id" | "state">): "operator" | "verification" {
  if (/assurance|membership|temporal|scope-state/.test(gap.id)) return "verification";
  if (gap.state === "unknown" && !/effectiveness/.test(gap.id)) return "verification";
  return "operator";
}

/**
 * The layer's disposition, or the best reading of an older agent's payload.
 *
 * The host computes this now, because only the host can tell a healthy unarmed
 * control from a broken one. A host on an older build sends no `disposition`,
 * so the fallback reconstructs it from what that build DID send: and it must
 * reconstruct it conservatively, never inventing `proven`.
 */
export function dispositionOf(
  layer: Pick<ProtectionLayer, "disposition" | "claim_state" | "effective_mode" | "desired_mode">,
): LayerDisposition {
  if (layer.disposition) return layer.disposition;

  // Fallback for a host that predates the field.
  if (layer.claim_state === "active") return "proven";
  if (layer.effective_mode === "unknown") return "cannot_verify";
  // "Doing what it was told" is the case the old model could not express, so
  // it has to be derived here rather than read.
  if (layer.effective_mode === layer.desired_mode) return "working_as_configured";
  if (layer.claim_state === "not_covered") return "not_enabled";
  return "needs_operator";
}

/**
 * What the reader should do, in their words.
 *
 * The host ships `disposition_reason`; this is the floor under a payload that
 * has the disposition but no sentence, so no state can ever render bare. A
 * state with no explanation is what made people stop reading this page.
 */
export function dispositionReason(
  layer: Pick<
    ProtectionLayer,
    "disposition" | "disposition_reason" | "claim_state" | "effective_mode" | "desired_mode" | "label"
  >,
  // The disposition actually being SHOWN, after the assurance veto. When it
  // differs from what the host reported, the host's sentence belongs to the
  // stronger state and must not be printed under the softer badge: on a real
  // host that produced a row badged "Working as set up" above the words "is
  // enforcing, and that was verified on this host". The badge is the claim;
  // the sentence has to agree with it, not outrank it.
  shown?: LayerDisposition,
): string {
  const effective = shown ?? dispositionOf(layer);
  if (layer.disposition_reason && effective === dispositionOf(layer)) {
    return layer.disposition_reason;
  }
  const fallback: Record<LayerDisposition, string> = {
    proven: `${layer.label} is enforcing, and that was verified on this host.`,
    working_as_configured: `${layer.label} is doing what it is set to do.`,
    not_enabled: `${layer.label} has not been turned on yet. Nothing is wrong.`,
    cannot_verify: `${layer.label} could not be read on this host. This is ours to fix, not yours.`,
    needs_operator: `${layer.label} is not yet doing what it was set to do.`,
  };
  return fallback[effective];
}

/** Only one disposition asks the reader for anything. Amber has to stay scarce
 *  to keep meaning anything. */
export function needsOperator(disposition: LayerDisposition): boolean {
  return disposition === "needs_operator";
}

/**
 * The disposition a surface may actually show, after the assurance veto.
 *
 * `proven` is the only disposition that earns the positive colour, so it is the
 * only one the assurance rule gets a veto over: a host can report a control as
 * verified while the assurance chain has not pinned it, and rendering that as
 * emerald is the over-claim this screen exists to prevent. The downgrade lands
 * on `working_as_configured`, not on an alarm; only the CLAIM is softened.
 *
 * EVERY surface must go through this. The summary pill applied the veto and the
 * control row did not, so on a real host the same control read "Working as set
 * up" in the pill and "Protecting" in the row, on the same render. A page that
 * contradicts itself is worse than a page that is wrong: the reader cannot tell
 * which line to believe.
 */
export function effectiveDisposition(
  layer: Pick<ProtectionLayer, "disposition" | "claim_state" | "effective_mode" | "desired_mode">,
  verifiedActive: boolean,
): LayerDisposition {
  const reported = dispositionOf(layer);
  return reported === "proven" && !verifiedActive ? "working_as_configured" : reported;
}

export type ControlPill = {
  name: string;
  mode: string;
  scope: string;
  freshness: string;
  tone: "positive" | "attention" | "neutral" | "informational";
  verified: boolean;
  /** Which of the five states this control is in. Drives colour and routing. */
  disposition: LayerDisposition;
  /** One sentence saying what to do, or why there is nothing to do. */
  reason: string;
};

/** The colour a disposition earns.
 *
 * `positive` is reserved for `proven`. `working_as_configured` reads
 * informational, not emerald, because "nothing to do" and "we proved this
 * protects you" are different claims and the page's whole job is keeping them
 * apart. `not_enabled` and `cannot_verify` are neutral: neither is a fault, and
 * both used to render amber. */
export function dispositionTone(disposition: LayerDisposition): ControlPill["tone"] {
  switch (disposition) {
    case "proven":
      return "positive";
    case "working_as_configured":
      return "informational";
    case "needs_operator":
      return "attention";
    default:
      return "neutral";
  }
}

/** The words on the pill. Plain enough for someone who has never run a
 *  security product, because that is who installs this. */
export function dispositionLabel(disposition: LayerDisposition): string {
  switch (disposition) {
    case "proven":
      return "Protecting";
    case "working_as_configured":
      return "Working as set up";
    case "not_enabled":
      return "Not turned on";
    case "cannot_verify":
      return "Can't confirm";
    case "needs_operator":
      return "Needs you";
  }
}

export function controlPill(
  layer: ProtectionLayer,
  bootstrap: DashboardBootstrap,
  generatedAt: string,
  current: boolean,
  evaluatedAt: string,
): ControlPill {
  const assurance = layerAssuranceLabel(
    layer,
    bootstrap.capabilities,
    bootstrap.assurance_matrix,
    generatedAt,
    bootstrap.generated_at,
    evaluatedAt,
    bootstrap.platform.os,
    current,
  );
  // `proven` is the only disposition that earns the positive colour, so it is
  // the only one the assurance rule gets a veto over. A host can report a
  // control as verified while the assurance chain has not pinned it; showing
  // that as emerald is precisely the over-claim this screen exists to prevent.
  //
  // The downgrade lands on `working_as_configured`, not on an alarm: the
  // control is still doing what it was told, and the reader still has nothing
  // to do. Only the CLAIM is softened.
  const disposition = effectiveDisposition(layer, assurance.verifiedActive);
  return {
    name: layer.label,
    mode: current ? dispositionLabel(disposition) : "Refreshing",
    scope: scopeDisplay(layer.effective_scope),
    freshness: current ? checkedAt(layer.freshness) : "refreshing",
    // Colour follows the disposition, not "is it verified, else does it have a
    // gap". Under the old rule every control that was not verified-active and
    // carried any gap went amber: which is every control on a healthy,
    // deliberately-unarmed, freshly installed host.
    tone: dispositionTone(disposition),
    verified: assurance.verifiedActive,
    disposition,
    reason: dispositionReason(layer, disposition),
  };
}

/** The one-line verdict the screen leads with.
 *
 * It counted "enforcing" and "not confirmed" and nothing else, so a host where
 * every control was healthy but deliberately watching led with `0 of 5`. That
 * number is true and reads as total failure. Lead with whether anything needs
 * the reader, because that is the question they came with. */
/**
 * The one line at the top of the page.
 *
 * Prefers the sentence the HOST computed, because the host is the only side
 * that can see whether a control's remedy command still needs running. This
 * screen counting dispositions and writing its own line is how the page came to
 * say "Nothing needs you." above two cards that each printed a command the
 * operator had to run: the tail below was unconditional.
 *
 * The local computation stays as the fallback, for a producer that sends no
 * summary, and its tail is now conditional too so the fallback cannot make the
 * same claim.
 */
export function postureHeadline(pills: ControlPill[], hostSummary?: string): string {
  const fromHost = hostSummary?.trim();
  if (fromHost) return fromHost;
  const total = pills.length;
  if (total === 0) return "No host controls reported";

  const needing = pills.filter((pill) => needsOperator(pill.disposition)).length;
  const protecting = pills.filter((pill) => pill.disposition === "proven").length;
  const notOn = pills.filter((pill) => pill.disposition === "not_enabled").length;

  const s = total === 1 ? "" : "s";

  // Anything needing the reader wins the headline: it is the only thing they
  // can act on, and burying it under a count of what is fine is how a page
  // stops being read.
  if (needing > 0) {
    return `${needing} of ${total} host control${s} need${needing === 1 ? "s" : ""} your attention`;
  }
  if (notOn === total) {
    return `Nothing is turned on yet: ${total} control${s} ready to enable`;
  }
  if (protecting === total) {
    return `All ${total} host control${s} protecting`;
  }

  // Every state is named, and "the rest" is never used to sweep one up.
  //
  // The headline read "N protecting, the rest working", and "the rest" quietly
  // included controls in `cannot_verify`. On a real host that put a control the
  // page had just described as unreadable, in its own words "we will not claim
  // either way", inside a count of things that are working. Summarising is not
  // a licence to claim what the detail refuses to claim, and this page exists
  // to keep proven, working and unknown apart.
  const cannotConfirm = pills.filter((pill) => pill.disposition === "cannot_verify").length;
  const working = pills.filter((pill) => pill.disposition === "working_as_configured").length;

  const parts: string[] = [];
  if (protecting > 0) parts.push(`${protecting} protecting`);
  if (working > 0) parts.push(`${working} working`);
  if (notOn > 0) parts.push(`${notOn} not turned on`);
  if (cannotConfirm > 0) {
    parts.push(`${cannotConfirm} we can't confirm`);
  }

  // "Nothing needs you" is a claim about every card on the page, so it may only
  // be made when no card asks for anything. A control that is off asks to be
  // turned on, and saying otherwise over its own remedy command is the same
  // defect this page was built to remove.
  const nothingToDo = notOn === 0 && cannotConfirm === 0;
  const tail = nothingToDo ? " Nothing needs you." : "";
  return `${total} host control${s}: ${parts.join(", ")}.${tail}`;
}

/** The quiet line shown when no gap card needs to render. */
export function emptyGapsLine(totalGaps: number): string {
  return totalGaps === 0
    ? "No coverage gaps in this snapshot."
    : "No coverage gaps need attention in this snapshot.";
}

// ────────────────────────────────── screen ───────────────────────────────────

export function Posture({
  bootstrap,
  posture,
  current,
  evaluatedAt,
  onCheckNow,
}: {
  bootstrap: DashboardBootstrap;
  posture: DashboardPosture;
  current: boolean;
  evaluatedAt: string;
  /** Force a re-read of the host now. Optional so an embedder that has no
   *  refresh handle simply does not render the button. */
  onCheckNow?: () => void | Promise<void>;
}) {
  const pills = posture.layers.map((layer) => controlPill(layer, bootstrap, posture.generated_at, current, evaluatedAt));
  // A gap is an amber card only when the control that OWNS it is asking for
  // the reader. The gap text still exists everywhere else: it stays in the
  // owning control's disclosure: so nothing is hidden; only the routing
  // changed. Suppressing the text would trade one dishonesty for another.
  // Read off the PILLS, which have already been through the assurance veto, so
  // the gap list, the pill and the row cannot end up telling three stories.
  // `pills` is built from `posture.layers` in order, so the indices line up.
  const needy = new Set(
    posture.layers
      .filter((_, index) => needsOperator(pills[index].disposition))
      .flatMap((layer) => layer.capability_ids),
  );
  const operatorGaps = dedupeGaps(
    posture.gaps.filter((gap) => gapAudience(gap) === "operator" && needy.has(gap.capability_id)),
  );

  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-700">Protection posture</p>
          <h2 className="mt-1 text-xl font-semibold tracking-tight text-slate-950">Host controls</h2>
          <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-600">
            What is enforcing, what is watching, and where the gaps are.
          </p>
        </div>
        {/* The page refreshes on a slow cadence now, because the evidence behind
            it does. An operator who wants an answer this second asks for one
            instead of waiting out a poll whose length they cannot see. */}
        {onCheckNow ? (
          <button
            type="button"
            onClick={() => void onCheckNow()}
            className="shrink-0 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-600"
          >
            Check now
          </button>
        ) : null}
      </div>

      {posture.layers.length > 0 ? (
        <section data-tour="posture" aria-labelledby="posture-verdict-title" className="overflow-hidden rounded-2xl border border-slate-200 bg-gradient-to-br from-white to-slate-50">
          <div className="px-5 py-6 sm:px-7">
            <h3 id="posture-verdict-title" className="text-2xl font-semibold tracking-tight text-slate-950">
              {postureHeadline(pills, posture.summary)}
            </h3>
            <ul className="mt-4 flex flex-wrap gap-2" aria-label="Host controls">
              {pills.map((pill) => (
                <li
                  key={pill.name}
                  title={pill.reason}
                  className={`inline-flex max-w-full items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold ${
                    pill.tone === "positive"
                      ? "border-emerald-200 bg-emerald-50 text-emerald-900"
                      : pill.tone === "attention"
                        ? "border-amber-200 bg-amber-50 text-amber-900"
                        : pill.tone === "informational"
                          ? "border-cyan-200 bg-cyan-50 text-cyan-900"
                          : "border-slate-200 bg-white text-slate-700"
                  }`}
                >
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-current opacity-70" aria-hidden="true" />
                  <span className="truncate">{pill.name}</span>
                  <span className="shrink-0 font-medium opacity-80">{pill.mode}</span>
                </li>
              ))}
            </ul>
          </div>
        </section>
      ) : (
        <p className="rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-sm leading-6 text-slate-600">
          No host controls reported in this snapshot.
        </p>
      )}

      <section aria-labelledby="posture-controls-title">
        <h3 id="posture-controls-title" className="sr-only">Control details</h3>
        <div className="space-y-3">
          {posture.layers.map((layer) => (
            <ControlRow
              key={layer.id}
              layer={layer}
              bootstrap={bootstrap}
              generatedAt={posture.generated_at}
              current={current}
              evaluatedAt={evaluatedAt}
            />
          ))}
        </div>
        <p className="mt-3 text-xs leading-5 text-slate-500">
          Host controls are evaluated from host evidence only; agent metadata never grants host trust.
        </p>
      </section>

      <section aria-labelledby="posture-gaps-title">
        <div className="mb-4">
          <h2 id="posture-gaps-title" className="text-xl font-semibold tracking-tight text-slate-950">Coverage gaps</h2>
        </div>
        {operatorGaps.length > 0 ? (
          <div className="space-y-3">{operatorGaps.map((gap) => <GapCard key={gap.id} gap={gap} />)}</div>
        ) : (
          <p className="text-sm leading-6 text-slate-600">{emptyGapsLine(posture.gaps.length)}</p>
        )}
      </section>
    </div>
  );
}

/** posture.gaps is the layers' known_gaps flattened by the producer, so a gap
 * must render once even if a future producer lists it twice. */
function dedupeGaps(gaps: CoverageGap[]): CoverageGap[] {
  const seen = new Set<string>();
  return gaps.filter((gap) => (seen.has(gap.id) ? false : (seen.add(gap.id), true)));
}

function ControlRow({
  layer,
  bootstrap,
  generatedAt,
  current,
  evaluatedAt,
}: {
  layer: ProtectionLayer;
  bootstrap: DashboardBootstrap;
  generatedAt: string;
  current: boolean;
  evaluatedAt: string;
}) {
  const assurance = layerAssuranceLabel(
    layer,
    bootstrap.capabilities,
    bootstrap.assurance_matrix,
    generatedAt,
    bootstrap.generated_at,
    evaluatedAt,
    bootstrap.platform.os,
    current,
  );
  const relevantCapabilities = layer.capability_ids
    .map((id) => bootstrap.capabilities.find((capability) => capability.id === id))
    .filter((capability): capability is CapabilityStatus => capability !== undefined);
  // Through the SAME veto the pill uses, or the two disagree on one render.
  const disposition = effectiveDisposition(layer, assurance.verifiedActive);
  // A gap whose owning control is NOT asking for the reader still belongs in
  // this disclosure: it is honest boundary text, just not an action card.
  const verificationGaps = layer.known_gaps.filter(
    (gap) => gapAudience(gap) === "verification" || !needsOperator(disposition),
  );

  return (
    <article className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm sm:p-5">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <h3 className="min-w-0 flex-1 truncate text-base font-semibold text-slate-950">{layer.label}</h3>
        <StatusBadge
          status={current ? disposition : "stale"}
          label={current ? dispositionLabel(disposition) : "Refreshing"}
          className="shrink-0"
        />
        <span className="[overflow-wrap:anywhere] text-sm text-slate-600">{scopeDisplay(layer.effective_scope)}</span>
        <span className="shrink-0 text-xs font-medium text-slate-500">{current ? checkedAt(layer.freshness) : "refreshing"}</span>
      </div>

      {/* The sentence, on the row, not one click away.
          Someone installing this for the first time should not have to open a
          disclosure called "How this was verified" to learn that a grey control
          is grey because they have not turned it on yet. */}
      {current ? (
        <p className="mt-2 text-sm leading-6 text-slate-600">{dispositionReason(layer, disposition)}</p>
      ) : null}

      <details className="mt-3 border-t border-slate-100 pt-3">
        <summary className="cursor-pointer text-xs font-semibold text-slate-500 hover:text-slate-700">How this was verified</summary>
        <div className="mt-3 space-y-5">
          <div className="flex flex-wrap items-center gap-3">
            <StatusBadge status={current ? assurance.status : "stale"} label={current ? assurance.label : "Awaiting a current snapshot"} />
            <span className="text-xs text-slate-500">
              {layer.evidence.length} evidence record{layer.evidence.length === 1 ? "" : "s"} · freshness {humanize(layer.freshness.state)}
              {layer.freshness.age_seconds !== null ? `, ${layer.freshness.age_seconds}s old` : ""} · {layer.freshness.budget_seconds}s producer budget
            </span>
          </div>
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Runtime convergence</h4>
            <Convergence convergence={layer.convergence} current={current} />
          </div>
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Effective scope</h4>
            <p className="mt-1 [overflow-wrap:anywhere] text-sm text-slate-700">{scopeDetail(layer.effective_scope)}</p>
            {layer.covered_action_classes.length > 0 ? (
              <p className="mt-1 text-xs text-slate-500">Covered actions: {layer.covered_action_classes.map(humanize).join(", ")}</p>
            ) : null}
          </div>
          <div>
            <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Declared capabilities</h4>
            {relevantCapabilities.length > 0 ? (
              <ul className="mt-2 space-y-2">
                {relevantCapabilities.map((capability) => (
                  <li key={capability.id} className="flex flex-wrap items-start justify-between gap-2 rounded-lg border border-slate-100 bg-slate-50 px-3 py-2 text-sm">
                    <span className="[overflow-wrap:anywhere] font-medium text-slate-800">{humanize(capability.id)}</span>
                    <StatusBadge status={current ? capability.availability : "stale"} />
                  </li>
                ))}
              </ul>
            ) : <p className="mt-2 text-sm text-slate-600">No matching capability record was declared.</p>}
          </div>
          {verificationGaps.length > 0 ? (
            <ul className="space-y-1">
              {verificationGaps.map((gap) => (
                <li key={gap.id} className="text-xs leading-5 text-slate-500">Verification pending: {gap.next_step}</li>
              ))}
            </ul>
          ) : null}
        </div>
      </details>
    </article>
  );
}

function Convergence({ convergence, current }: { convergence: RuntimeConvergence; current: boolean }) {
  const stages = [
    ["Configured", convergence.configured],
    ["Loaded", convergence.loaded],
    ["Running", convergence.running],
    ["Enforcing", convergence.enforcing],
    ["Verified effective", convergence.verified_effective],
  ] as const;
  return (
    <ol className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-5">
      {stages.map(([label, stage]) => (
        <li key={label} className="rounded-lg border border-slate-100 bg-slate-50 p-2.5">
          <div className="text-[11px] font-semibold text-slate-600">{label}</div>
          <div className="mt-1"><StatusBadge status={current ? stage.state : "stale"} /></div>
          {stage.reason_code ? <div className="mt-1 [overflow-wrap:anywhere] text-[10px] text-slate-500">{humanize(stage.reason_code)}</div> : null}
        </li>
      ))}
    </ol>
  );
}

function GapCard({ gap }: { gap: CoverageGap }) {
  return (
    <article className="rounded-xl border border-amber-200 bg-amber-50/60 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <StatusBadge status={gap.state} />
          <h3 className="mt-2 [overflow-wrap:anywhere] font-semibold text-slate-950">{humanize(gap.capability_id)}</h3>
        </div>
      </div>
      <p className="mt-2 text-sm leading-6 text-slate-800">{sentence(gap.next_step)}</p>
      <p className="mt-2 text-xs text-slate-600">
        {gap.action_classes.length > 0 ? `Affects ${gap.action_classes.map(humanize).join(", ").toLowerCase()}` : "Affected actions not reported"}
        {" · "}
        {scopeDisplay(gap.affected_scope)}
      </p>
    </article>
  );
}

function sentence(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return trimmed;
  const capitalized = trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
  return /[.!?]$/.test(capitalized) ? capitalized : `${capitalized}.`;
}

function humanize(value: string): string {
  const text = value.replace(/[._-]+/g, " ").replace(/\s+/g, " ").trim();
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : "Unknown";
}
