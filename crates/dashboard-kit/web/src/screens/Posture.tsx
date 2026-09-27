import { Children, type ReactNode } from "react";
import type {
  AgentLayerReport,
  CapabilityStatus,
  CoverageGap,
  DashboardBootstrap,
  DashboardPosture,
  EvidenceFreshness,
  LayerDisposition,
  LocalModelReport,
  MeasuredValue,
  ProtectionLayer,
  RuntimeConvergence,
  ScopeRef,
} from "../api/v1";
import { StatusBadge, statusPresentation } from "../components/StatusBadge";
import { setTechnicalDetail, TechnicalOnly, useTechnicalDetail } from "../components/TechnicalDetail";
import { OutcomeBreakdown } from "../components/LaneCards";
import { controlGlyph, Glyph } from "../components/icons";
import { Ring, Steps, type Part, type StepMark } from "../components/viz";
import { LANE_WINDOW_PHRASE, type AgentCommands } from "../lanes";
import { formatClock, formatCount, freshnessLabel, timeTitle } from "../presentation";
import { layerAssuranceLabel, type LayerAssuranceLabel } from "../posture/assurance";
import { POSTURE_REFRESH_MS } from "../posture/refresh";

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
export function checkedAt(freshness: EvidenceFreshness, now: Date = new Date(), timeZone?: string): string {
  if (freshness.observed_at === null || freshness.observed_at === undefined) {
    return "never checked";
  }
  // The time of day with its zone when the check was today, and the date as
  // well when it was not: "as of 01:21" read the same on a check from this
  // morning and one from last week.
  const at = formatClock(freshness.observed_at, now, timeZone);
  return at === undefined ? "never checked" : `as of ${at}`;
}

/** How much older than the newest check a row's own check must be to be printed on it. */
export const CHECK_LAG_MS = 5 * 60 * 1_000;

/**
 * Whether a control's check is worth its own time on its row: never
 * checked, or more than `CHECK_LAG_MS` older than the newest check the hero
 * states. A row checked with the others says nothing the hero does not.
 */
export function checkedLate(observedAt: string | null | undefined, latest: string | undefined): boolean {
  if (observedAt === null || observedAt === undefined) return true;
  const at = Date.parse(observedAt);
  const newest = latest === undefined ? Number.NaN : Date.parse(latest);
  if (!Number.isFinite(at) || !Number.isFinite(newest)) return true;
  return newest - at > CHECK_LAG_MS;
}

/**
 * Whether a control's sentence says more than its badge and its ladder: a
 * command to run, a control that is not on, one this page cannot confirm,
 * one that needs the reader, or one softened from protecting. For a control
 * protecting, or working as set up, it restated the badge.
 */
export function reasonAddsToBadge(disposition: LayerDisposition, softened: boolean, reason: string): boolean {
  if (reason.includes("`")) return true;
  if (disposition === "proven") return false;
  return !(disposition === "working_as_configured" && !softened);
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
  > & Partial<Pick<ProtectionLayer, "id" | "capability_ids">>,
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
    return agreeWithControls(withProductName(layer.disposition_reason, layer));
  }
  // The name the reader bought, where the control has one.
  const label = controlName({ id: layer.id ?? "", label: layer.label, capability_ids: layer.capability_ids ?? [] }).name;
  const fallback: Record<LayerDisposition, string> = {
    proven: `${label} is enforcing, and that was verified on this host.`,
    // Deliberately not "is doing what it is set to do": that sentence rendered
    // under a chip reading "not proven", so the card asserted in prose exactly
    // what the chip beside it declined to assert. This says what is on record
    // and stops.
    working_as_configured: `${label} is set up and reporting.`,
    not_enabled: `${label} has not been turned on yet. Nothing is wrong.`,
    cannot_verify: `${label} could not be read on this host. This is ours to fix, not yours.`,
    needs_operator: `${label} is not yet doing what it was set to do.`,
  };
  return agreeWithControls(fallback[effective]);
}

/**
 * "Response controls is blocking" reads as a slip on the one page that asks
 * to be believed word for word. A control named in the plural ("... controls")
 * takes "are" (and "have", "were"). Only that construction is touched: every
 * other word of the host's sentence is printed as sent.
 */
export function agreeWithControls(sentence: string): string {
  return sentence
    .replace(/\bcontrols is\b/g, "controls are")
    .replace(/\bcontrols has\b/g, "controls have")
    .replace(/\bcontrols was\b/g, "controls were");
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

/**
 * Did the assurance veto soften this control's claim?
 *
 * The host counts its headline off the RAW dispositions it sent, so a host that
 * reported three controls as proven leads with "3 protecting, 1 working". Every
 * chip on this page is computed after the veto, and the veto lands all three of
 * those on `working_as_configured`: so four controls wore the identical chip
 * "Working as set up" under a sentence that had just split them three to one.
 * A reader cannot check a sentence against chips that say the same thing.
 *
 * This is the difference the chip needs to show, and it is a real difference,
 * not a cosmetic one: a control the host claims is verified but whose proof
 * chain is unpinned is not the same fact as a control that is simply doing what
 * it was configured to do.
 *
 * It reads the reported state as `effectiveDisposition(layer, true)`, which is
 * the veto switched off, rather than calling `dispositionOf` directly. One
 * reader of the raw disposition is the whole point of the veto.
 */
export function claimSoftened(
  layer: Pick<ProtectionLayer, "disposition" | "claim_state" | "effective_mode" | "desired_mode">,
  verifiedActive: boolean,
): boolean {
  return (
    effectiveDisposition(layer, true) === "proven" &&
    effectiveDisposition(layer, verifiedActive) !== "proven"
  );
}

/**
 * The name a control is sold under, and what it does in general words.
 *
 * The site sells Execution Gate, Secret Read Guard and DNS Guard. This page
 * named the same three "Independent host execution", "Secret access
 * control" and "DNS resolution control", and a buyer looking for what they
 * paid for found none of the names. The product name is the title now, and
 * the general description sits under it, so both readers find their word.
 *
 * Matched on the ids the host sends (the layer's own id, or any capability
 * id it carries), never on the label: a label is prose and may be reworded.
 * A control with no product name of its own (host visibility, response
 * controls) keeps the host's label and has no second line.
 */
export type ControlName = { name: string; description?: string };

// Exactly the six ids the paid host sends for these three controls, a layer
// id and a capability id each: an id no host sends is a name this page could
// hand out to something it does not know.
const PRODUCT_NAMES: readonly { ids: readonly string[]; name: string; description: string }[] = [
  {
    ids: ["independent_host_execution", "kernel_execution_control"],
    name: "Execution Gate",
    description: "Independent host execution control",
  },
  {
    ids: ["secret_access_control", "secret_read_guard"],
    name: "Secret Read Guard",
    description: "Secret access control",
  },
  {
    ids: ["dns_resolution_control", "dns_guard"],
    name: "DNS Guard",
    description: "DNS resolution control",
  },
];

function productFor(ids: readonly string[]): (typeof PRODUCT_NAMES)[number] | undefined {
  return PRODUCT_NAMES.find((product) => ids.some((id) => product.ids.includes(id)));
}

export function controlName(layer: Pick<ProtectionLayer, "id" | "label" | "capability_ids">): ControlName {
  const product = productFor([layer.id, ...layer.capability_ids]);
  return product === undefined ? { name: layer.label } : { name: product.name, description: product.description };
}

/**
 * The host's sentence about a control, with the control called by the name
 * on its card.
 *
 * The card's title says "Execution Gate" and the host's sentence under it
 * began "Independent host execution is blocking...", so one card named the
 * control twice, two ways. Where the sentence OPENS with the host's label
 * for the control (or the general words under the title), that opening is
 * the control's name and is written as the product name. Nothing else in
 * the sentence is touched, and a control with no product name keeps the
 * host's words.
 */
export function withProductName(
  sentence: string,
  layer: Pick<ProtectionLayer, "label"> & Partial<Pick<ProtectionLayer, "id" | "capability_ids">>,
): string {
  const product = productFor([layer.id ?? "", ...(layer.capability_ids ?? [])]);
  if (product === undefined) return sentence;
  const lead = sentence.trimStart();
  for (const phrase of [layer.label, product.description].map((value) => value.trim()).filter((value) => value !== "")) {
    if (lead.length < phrase.length || lead.slice(0, phrase.length).toLowerCase() !== phrase.toLowerCase()) continue;
    // A whole phrase only: "DNS resolution controller" is not "DNS resolution control".
    if (/^[\p{L}\p{N}_]/u.test(lead.slice(phrase.length))) continue;
    return `${product.name}${lead.slice(phrase.length)}`;
  }
  return sentence;
}

/** A capability by the product name it belongs to, or its id in words. */
export function capabilityName(id: string): string {
  return productFor([id])?.name ?? humanize(id);
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
  /**
   * The host reported this control as proven and the assurance chain did not
   * pin it, so its chip reads "Containing, not proven" (`claimSoftened`).
   */
  softened: boolean;
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
 *  security product, because that is who installs this.
 *
 *  `softened` is the control the host reported as proven and the assurance
 *  chain did not pin. It shares a disposition with a control that is merely
 *  doing what it was configured to do, and it must not share a chip: the host
 *  headline counts the two apart, and a page whose chips collapse a split the
 *  sentence above them just made cannot be checked by the person reading it.
 *
 *  It says "not proven" and stops. It does not say "watching" or "not
 *  containing", which would be this page inventing a fact about the control's
 *  mode out of a missing proof. Only the CLAIM is softened; the control may
 *  well be enforcing. */
export function dispositionLabel(disposition: LayerDisposition, softened = false): string {
  // "Containing", not "Working". A softened chip is a control the HOST called
  // proven and whose assurance chain this page could not pin, so what it does is
  // known and only the proof is missing. Labelling it "Working, not proven" put
  // it BELOW the plain "Working as set up" worn by a control that only observes,
  // so the page read as if containment were weaker than watching, and it
  // contradicted its own summary of "3 protecting, 1 working". Name the job,
  // then name what is missing.
  if (softened && disposition === "working_as_configured") return "Containing, not proven";
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
  /** The assurance already decided for this read (`heldAssurance`); computed here when absent. */
  decided?: LayerAssuranceLabel,
): ControlPill {
  const assurance = decided ?? layerAssuranceLabel(
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
  const softened = claimSoftened(layer, assurance.verifiedActive);
  return {
    name: controlName(layer).name,
    mode: current ? dispositionLabel(disposition, softened) : "Refreshing",
    scope: scopeDisplay(layer.effective_scope),
    freshness: current ? checkedAt(layer.freshness) : "refreshing",
    // Colour follows the disposition, not "is it verified, else does it have a
    // gap". Under the old rule every control that was not verified-active and
    // carried any gap went amber: which is every control on a healthy,
    // deliberately-unarmed, freshly installed host.
    tone: dispositionTone(disposition),
    verified: assurance.verifiedActive,
    disposition,
    softened,
    reason: dispositionReason(layer, disposition),
  };
}

/**
 * How long past the posture poll a verification may be held while the next
 * read is on its way: a read in flight, or a poll that fired a little late.
 * Past it the page has no current proof, and the chip says so.
 */
export const HOLD_GRACE_MS = 60_000;

/** One verification this page made on a read, and what it may be held against. */
export type HeldVerification = {
  /** The bootstrap read the verification was made with. */
  bootstrap: DashboardBootstrap;
  /** The consumer's clock the last time the read verified it. */
  at: number;
  /** When the hold lapses: a poll and its grace later, or the claim's expiry. */
  until: number;
};

/**
 * Which controls were verified on each posture READ, by the read itself.
 *
 * Keyed on the snapshot object: the shell keeps one object per successful
 * read (a re-read, even of identical bytes, is a new object), so a hold lasts
 * at most as long as the read it was made on, and survives the reader leaving
 * the screen and coming back.
 */
const heldByRead = new WeakMap<DashboardPosture, Map<string, HeldVerification>>();

/**
 * The capability records behind a layer, in a bootstrap, still claim what
 * they claimed when the page verified it: available, supported, healthy,
 * enforcing, with nothing uncovered, and a verified claim that has not
 * expired at `now`. A bootstrap that withdraws the capability (health
 * failed, degraded, no claims, an expired claim) does not.
 */
export function bootstrapStillBacks(layer: Pick<ProtectionLayer, "capability_ids">, bootstrap: DashboardBootstrap, now: number): boolean {
  const records = bootstrap.capabilities.filter((capability) => layer.capability_ids.includes(capability.id));
  return bootstrap.assurance_matrix !== null
    && records.length > 0
    && records.every((capability) => capability.tier === "enterprise_core"
      && capability.availability === "available"
      && capability.support === "supported"
      && capability.effective_mode === "enforce"
      && capability.rollout_state === "enforcing"
      && capability.health === "healthy"
      && capability.bypass_classes.length === 0
      && capability.known_uncovered_paths.length === 0
      && capability.claims.some((claim) => claim.status === "verified"
        && claim.expires_at !== null
        && Number.isFinite(Date.parse(claim.expires_at))
        && now <= Date.parse(claim.expires_at)));
}

/** The earliest expiry of the verified claims behind a layer, or none. */
function claimsExpireAt(layer: Pick<ProtectionLayer, "capability_ids">, bootstrap: DashboardBootstrap): number {
  const expiries = bootstrap.capabilities
    .filter((capability) => layer.capability_ids.includes(capability.id))
    .flatMap((capability) => capability.claims)
    .filter((claim) => claim.status === "verified" && claim.expires_at !== null)
    .map((claim) => Date.parse(claim.expires_at as string))
    .filter(Number.isFinite);
  return expiries.length === 0 ? Number.POSITIVE_INFINITY : Math.min(...expiries);
}

/**
 * What the disclosure says about a verification held from earlier on the
 * read: when it was made, never a present tense. The chip says Protecting;
 * the disclosure says since when that is known.
 */
export function heldVerifiedLabel(at: number, now: number, timeZone?: string): string {
  const clock = formatClock(new Date(at), new Date(now), timeZone);
  return clock === undefined ? "Active enforcement verified earlier" : `Active enforcement verified at ${clock}`;
}

/**
 * The assurance each control shows for this read, with a verification held
 * across the seconds of the read instead of lapsing between polls.
 *
 * The check binds each control's evidence to the consumer's clock, which
 * ticks every second, against a producer budget of seconds, while the page
 * reads the host every few minutes. So a control verified at the read went
 * from "Protecting" to "Containing, not proven" half a minute later, and back
 * when the reader pressed Check now: the chips changed on every press and
 * nothing on the host had. A reader cannot trust chips that move when nothing
 * moved.
 *
 * So a control verified on a read keeps its verification while that read is
 * the page's reading, and no longer than it could still be true:
 *
 *  - The next posture read decides again from scratch (a host re-serving a
 *    frozen snapshot is a new read, judged by the clock at that read).
 *  - A new bootstrap read that withdraws the control's capability, or whose
 *    claim has expired, ends the hold at once (`bootstrapStillBacks`): a
 *    contradicting record demotes it at that read.
 *  - The hold never outlives the verified claim's `expires_at`, nor the
 *    posture poll plus `HOLD_GRACE_MS` after the page last verified it: a
 *    read that stalled is not proof, and the requests are bounded
 *    (`DASHBOARD_FETCH_TIMEOUT_MS`), so a hung one turns the page stale.
 *  - A page whose reading is not current holds nothing: it says "Refreshing".
 *
 * While held, the disclosure says when the verification was made
 * (`heldVerifiedLabel`) rather than a present tense.
 */
export function heldAssurance(
  posture: DashboardPosture,
  layer: ProtectionLayer,
  computed: LayerAssuranceLabel,
  current: boolean,
  context: { bootstrap: DashboardBootstrap; evaluatedAt: string },
  held: WeakMap<DashboardPosture, Map<string, HeldVerification>> = heldByRead,
): LayerAssuranceLabel {
  if (!current) return computed;
  const now = Date.parse(context.evaluatedAt);
  let verified = held.get(posture);
  if (verified === undefined) {
    verified = new Map();
    held.set(posture, verified);
  }
  if (computed.verifiedActive) {
    if (Number.isFinite(now)) {
      verified.set(layer.id, {
        bootstrap: context.bootstrap,
        at: now,
        until: Math.min(now + POSTURE_REFRESH_MS + HOLD_GRACE_MS, claimsExpireAt(layer, context.bootstrap)),
      });
    }
    return computed;
  }
  const hold = verified.get(layer.id);
  if (hold === undefined) return computed;
  const lapsed = !Number.isFinite(now)
    || now > hold.until
    || (context.bootstrap !== hold.bootstrap && !bootstrapStillBacks(layer, context.bootstrap, now));
  if (lapsed) {
    verified.delete(layer.id);
    return computed;
  }
  return { label: heldVerifiedLabel(hold.at, now), status: "active", verifiedActive: true, verifiedAt: hold.at };
}

function assuranceFor(
  posture: DashboardPosture,
  layer: ProtectionLayer,
  bootstrap: DashboardBootstrap,
  current: boolean,
  evaluatedAt: string,
): LayerAssuranceLabel {
  const computed = layerAssuranceLabel(
    layer,
    bootstrap.capabilities,
    bootstrap.assurance_matrix,
    posture.generated_at,
    bootstrap.generated_at,
    evaluatedAt,
    bootstrap.platform.os,
    current,
  );
  return heldAssurance(posture, layer, computed, current, { bootstrap, evaluatedAt });
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
  // The host counts the dispositions it SENT. A chip the assurance veto
  // softened shows another state, so the host's sentence then counts states
  // the chips below it do not show: "3 protecting" over one "Protecting" and
  // two "Containing, not proven". The page is only checkable when its
  // headline and its chips come from the same states, so the host's sentence
  // leads only while no chip moved away from what it counted.
  const fromHost = hostSummary?.trim();
  if (fromHost && !pills.some((pill) => pill.softened)) return fromHost;
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
  // Counted apart from the plainly working ones because the chip is apart:
  // "Containing, not proven" is a control the host says contains, whose proof
  // this page could not pin, not one that merely does what it was set to.
  const unproven = pills.filter((pill) => pill.disposition === "working_as_configured" && pill.softened).length;
  const working = pills.filter((pill) => pill.disposition === "working_as_configured" && !pill.softened).length;

  const parts: string[] = [];
  if (protecting > 0) parts.push(`${protecting} protecting`);
  if (unproven > 0) parts.push(`${unproven} containing but not proven`);
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

/**
 * The host's own count of the controls it just described.
 *
 * Printed beside the rows so a reader can check one against the other by
 * looking, which is the reason the host ships the numbers at all. It is a
 * caption, never the headline: the headline is the host's `summary` and this
 * line does not get to compete with it.
 *
 * Null on a producer that sends neither number, because the alternative is this
 * screen inventing a count of "actively containing" from pills that answer a
 * different question.
 */
export function controlCountLine(
  posture: Pick<DashboardPosture, "enforcing_count" | "control_count">,
): string | null {
  const enforcing = posture.enforcing_count;
  const total = posture.control_count;
  if (enforcing === undefined || total === undefined) return null;
  return `The host counts ${enforcing} of ${total} control${total === 1 ? "" : "s"} actively containing.`;
}

// ───────────────────── what runs inside the agent, kept apart ────────────────
//
// Two sections below the host controls, and they are separate on purpose. The
// page footer's rule is correct and stays: host controls are evaluated from host
// evidence only, and agent metadata never grants host trust. The on-device model
// runs in the agent's process and the guardrail's figures are the guardrail's own
// account of itself, so neither is host evidence and neither may touch a host
// control's state, colour, or the summary line above.
//
// They are here because the page a buyer opens to ask "is it all working" did
// not contain the feature they bought: the shipped bundle held no occurrence of
// `local_model` or `agent_layer` at all, on hosts that send both.

/**
 * One line of a section: a number the host measured, or a gap the host named.
 *
 * A gap is NEVER a number. Rendering "how often the model agreed with the
 * deterministic rules" as `0` would print a measurement nobody took, on the one
 * page whose job is telling proven from assumed apart.
 */
export type SectionRow =
  | { kind: "measured"; id: string; label: string; value: string; covers: string }
  | { kind: "not_measured"; reason: string };

export function sectionRows(report: { measured: MeasuredValue[]; not_measured: string[] }): SectionRow[] {
  return [
    ...report.measured.map((entry) => ({ kind: "measured" as const, ...entry })),
    ...report.not_measured.map((reason) => ({ kind: "not_measured" as const, reason })),
  ];
}

const isMeasured = (row: SectionRow): row is Extract<SectionRow, { kind: "measured" }> => row.kind === "measured";
const isNotMeasured = (row: SectionRow): row is Extract<SectionRow, { kind: "not_measured" }> => row.kind === "not_measured";

/**
 * Which of the three answers the guardrail section is giving.
 *
 * They must never collapse into one empty state. A host whose record was READ
 * and holds nothing gets its zeroes printed, because a zero it measured is a
 * fact. A host whose record could not be OPENED gets no figures at all, because
 * a zero there would report a quiet host to somebody whose files merely could
 * not be read. A fresh install gets neither treatment: nothing has been written
 * yet, and that is not a fault.
 *
 * The label is structure, not a claim. Every sentence in this section, including
 * the basis line, is the host's own wording rendered verbatim.
 */
export type AgentLayerFigures =
  | { kind: "counted" }
  | { kind: "nothing_recorded"; label: string }
  | { kind: "unreadable"; label: string };

export function agentLayerFigures(report: Pick<AgentLayerReport, "state">): AgentLayerFigures {
  switch (report.state) {
    case "screening":
      return { kind: "counted" };
    case "no_decisions_yet":
      return { kind: "nothing_recorded", label: "Nothing recorded yet" };
    case "record_unreadable":
      return { kind: "unreadable", label: "Record could not be read" };
  }
}

/** Which build of the model answered, when the host could tell two apart. */
export function modelProvenance(report: Pick<LocalModelReport, "provider" | "model_id">): string | null {
  const parts: string[] = [];
  if (report.provider) parts.push(`provider ${report.provider}`);
  if (report.model_id) parts.push(`build ${report.model_id}`);
  return parts.length > 0 ? parts.join(" · ") : null;
}

/**
 * The quiet line shown when no gap card needs to render.
 *
 * It answers for what was actually examined, and it used to answer for more.
 * "No coverage gaps in this snapshot" reads as a statement about everything the
 * product watches, and it rendered on a host with a detector switched off and
 * four telemetry streams silent. `posture.gaps` is the host controls' own
 * `known_gaps` flattened by the producer: it is the enforcement chain auditing
 * itself, and it has no field that can carry the state of a sensor collector.
 * A sentence must not answer a question its data cannot reach, so this one now
 * names its subject, and what it leaves out is said behind the switch
 * (`GAPS_SCOPE_NOTE`).
 *
 * When the producer starts publishing collector coverage as gaps, this line is
 * the thing to widen, not before.
 */
export function emptyGapsLine(totalGaps: number): string {
  return totalGaps === 0
    ? "No gaps reported by the host controls above."
    : "No gaps in the host controls above need your attention.";
}

/**
 * What the check leaves out, said to whoever audits it: the line above
 * names its subject (the host controls), so this is the provenance of a
 * good state and sits behind the switch. On the paid screen the sensor's
 * collectors follow directly.
 */
export const GAPS_SCOPE_NOTE = "Sensor collector state is not part of this check.";

/**
 * What the section says when the last posture refresh failed and the page is
 * showing an older read. Measured on the challenge box (2026-09-27): a failed
 * refresh emptied the list of controls the page cannot confirm, and the
 * section fell through to "No gaps in the host controls above need your
 * attention" under a DNS Guard reading "Can't confirm". A read that is not
 * current can say what it last saw, never that nothing is wrong.
 */
export function staleGapsLine(): string {
  return "The host's controls could not be read again just now, so this page cannot say there are no gaps. The cards above are the last read.";
}

/**
 * The controls whose state this page cannot confirm: ones reading "Can't
 * confirm", and ones claimed as working or protecting that were never
 * checked. A control that is off was never checked because it is off, which
 * is not a gap.
 *
 * "Coverage gaps: No gaps reported" sat under "DNS Guard · Can't confirm ·
 * never checked", and a buyer read it as: the DNS Guard I paid for is
 * unchecked, and there are no gaps. `posture.gaps` is what the host listed;
 * what the page itself cannot vouch for is a gap all the same.
 */
export function unconfirmedControls(layers: readonly ProtectionLayer[], pills: readonly ControlPill[]): string[] {
  return layers.flatMap((layer, index) => {
    const pill = pills[index];
    if (pill === undefined) return [];
    const neverChecked = layer.freshness.observed_at === null || layer.freshness.observed_at === undefined;
    const claimed = pill.disposition === "proven" || pill.disposition === "working_as_configured";
    return pill.disposition === "cannot_verify" || (neverChecked && claimed) ? [pill.name] : [];
  });
}

/** "1 control we can't confirm: DNS Guard. We will not claim it either way." */
export function unconfirmedLine(names: readonly string[]): string {
  const one = names.length === 1;
  const listed = names.length <= 2
    ? names.join(" and ")
    : `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
  return `${names.length} control${one ? "" : "s"} we can't confirm: ${listed}. We will not claim ${one ? "it" : "them"} either way.`;
}

/**
 * Every control's chip for one read, and the assurance each chip was drawn
 * from: the one computation this page's ring, counts and rows share, and the
 * one a paid Overview tile calls too, with the veto and the held verification
 * applied, so no two surfaces can tell two stories about the same read.
 */
export function controlPills(
  posture: DashboardPosture,
  bootstrap: DashboardBootstrap,
  current: boolean,
  evaluatedAt: string,
): { assurances: LayerAssuranceLabel[]; pills: ControlPill[] } {
  const assurances = posture.layers.map((layer) => assuranceFor(posture, layer, bootstrap, current, evaluatedAt));
  const pills = posture.layers.map((layer, index) =>
    controlPill(layer, bootstrap, posture.generated_at, current, evaluatedAt, assurances[index]));
  return { assurances, pills };
}

/** How many controls wear each chip. */
export type StateCount = {
  key: "proven" | "softened" | "working" | "not_enabled" | "cannot_verify" | "needs_operator";
  count: number;
  label: string;
};

/**
 * One count per state that has a control in it, in the order a reader
 * weighs them, and the controls that need the reader ALWAYS, so a zero is
 * seen rather than inferred. A softened control is counted apart, because
 * its chip is apart ("Containing, not proven").
 */
export function stateCounts(pills: readonly ControlPill[]): StateCount[] {
  const count = (test: (pill: ControlPill) => boolean) => pills.filter(test).length;
  const needing = count((pill) => pill.disposition === "needs_operator");
  const counts: StateCount[] = [
    { key: "proven", count: count((pill) => pill.disposition === "proven"), label: "Protecting" },
    { key: "softened", count: count((pill) => pill.disposition === "working_as_configured" && pill.softened), label: "Containing, not proven" },
    { key: "working", count: count((pill) => pill.disposition === "working_as_configured" && !pill.softened), label: "Working as set up" },
    { key: "not_enabled", count: count((pill) => pill.disposition === "not_enabled"), label: "Not turned on" },
    { key: "cannot_verify", count: count((pill) => pill.disposition === "cannot_verify"), label: "Can't confirm" },
  ];
  return [
    ...counts.filter((entry) => entry.count > 0),
    { key: "needs_operator", count: needing, label: needing === 1 ? "Needs you" : "Need you" },
  ];
}

/**
 * The ring's segments: one per control, in the order the host sent them,
 * each the colour of the chip it wears after the veto. Only a proven control
 * is emerald; one this page cannot confirm is an outline, never a fill; a
 * read that is not current is all grey.
 */
export function ringParts(pills: readonly ControlPill[], current: boolean): Part[] {
  return pills.map((pill, index): Part => {
    const base = { key: String(index), value: 1, label: `${pill.name}: ${pill.mode}` };
    if (!current) return { ...base, tone: "off" };
    switch (pill.disposition) {
      case "proven":
        return { ...base, tone: "proven" };
      case "working_as_configured":
        return { ...base, tone: "working" };
      case "needs_operator":
        return { ...base, tone: "attention" };
      case "cannot_verify":
        return { ...base, tone: "unknown", hollow: true };
      default:
        return { ...base, tone: "off" };
    }
  });
}

/** When the newest of the controls was checked, or nothing when none was. */
export function latestCheck(layers: readonly Pick<ProtectionLayer, "freshness">[]): string | undefined {
  let latest: string | undefined;
  for (const layer of layers) {
    const at = layer.freshness.observed_at;
    if (typeof at === "string" && Number.isFinite(Date.parse(at)) && (latest === undefined || Date.parse(at) > Date.parse(latest))) latest = at;
  }
  return latest;
}

const COUNT_CHIP: Record<StateCount["key"], string> = {
  proven: "border-emerald-200 bg-emerald-50 text-emerald-900",
  softened: "border-cyan-200 bg-cyan-50 text-cyan-900",
  working: "border-cyan-200 bg-cyan-50 text-cyan-900",
  not_enabled: "border-slate-200 bg-slate-50 text-slate-700",
  cannot_verify: "border-dashed border-slate-400 bg-white text-slate-700",
  needs_operator: "border-slate-200 bg-white text-slate-600",
};

const COUNT_DOT: Record<StateCount["key"], string> = {
  proven: "bg-emerald-500",
  softened: "bg-cyan-600",
  working: "bg-cyan-600",
  not_enabled: "bg-slate-200",
  cannot_verify: "border border-dashed border-slate-400",
  needs_operator: "bg-amber-500",
};

/**
 * The verdict: the ring of controls, the host's headline, a count per state
 * as the ring's legend, and, beside them, when it was checked and the button
 * that checks again: the refresh sits with the verdict it refreshes.
 */
function PostureHero({ pills, current, posture, onCheckNow, children }: { pills: ControlPill[]; current: boolean; posture: DashboardPosture; onCheckNow?: () => void | Promise<void>; children: ReactNode }) {
  const [technical] = useTechnicalDetail();
  const total = pills.length;
  const needing = pills.filter((pill) => needsOperator(pill.disposition)).length;
  const working = pills.filter((pill) => pill.disposition === "proven" || pill.disposition === "working_as_configured").length;
  const checked = latestCheck(posture.layers);
  const clock = checked === undefined ? undefined : formatClock(checked, new Date(), technical ? "UTC" : undefined);
  const ringLabel = !current
    ? `${total} host controls, refreshing`
    : needing > 0
      ? `${needing} of ${total} host controls need you`
      : `${working} of ${total} host controls working`;
  return (
    <div className="flex flex-col items-center gap-5 px-5 py-5 sm:flex-row sm:items-center sm:gap-7 sm:px-6">
      <Ring parts={ringParts(pills, current)} size={144} stroke={12} label={ringLabel}>
        {!current ? (
          <span className="text-sm font-semibold text-slate-500">Refreshing</span>
        ) : needing > 0 ? (
          <>
            <span className="text-4xl font-semibold text-amber-600">{needing}</span>
            <span className="mt-0.5 text-xs font-medium text-amber-800">{needing === 1 ? "needs you" : "need you"}</span>
          </>
        ) : (
          <>
            <span className="text-4xl font-semibold text-slate-950">{working}</span>
            <span className="mt-0.5 text-xs font-medium text-slate-500">of {total} working</span>
          </>
        )}
      </Ring>
      <div className="min-w-0 flex-1">
        <h3 id="posture-verdict-title" className="text-xl font-semibold tracking-tight text-slate-950 sm:text-2xl">
          {children}
        </h3>
        <ul className="mt-3 flex flex-wrap gap-2" aria-label="Host controls">
          {current
            ? stateCounts(pills).map((entry) => (
              <li
                key={entry.key}
                data-state={entry.key}
                className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${
                  entry.key === "needs_operator" && entry.count > 0 ? "border-amber-200 bg-amber-50 text-amber-900" : COUNT_CHIP[entry.key]
                }`}
              >
                {entry.key === "needs_operator" && entry.count === 0 ? null : (
                  <span aria-hidden="true" className={`h-2 w-2 shrink-0 rounded-full ${COUNT_DOT[entry.key]}`} />
                )}
                <span className="font-semibold tabular-nums">{entry.count}</span> {entry.label}
              </li>
            ))
            : <li className="inline-flex rounded-full border border-slate-200 bg-white px-2.5 py-0.5 text-xs font-medium text-slate-600">Refreshing</li>}
        </ul>
        {/* The host's own count, never replacing the headline. It is a
            second count from a second source, and beside the headline in
            the plain view it read as a second verdict; it stays for
            whoever checks one against the other. */}
        {controlCountLine(posture) ? (
          <TechnicalOnly>
            <p className="mt-2 text-xs leading-5 text-slate-500">{controlCountLine(posture)}</p>
          </TechnicalOnly>
        ) : null}
      </div>
      <div className="flex shrink-0 items-center gap-3">
        {/* The page refreshes on a slow cadence, because the evidence
            behind it does. An operator who wants an answer this second asks
            for one instead of waiting out a poll whose length they cannot
            see. */}
        {onCheckNow ? <CheckNowButton onCheckNow={onCheckNow} /> : null}
        <p className="text-xs text-slate-500">
          {current ? (clock === undefined ? "Not checked yet." : `Checked ${clock}.`) : "Reading the host again."}
        </p>
      </div>
    </div>
  );
}

function CheckNowButton({ onCheckNow }: { onCheckNow: () => void | Promise<void> }) {
  return (
    <button
      type="button"
      onClick={() => void onCheckNow()}
      className="shrink-0 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-600"
    >
      Check now
    </button>
  );
}

/**
 * The host's sentence with each backticked command drawn as code, so a
 * command the reader runs looks like one, and no backtick is printed.
 */
export function withCode(sentence: string): ReactNode[] {
  return sentence.split(/`([^`]+)`/).map((part, index) =>
    index % 2 === 1 ? (
      // A short command or name is one unbroken chip ("challenge-" over
      // "agent.service" read as two things on a phone); only a long one may
      // break, anywhere, to fit.
      <code key={index} className={`rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[0.85em] text-slate-800 ${part.length <= CODE_UNBROKEN_MAX ? "whitespace-nowrap" : "[overflow-wrap:anywhere]"}`}>{part}</code>
    ) : (
      part
    ));
}

/** The longest command or name a code chip keeps on one line. */
export const CODE_UNBROKEN_MAX = 32;

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
  // One assurance per control for this read, shared by its segment of the
  // ring, its row and the headline, so the three cannot tell different stories.
  const { assurances, pills } = controlPills(posture, bootstrap, current, evaluatedAt);
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
  // A control the page cannot confirm is a gap in what it can say, even
  // when the host listed none for it: the section said "No gaps" under a
  // DNS Guard reading "Can't confirm · never checked".
  const unconfirmed = current ? unconfirmedControls(posture.layers, pills) : [];
  // The one line alone sits beside its heading on a wide screen: a card
  // around a single sentence read as a second verdict. Amber gap cards keep
  // their own layout.
  const compactGaps = operatorGaps.length === 0 && unconfirmed.length > 0;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.16em] text-cyan-700">Protection posture</p>
          <h2 className="mt-1 text-xl font-semibold tracking-tight text-slate-950">Host controls</h2>
          <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-600">
            What is enforcing, what is watching, and where the gaps are.
          </p>
        </div>
        {/* With a verdict the button sits beside it (`PostureHero`); with no
            control reported there is none, and it stays up here. */}
        {onCheckNow && posture.layers.length === 0 ? <CheckNowButton onCheckNow={onCheckNow} /> : null}
      </div>

      {posture.layers.length > 0 ? (
        <section data-tour="posture" aria-labelledby="posture-verdict-title" className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm">
          <PostureHero pills={pills} current={current} posture={posture} onCheckNow={onCheckNow}>
            {postureHeadline(pills, posture.summary)}
          </PostureHero>
        </section>
      ) : (
        <p className="rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-sm leading-6 text-slate-600">
          No host controls reported in this snapshot.
        </p>
      )}

      <section aria-labelledby="posture-controls-title">
        <h3 id="posture-controls-title" className="sr-only">Control details</h3>
        {posture.layers.length > 0 ? (
          <>
            {/* The five stages once, over the column every row's ladder sits
                in, so the ladders read as one matrix. Under lg the rows
                stack, and the stages are named once above them instead. */}
            <div aria-hidden="true" className="hidden px-4 pb-1.5 lg:flex lg:items-end lg:gap-6">
              <span className="flex-1" />
              <span className="w-48" />
              <span className="grid w-72 grid-cols-5 text-center text-[11px] font-medium text-slate-500">
                {STAGES.map(([, label]) => <span key={label}>{label}</span>)}
              </span>
              <span className="w-32" />
            </div>
            <p aria-hidden="true" className="pb-1.5 text-[11px] font-medium text-slate-500 lg:hidden">
              {STAGES.map(([, label]) => label).join(" › ")}
            </p>
          </>
        ) : null}
        <div className="space-y-2">
          {posture.layers.map((layer, index) => (
            <ControlRow
              key={layer.id}
              layer={layer}
              bootstrap={bootstrap}
              current={current}
              assurance={assurances[index]}
              evaluatedAt={evaluatedAt}
              latestCheckedAt={latestCheck(posture.layers)}
            />
          ))}
        </div>
        <TechnicalOnly>
          <p className="mt-3 text-xs leading-5 text-slate-500">
            Host controls are evaluated from host evidence only; agent metadata never grants host trust.
          </p>
        </TechnicalOnly>
      </section>

      <section aria-labelledby="posture-gaps-title" className={compactGaps ? "sm:flex sm:items-baseline sm:gap-4" : undefined}>
        <div className={compactGaps ? "mb-1 shrink-0 sm:mb-0" : "mb-2"}>
          <h2 id="posture-gaps-title" className={`${compactGaps ? "text-base" : "text-lg"} font-semibold tracking-tight text-slate-950`}>Coverage gaps</h2>
        </div>
        {operatorGaps.length > 0 ? (
          <div className="space-y-3">{operatorGaps.map((gap) => <GapCard key={gap.id} gap={gap} />)}</div>
        ) : null}
        {unconfirmed.length > 0 ? (
          <p
            data-unconfirmed-controls
            className={compactGaps
              ? "flex min-w-0 items-start gap-2 text-sm leading-6 text-slate-700"
              : `${operatorGaps.length > 0 ? "mt-3 " : ""}rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm leading-6 text-slate-700`}
          >
            {compactGaps ? (
              <span aria-hidden="true" className="mt-1 flex h-4 w-4 shrink-0 items-center justify-center rounded-full border border-dashed border-slate-400 text-[10px] font-semibold text-slate-500">?</span>
            ) : null}
            <span className="min-w-0">{unconfirmedLine(unconfirmed)}</span>
          </p>
        ) : null}
        {operatorGaps.length === 0 && unconfirmed.length === 0 ? (
          <p className="text-sm leading-6 text-slate-600">
            {current ? emptyGapsLine(posture.gaps.length) : staleGapsLine()}
            {current ? <TechnicalOnly>{` ${GAPS_SCOPE_NOTE}`}</TechnicalOnly> : null}
          </p>
        ) : null}
      </section>

      {/* Below the host controls, and outside them. A producer that sends
          neither renders everything above and nothing here, unchanged. Side
          by side on a wide screen, each holding its own figure. */}
      <AgentBand>
        {posture.local_model ? <LocalModelSection report={posture.local_model} /> : null}
        {posture.agent_layer ? <AgentLayerSection report={posture.agent_layer} commands={posture.agent_commands} /> : null}
      </AgentBand>
    </div>
  );
}

/**
 * The agent-side sections as one band: side by side on a wide screen when
 * there are two, each holding its own figure; nothing at all when there are
 * none. It reads only what it is handed, never the posture.
 */
function AgentBand({ children }: { children: ReactNode }) {
  const [technical] = useTechnicalDetail();
  const sections = Children.toArray(children);
  if (sections.length === 0) return null;
  // Side by side only in the plain view, where each card holds one figure
  // and the two end together. The technical view adds the screening's
  // record to one of them, and a grid row stretched the other to its height:
  // 757 px of empty card on the challenge box.
  return <div data-agent-band={technical ? "stacked" : "paired"} className={sections.length > 1 ? `grid gap-4 ${technical ? "" : "lg:grid-cols-2"}` : undefined}>{sections}</div>;
}

/** The chrome both agent-side sections share, so the separation from the host
 *  controls is one decision rather than two that can drift. */
function AgentSideSection({
  titleId,
  title,
  children,
}: {
  titleId: string;
  title: string;
  children: ReactNode;
}) {
  return (
    <section
      aria-labelledby={titleId}
      className="rounded-2xl border border-dashed border-slate-300 bg-slate-50/70 p-4 sm:p-5"
    >
      <p className="text-xs font-semibold uppercase tracking-[0.16em] text-slate-500">
        In the agent, not a host control
      </p>
      <h2 id={titleId} className="mt-1 text-xl font-semibold tracking-tight text-slate-950">{title}</h2>
      {children}
    </section>
  );
}

/**
 * How a section's measured figures are laid out: a tile for each figure that
 * reads something, one line naming every figure that reads zero, and the
 * population they cover said once when they share one.
 *
 * Seven tiles, six of them zero, each repeating the same forty-word caption,
 * made the guardrail's section most of a screen tall and said one thing seven
 * times. A zero is still printed, as a zero, in the line: a figure the host
 * measured never disappears, it just stops taking a tile.
 */
export type FigureLayout = {
  tiles: Extract<SectionRow, { kind: "measured" }>[];
  zeros: Extract<SectionRow, { kind: "measured" }>[];
  /** The population every figure covers, when they all cover the same one. */
  sharedCovers?: string;
};

export function figureLayout(rows: SectionRow[]): FigureLayout {
  const measured = rows.filter(isMeasured);
  const covers = new Set(measured.map((row) => row.covers));
  const [only] = covers;
  const sharedCovers = covers.size === 1 && only !== undefined && only.trim() !== "" ? only : undefined;
  return {
    tiles: measured.filter((row) => row.value.trim() !== "0"),
    zeros: measured.filter((row) => row.value.trim() === "0"),
    ...(sharedCovers === undefined ? {} : { sharedCovers }),
  };
}

/**
 * The zeros, by label. With no caption shared by the whole section, the ones
 * that share a population are listed together and it is said once after
 * them: "A; B (today)".
 */
export function zeroLine(zeros: Extract<SectionRow, { kind: "measured" }>[], captionSaidElsewhere: boolean): string {
  if (captionSaidElsewhere) return zeros.map((row) => row.label).join("; ");
  const groups = new Map<string, string[]>();
  for (const row of zeros) groups.set(row.covers, [...(groups.get(row.covers) ?? []), row.label]);
  return [...groups].map(([covers, labels]) => `${labels.join("; ")} (${covers})`).join("; ");
}

/** The numbers the host measured, and the gaps it named, kept apart on screen
 *  the way `sectionRows` keeps them apart in the data. */
function SectionFigures({ rows }: { rows: SectionRow[] }) {
  const layout = figureLayout(rows);
  const notMeasured = rows.filter(isNotMeasured);
  const shared = layout.sharedCovers;
  return (
    <>
      {layout.tiles.length > 0 ? (
        <dl className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {layout.tiles.map((row) => (
            <div key={row.id} className="rounded-xl border border-slate-200 bg-white px-3 py-2">
              <dt className="text-xs font-medium text-slate-500">{row.label}</dt>
              <dd className="mt-0.5 text-2xl font-semibold text-slate-950">{row.value}</dd>
              {/* The population, in the host's words. A count without one is how
                  a decision total gets read as a claim about enforcement. Said
                  once under the figures when every figure shares it. */}
              {shared === undefined ? <dd className="mt-1 text-[11px] leading-4 text-slate-500">{row.covers}</dd> : null}
            </div>
          ))}
        </dl>
      ) : null}
      {/* A figure the host measured at zero never disappears. Beside tiles
          that read something, a line of them restated nothing a reader acts
          on: it is the provenance of the tiles, one switch away. With no
          tile at all, the zeros are the section's figures and stay. */}
      {layout.zeros.length > 0 ? (
        layout.tiles.length > 0 ? (
          <TechnicalOnly>
            <ZeroLine text={zeroLine(layout.zeros, shared !== undefined)} />
          </TechnicalOnly>
        ) : (
          <ZeroLine text={zeroLine(layout.zeros, shared !== undefined)} />
        )
      ) : null}
      {shared !== undefined && (layout.tiles.length > 0 || layout.zeros.length > 0) ? (
        <p className="mt-1 text-[11px] leading-4 text-slate-500">What these cover: {shared}.</p>
      ) : null}
      {notMeasured.length > 0 ? <NotMeasuredNote count={notMeasured.length} /> : null}
      {notMeasured.length > 0 ? (
        // What the host could not measure is its own account of its limits:
        // evidence for whoever audits the figures, not an answer, so the list
        // sits behind the switch. It is never a zero standing in for a figure.
        <TechnicalOnly>
          <div className="mt-3">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Not measured</h3>
            <ul className="mt-2 space-y-1">
              {notMeasured.map((row) => (
                <li key={row.reason} className="text-xs leading-5 text-slate-600">{row.reason}</li>
              ))}
            </ul>
          </div>
        </TechnicalOnly>
      ) : null}
    </>
  );
}

function ZeroLine({ text }: { text: string }) {
  return (
    <p className="mt-2 text-xs leading-5 text-slate-600">
      <span className="font-semibold text-slate-700">Zero: </span>
      {text}.
    </p>
  );
}

/** "2 figures are not measured on this host." */
export function notMeasuredLine(count: number): string {
  return count === 1 ? "1 figure is not measured on this host." : `${count} figures are not measured on this host.`;
}

/**
 * In the plain view, that something is not measured, and the way to the
 * list. The list is the auditor's; that there is one is everyone's: a page
 * that hid it would hide the existence of a gap, which the switch never may.
 */
function NotMeasuredNote({ count }: { count: number }) {
  const [technical] = useTechnicalDetail();
  if (technical) return null;
  return (
    <p data-not-measured className="mt-2 text-xs leading-5 text-slate-600">
      {notMeasuredLine(count)}{" "}
      <button
        type="button"
        onClick={() => setTechnicalDetail(true)}
        className="font-semibold text-cyan-700 underline decoration-cyan-300 underline-offset-2 hover:text-cyan-900"
      >
        Show which
      </button>
    </p>
  );
}

function LocalModelSection({ report }: { report: LocalModelReport }) {
  const provenance = modelProvenance(report);
  return (
    <AgentSideSection titleId="posture-local-model-title" title={report.display_name}>
      <p className="mt-2 text-sm leading-6 text-slate-700">{report.summary}</p>
      {provenance ? (
        <TechnicalOnly>
          <p className="mt-1 [overflow-wrap:anywhere] text-xs text-slate-500">{provenance}</p>
        </TechnicalOnly>
      ) : null}
      {report.roles.length > 0 ? (
        <ul className="mt-3 flex flex-wrap gap-2" aria-label="What this model does">
          {report.roles.map((role) => (
            <li key={role} className="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs text-slate-700">{role}</li>
          ))}
        </ul>
      ) : null}
      <SectionFigures rows={sectionRows(report)} />
    </AgentSideSection>
  );
}

/**
 * The agent's commands over the card's window, drawn: the count the
 * Overview's agent card prints, the split of it as a bar with its legend,
 * the parts that read zero said once, and the program starts the kernel
 * refused that no command explains.
 */
function AgentCommandsFigure({ commands }: { commands: AgentCommands }) {
  const zeros = commands.breakdown.filter((part) => part.count === 0);
  const refused = commands.unexplainedRefused ?? 0;
  return (
    <div className="mt-3">
      <p className="flex flex-wrap items-baseline gap-x-2">
        <span data-agent-commands-count className="text-4xl font-semibold text-slate-950">{formatCount(commands.count)}</span>
        {" "}
        <span className="text-sm text-slate-500">{commands.count === 1 ? "command" : "commands"} {LANE_WINDOW_PHRASE[commands.window]}</span>
      </p>
      {commands.count > 0 ? (
        <OutcomeBreakdown parts={commands.breakdown} label={`What happened to each of the ${formatCount(commands.count)} commands`} className="mt-4" />
      ) : null}
      {commands.count > 0 && zeros.length > 0 ? (
        <TechnicalOnly>
          <p className="mt-2 text-xs leading-5 text-slate-500">
            <span className="font-semibold text-slate-600">Zero: </span>
            {zeros.map((part) => part.label).join("; ")}.
          </p>
        </TechnicalOnly>
      ) : null}
      {refused > 0 ? (
        <p className="mt-3 text-sm leading-6 text-slate-700">
          The kernel also refused {formatCount(refused)} program {refused === 1 ? "start" : "starts"} in the agent's scope that no command explains.
        </p>
      ) : null}
    </div>
  );
}

function AgentLayerSection({ report, commands }: { report: AgentLayerReport; commands?: AgentCommands }) {
  const figures = agentLayerFigures(report);
  const notMeasured = report.not_measured.length;
  return (
    <AgentSideSection titleId="posture-agent-layer-title" title={report.display_name}>
      {/* With the host's tally the section leads with it, drawn; the host's
          sentence says the same facts in words and moves behind the switch
          with the record's own figures. Without it, as before. */}
      {commands ? (
        <AgentCommandsFigure commands={commands} />
      ) : (
        <p className="mt-2 text-sm leading-6 text-slate-700">{report.summary}</p>
      )}
      {/* Three states, three renders. A record that was read and holds zeroes
          keeps its zeroes; a record that could not be opened shows no figure at
          all, with the cause the host named. */}
      {figures.kind === "counted" ? null : (
        <p className="mt-3 flex flex-wrap items-center gap-2 text-xs">
          <span className="rounded-full border border-slate-300 bg-white px-3 py-1 font-semibold text-slate-700">
            {figures.label}
          </span>
          <span className="[overflow-wrap:anywhere] text-slate-500">{report.reason}</span>
        </p>
      )}
      {commands ? (
        <>
          {notMeasured > 0 ? <NotMeasuredNote count={notMeasured} /> : null}
          <TechnicalOnly>
            <p className="mt-4 border-t border-slate-200 pt-3 text-sm leading-6 text-slate-700">{report.summary}</p>
            <SectionFigures rows={sectionRows(report)} />
          </TechnicalOnly>
        </>
      ) : (
        <SectionFigures rows={sectionRows(report)} />
      )}
      {/* The session ids, the record's basis and its file are the evidence
          behind the figures, for whoever audits them. The section's eyebrow
          already says, in the plain view, that none of it is a host control. */}
      <TechnicalOnly>
        {report.sessions.length > 0 ? (
          <div className="mt-4">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">Agent sessions in the record</h3>
            <ul className="mt-2 flex flex-wrap gap-2" aria-label="Agent sessions in the record">
              {report.sessions.map((session) => (
                <li key={session} className="[overflow-wrap:anywhere] rounded-lg border border-slate-200 bg-white px-2.5 py-1 font-mono text-[11px] text-slate-700">{session}</li>
              ))}
            </ul>
          </div>
        ) : null}
        {/* The host ships this sentence so the section cannot be rendered
            without it. Printed as sent: the screen does not write its own. */}
        <p className="mt-4 border-t border-slate-200 pt-3 text-xs leading-5 text-slate-500">{report.evidence_basis}</p>
        {report.evidence_source ? (
          <p className="mt-1 [overflow-wrap:anywhere] font-mono text-[11px] text-slate-500">{report.evidence_source}</p>
        ) : null}
      </TechnicalOnly>
    </AgentSideSection>
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
  current,
  assurance,
  evaluatedAt,
  latestCheckedAt,
}: {
  layer: ProtectionLayer;
  bootstrap: DashboardBootstrap;
  current: boolean;
  /** The same assurance the chip for this control was drawn from. */
  assurance: LayerAssuranceLabel;
  /** The consumer's clock this render was judged at. */
  evaluatedAt: string;
  /** The newest check of any control, the one the hero states. */
  latestCheckedAt?: string;
}) {
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

  const name = controlName(layer);
  const softened = claimSoftened(layer, assurance.verifiedActive);
  const glyph = controlGlyph([layer.id, ...layer.capability_ids]);
  const scoped = layer.effective_scope.some((scope) => scope.kind !== "host");
  const [technical] = useTechnicalDetail();
  const reason = dispositionReason(layer, disposition);
  // The time of this row's check only where it says something: a check more
  // than 5 minutes older than the newest one the hero states. Beside the
  // hero's "Checked 14:56", five rows of "as of 14:56" said it five times.
  const lagging = checkedLate(layer.freshness.observed_at, latestCheckedAt);
  return (
    <article className="rounded-2xl border border-slate-200 bg-white px-4 py-3 shadow-sm">
      {/* The badge, the ladder and the time sit on the title's line, so the
          ladders of every row read down the page as one matrix; centred on
          a title with a description and a scope under it they sat 25 px
          lower than on a row with neither. */}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 lg:flex-nowrap lg:items-start lg:gap-6">
        {/* A basis of its own, so on a narrow screen the title takes the
            row and the badge and time wrap under it. With a basis of zero it
            stayed beside them, shrank to what they left (26 px at 320) and
            broke "Execution Gate" into a column of fragments. */}
        <div className="flex min-w-0 flex-[1_1_100%] items-start gap-3 lg:flex-1">
          {glyph === undefined ? null : (
            <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-700">
              <Glyph name={glyph} />
            </span>
          )}
          <div className="min-w-0 flex-1">
            <h3 className="break-words text-base font-semibold leading-8 text-slate-950">{name.name}</h3>
            {/* What the product name stands for, for whoever maps it to the
                capability: not every row has one, and on some rows it only
                pushed the rest down. */}
            {name.description === undefined ? null : (
              <TechnicalOnly>
                <p className="text-xs text-slate-500">{name.description}</p>
              </TechnicalOnly>
            )}
            {/* The scope, plainly, only where it is narrower than the host:
                "this host" on every other row said nothing. */}
            {scoped ? (
              <p className="break-words text-xs text-slate-600 [overflow-wrap:anywhere]">
                <span className="text-slate-500">Covers </span>
                {withCode(scopeDisplay(layer.effective_scope))}
              </p>
            ) : null}
          </div>
        </div>
        <div className="flex min-w-0 flex-1 items-center justify-between gap-3 lg:contents">
          <span className="lg:flex lg:h-8 lg:w-48 lg:shrink-0 lg:items-center">
            <ControlBadge status={current ? disposition : "stale"} label={current ? dispositionLabel(disposition, softened) : "Refreshing"} />
          </span>
          <span className="hidden lg:flex lg:h-8 lg:w-72 lg:shrink-0 lg:items-center">
            <Ladder layer={layer} name={name.name} current={current} softened={softened} />
          </span>
          <span
            data-checked-at={technical || lagging || !current ? "shown" : "same"}
            className="shrink-0 text-right text-xs font-medium text-slate-500 lg:flex lg:h-8 lg:w-32 lg:items-center lg:justify-end"
            title={current && layer.freshness.observed_at ? timeTitle(layer.freshness.observed_at) : undefined}
          >
            {!current ? "refreshing" : technical || lagging ? checkedAt(layer.freshness, new Date(), technical ? "UTC" : undefined) : null}
          </span>
        </div>
        <div className="w-full lg:hidden">
          <Ladder layer={layer} name={name.name} current={current} softened={softened} />
        </div>
      </div>
      {technical && current ? <StageReasons convergence={layer.convergence} /> : null}

      {/* The sentence, on the row, not one click away, where it says more
          than the badge and the ladder do: a command to run, a control not
          on, one this page cannot confirm or one that needs the reader.
          Someone installing this for the first time should not have to open
          a disclosure called "How this was verified" to learn that a grey
          control is grey because they have not turned it on yet. For a
          control protecting, or working as set up, it restated the badge;
          it is the provenance of that good state, one switch away. */}
      {current && (technical || reasonAddsToBadge(disposition, softened, reason)) ? (
        <p className="mt-2 text-sm leading-6 text-slate-600">{withCode(reason)}</p>
      ) : null}

      <details className="mt-2 border-t border-slate-100 pt-2">
        <summary className="cursor-pointer text-xs font-semibold text-slate-500 hover:text-slate-700">How this was verified</summary>
        <div className="mt-3 space-y-5">
          <div className="flex flex-wrap items-center gap-3">
            <StatusBadge
              status={current ? assurance.status : "stale"}
              label={!current
                ? "Awaiting a current snapshot"
                : assurance.verifiedAt === undefined
                  ? assurance.label
                  : heldVerifiedLabel(assurance.verifiedAt, Date.parse(evaluatedAt), technical ? "UTC" : undefined)}
            />
            <span className="text-xs text-slate-500">
              {layer.evidence.length} evidence record{layer.evidence.length === 1 ? "" : "s"} · {freshnessLabel(layer.freshness)}
            </span>
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
                    <span className="[overflow-wrap:anywhere] font-medium text-slate-800">{capabilityName(capability.id)}</span>
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

/**
 * A control's state on its row, in the colours its segment of the ring and
 * its count chip wear: emerald only for a proven control, cyan for one doing
 * what it was set up to do, amber only for one that needs the reader, an
 * outline for one this page cannot confirm.
 */
const CONTROL_BADGE: Record<LayerDisposition | "stale", string> = {
  proven: "border-emerald-200 bg-emerald-50 text-emerald-800",
  working_as_configured: "border-cyan-200 bg-cyan-50 text-cyan-800",
  needs_operator: "border-amber-200 bg-amber-50 text-amber-900",
  cannot_verify: "border-dashed border-slate-400 bg-white text-slate-700",
  not_enabled: "border-slate-200 bg-slate-50 text-slate-700",
  stale: "border-slate-200 bg-slate-50 text-slate-600",
};

function ControlBadge({ status, label }: { status: LayerDisposition | "stale"; label: string }) {
  return (
    <span data-status={status} className={`inline-flex w-fit max-w-full shrink-0 items-start gap-1.5 rounded-md border px-2.5 py-1 text-xs font-semibold leading-4 ${CONTROL_BADGE[status]}`}>
      <span className="shrink-0 font-bold" aria-hidden="true">{statusPresentation(status).symbol}</span>
      <span className="min-w-0 break-words">{label}</span>
    </span>
  );
}

/** The five stages a control is proven through, in order. */
export const STAGES = [
  ["configured", "Configured"],
  ["loaded", "Loaded"],
  ["running", "Running"],
  ["enforcing", "Enforcing"],
  ["verified_effective", "Verified"],
] as const satisfies readonly (readonly [keyof RuntimeConvergence, string])[];

/** How one stage is drawn: the shared ladder marks (`viz.tsx`), less the case's "waiting". */
export type StageMark = Exclude<StepMark, "waiting">;

/**
 * One stage's mark: a filled dot for a stage that is so, the Verified stage
 * emerald only when the chip agrees (a softened control's Verified is
 * hollow: the host says it, this page could not pin the proof), a hollow dot
 * for what is not known, a dash for a stage that does not apply, a red ring
 * for a factual No, and all hollow on a read that is not current.
 */
export function stageMark(state: RuntimeConvergence["configured"]["state"], verifiedStage: boolean, softened: boolean, current: boolean): StageMark {
  if (!current) return "stale";
  switch (state) {
    case "yes":
      if (!verifiedStage) return "done";
      return softened ? "unproven" : "verified";
    case "no":
      return "no";
    case "not_applicable":
      return "not_applicable";
    default:
      return "unknown";
  }
}

const STAGE_MARK_WORDS: Record<StageMark, string> = {
  done: "yes",
  verified: "yes, verified on this host",
  unproven: "the host reports it verified; this page could not pin the proof",
  unknown: "not known",
  not_applicable: "does not apply",
  no: "no",
  stale: "refreshing",
};

/**
 * How far a control is proven: five dots, joined where two neighbouring
 * stages are both so. Aligned into one matrix down the page on a wide screen.
 * The marks are the shared ladder's (`Steps`), so a case's ladder reads the
 * same.
 */
export function Ladder({ layer, name, current, softened }: { layer: Pick<ProtectionLayer, "convergence">; name: string; current: boolean; softened: boolean }) {
  const steps = STAGES.map(([key, label], index) => {
    const mark = stageMark(layer.convergence[key].state, index === STAGES.length - 1, softened, current);
    return { key, label, mark, words: STAGE_MARK_WORDS[mark] };
  });
  return <Steps steps={steps} label={`How far ${name} is proven`} />;
}

/** The host's reason for each stage that is not a plain yes, in words, for the technical view. */
function StageReasons({ convergence }: { convergence: RuntimeConvergence }) {
  const reasons = STAGES.flatMap(([key, label]) => {
    const stage = convergence[key];
    return stage.state !== "yes" && stage.reason_code ? [`${label}: ${humanize(stage.reason_code)}`] : [];
  });
  if (reasons.length === 0) return null;
  return <p className="mt-1.5 text-[11px] leading-4 text-slate-500 [overflow-wrap:anywhere]">{reasons.join(" · ")}</p>;
}

function GapCard({ gap }: { gap: CoverageGap }) {
  return (
    <article className="rounded-xl border border-amber-200 bg-amber-50/60 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <StatusBadge status={gap.state} />
          <h3 className="mt-2 [overflow-wrap:anywhere] font-semibold text-slate-950">{capabilityName(gap.capability_id)}</h3>
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

/** Words that are initials, spelled the way people write them. */
const INITIALISMS: Record<string, string> = { dns: "DNS", mcp: "MCP", ai: "AI", llm: "LLM", ssh: "SSH", bpf: "BPF", ebpf: "eBPF", lsm: "LSM", id: "ID", ip: "IP", tls: "TLS", tcp: "TCP", http: "HTTP", usb: "USB", suid: "SUID", aws: "AWS" };

/**
 * An id in words: `dns_resolution_control` reads "DNS resolution control",
 * never "Dns", and `ebpf` reads "eBPF", never "EBPF": an initialism keeps
 * its own spelling even as the first word.
 */
export function humanize(value: string): string {
  const words = value
    .replace(/[._-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .split(" ")
    .filter((word) => word !== "");
  if (words.length === 0) return "Unknown";
  return words
    .map((word, index) => {
      const initials = INITIALISMS[word.toLowerCase()];
      if (initials !== undefined) return initials;
      return index === 0 ? word.charAt(0).toUpperCase() + word.slice(1) : word;
    })
    .join(" ");
}
