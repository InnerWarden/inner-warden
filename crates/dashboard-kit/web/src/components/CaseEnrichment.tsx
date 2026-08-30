import { Fragment, type ReactElement } from "react";
import type {
  AgentActivity,
  AiVerdict,
  CaseEnrichment,
  DetectionContext,
  DnsLookup,
  MitreRef,
  RuleHit,
  ThreatIntel,
  HoneypotContext,
} from "../api/cases";
import { StatusBadge } from "./StatusBadge";

// Enrichment renders the signals wired together from the underlying incident /
// decision / mitre mapping. Everything is producer-REPORTED, not verified: the
// section header says so, and every block only renders when its data is present.
// An orphan observation (no detector/AI/rule) renders a single honest banner
// instead of empty scaffolding, so an operator immediately understands "nothing
// flagged this as malicious; it's here for context/recurrence".

const CARD = "min-w-0 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm";
const LABEL = "text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700";

function hasAny(e: CaseEnrichment): boolean {
  return Boolean(
    e.detection ||
      e.ai ||
      e.agent_activity ||
      e.threat_intel ||
      e.honeypot ||
      (e.rules?.length ?? 0) > 0 ||
      (e.mitre?.length ?? 0) > 0 ||
      (e.dns?.length ?? 0) > 0,
  );
}

export function CaseEnrichmentView({ enrichment }: { enrichment: CaseEnrichment | null | undefined }) {
  if (!enrichment) return null;
  if (!hasAny(enrichment)) {
    return (
      <section className={CARD} aria-label="Why this is a case">
        <p className={LABEL}>Why this is a case</p>
        <div className="mt-3 rounded-xl border border-dashed border-slate-300 bg-slate-50 px-4 py-5">
          <h3 className="font-semibold text-slate-950">Raw host observation</h3>
          <p className="mt-1 text-sm leading-6 text-slate-600">
            No detector, AI model, or rule flagged this as malicious. The sensor recorded the activity for context and
            recurrence tracking only. There is no threat verdict, no attacker attribution, and no enforcement. Treat it
            as a signal, not a finding.
          </p>
        </div>
      </section>
    );
  }

  const reasoning: ReactElement[] = [];
  if (enrichment.ai) reasoning.push(<AiVerdictSection key="ai" value={enrichment.ai} />);
  if (enrichment.mitre?.length > 0 || enrichment.rules?.length > 0) {
    reasoning.push(<RulesMitreSection key="rules" rules={enrichment.rules ?? []} mitre={enrichment.mitre ?? []} />);
  }
  const blocks: Record<EnrichmentBlock, ReactElement | null> = {
    agent_activity: enrichment.agent_activity ? <AgentActivitySection value={enrichment.agent_activity} /> : null,
    detection: enrichment.detection ? <DetectionSection value={enrichment.detection} /> : null,
    threat_intel: enrichment.threat_intel ? <ThreatIntelSection value={enrichment.threat_intel} /> : null,
    // One reasoning panel takes the whole row rather than half of it, which is
    // the same half empty box the agent grid had.
    reasoning: reasoning.length > 0
      ? <div className={reasoning.length > 1 ? "grid min-w-0 gap-4 lg:grid-cols-2" : "grid min-w-0 gap-4"}>{reasoning}</div>
      : null,
    dns: enrichment.dns?.length > 0 ? <DnsSection value={enrichment.dns} /> : null,
    honeypot: enrichment.honeypot ? <HoneypotSection value={enrichment.honeypot} /> : null,
  };

  return (
    <section className="min-w-0 space-y-4" aria-label="Case context">
      <p className={LABEL}>What happened</p>
      {enrichmentOrder(enrichment).map((key) => <Fragment key={key}>{blocks[key]}</Fragment>)}
      {/* The "Producer-reported · not verified" badge that used to sit up in
          the section header was styled as a STATUS, so it read as something to
          act on when it is a standing property of every case. The sentence is
          kept, once, where a footnote goes. */}
      <p className="text-xs leading-5 text-slate-500">{REPORTED_NOT_VERIFIED}</p>
    </section>
  );
}

export type EnrichmentBlock = "agent_activity" | "detection" | "threat_intel" | "reasoning" | "dns" | "honeypot";

/**
 * The order the case answers the operator's questions in.
 *
 * What happened (the agent, then the detector that flagged it), WHERE IT CAME
 * FROM, and only then how we reasoned about it. Threat intelligence used to be
 * the fifth panel, below the model verdict and the rule chips, so "who is doing
 * this to me" was two screens of our own reasoning away from the IP that
 * answers it.
 */
export const ENRICHMENT_ORDER: readonly EnrichmentBlock[] = [
  "agent_activity",
  "detection",
  "threat_intel",
  "reasoning",
  "dns",
  "honeypot",
];

/** The blocks this case actually carries, in the order above. */
export function enrichmentOrder(enrichment: CaseEnrichment): EnrichmentBlock[] {
  const present: Record<EnrichmentBlock, boolean> = {
    agent_activity: Boolean(enrichment.agent_activity),
    detection: Boolean(enrichment.detection),
    threat_intel: Boolean(enrichment.threat_intel),
    reasoning: Boolean(enrichment.ai) || (enrichment.rules?.length ?? 0) > 0 || (enrichment.mitre?.length ?? 0) > 0,
    dns: (enrichment.dns?.length ?? 0) > 0,
    honeypot: Boolean(enrichment.honeypot),
  };
  return ENRICHMENT_ORDER.filter((key) => present[key]);
}

export const REPORTED_NOT_VERIFIED =
  "Everything above is what the sensor, the rules and the model reported. It has not been independently verified. What the system did about it is below.";

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 rounded-lg bg-slate-50 px-3 py-2">
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd className="mt-0.5 break-words text-sm font-semibold text-slate-800 [overflow-wrap:anywhere]">{value}</dd>
    </div>
  );
}

function Chip({ label, tone = "slate" }: { label: string; tone?: "slate" | "cyan" | "amber" | "rose" | "violet" }) {
  const tones: Record<string, string> = {
    slate: "border-slate-200 bg-slate-50 text-slate-700",
    cyan: "border-cyan-200 bg-cyan-50 text-cyan-800",
    amber: "border-amber-200 bg-amber-50 text-amber-900",
    rose: "border-rose-200 bg-rose-50 text-rose-800",
    violet: "border-violet-200 bg-violet-50 text-violet-800",
  };
  return (
    <span className={`inline-flex max-w-full items-center gap-1 rounded-full border px-2.5 py-1 text-xs font-medium leading-snug ${tones[tone]}`}>
      <span className="break-words [overflow-wrap:anywhere]">{label}</span>
    </span>
  );
}

// --- Agent activity: the AI agent was flagged doing something (dangerous command
// / injected prompt). This is the most important block when present, so it leads.
function AgentActivitySection({ value }: { value: AgentActivity }) {
  const risk = value.risk_score;
  const tone = risk != null && risk >= 70 ? "rose" : risk != null && risk >= 40 ? "amber" : "slate";
  return (
    <section className={`${CARD} border-l-4 border-l-rose-400`} aria-label="AI agent activity">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="min-w-0">
          <p className={LABEL}>AI agent flagged</p>
          <h3 className="mt-1 break-words text-base font-semibold text-slate-950 [overflow-wrap:anywhere]">{value.agent_name}</h3>
        </div>
        {risk != null && <StatusBadge status={tone === "rose" ? "degraded" : tone === "amber" ? "degraded" : "unknown"} label={`Risk ${risk}`} />}
      </div>
      {value.command && (
        <div className="mt-3">
          <p className="mb-1 text-xs text-slate-500">Flagged command / prompt returned by the agent</p>
          <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-xl bg-slate-950 px-4 py-3 text-xs leading-6 text-rose-100 [overflow-wrap:anywhere]">
            <code>{value.command}</code>
          </pre>
        </div>
      )}
      {value.atr_rule_ids.length > 0 && (
        <div className="mt-3">
          <p className="mb-1.5 text-xs text-slate-500">ATR rules matched</p>
          <div className="flex flex-wrap gap-1.5">
            {value.atr_rule_ids.map((id) => (
              <Chip key={id} label={id} tone="rose" />
            ))}
          </div>
        </div>
      )}
      {value.recommendation && (
        <p className="mt-3 break-words rounded-lg bg-amber-50 px-3 py-2 text-xs leading-6 text-amber-900 [overflow-wrap:anywhere]">
          <strong>Recommendation:</strong> {value.recommendation}
        </p>
      )}
      {value.explanation && (
        <p className="mt-2 break-words text-xs leading-6 text-slate-600 [overflow-wrap:anywhere]">{value.explanation}</p>
      )}
    </section>
  );
}

// --- Why flagged: which layer/detector fired + reason.
function DetectionSection({ value }: { value: DetectionContext }) {
  return (
    <section className={CARD} aria-label="Why flagged">
      <p className={LABEL}>Why flagged</p>
      {/* "Suggested checks: 3" was a fourth cell here, counting the chips that
          are printed in full immediately below it. A count of records the
          reader can see is not a fact about the host. */}
      <dl className="mt-3 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        <Field label="Detector" value={value.detector} />
        {value.kind && <Field label="Signal kind" value={value.kind} />}
        {value.layer && <Field label="Layer" value={value.layer} />}
      </dl>
      {value.reason && <p className="mt-3 break-words text-sm leading-6 text-slate-700 [overflow-wrap:anywhere]">{value.reason}</p>}
      {value.recommended_checks.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {value.recommended_checks.map((c) => (
            <Chip key={c} label={c} />
          ))}
        </div>
      )}
    </section>
  );
}

/**
 * A verdict a MODEL produced, as opposed to one our own bookkeeping produced.
 *
 * The host maps a producer label to a model family and answers `unknown` for
 * everything that is not one of the three engines it knows. Those producers are
 * real and their reasons are worth reading, but they are not models: the sweep
 * that routes an unreviewed finding to a person reports itself as
 * `orphan-recovery`, and the one that gives up reports `needs-review`.
 *
 * Rendering those under "AI verdict / Provider: orphan-recovery" told the
 * operator an artificial intelligence had looked at the case and was called
 * "orphan-recovery". Nothing had looked at it, which is the entire point of
 * those two producers, and the panel said the opposite of the truth.
 */
function isModelVerdict(value: AiVerdict): boolean {
  return value.model_kind === "local_warden" || value.model_kind === "local_classifier" || value.model_kind === "llm";
}

/** `needs_review` is our wire token. A person reads "Needs review". */
function humanVerdict(verdict: string): string {
  const words = verdict.replace(/[_-]+/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

// --- AI verdict: which model decided, local Warden vs cloud LLM.
function AiVerdictSection({ value }: { value: AiVerdict }) {
  const isLocal = value.model_kind === "local_warden" || value.model_kind === "local_classifier";

  // No model ran. Say that, and keep the reason, which is the useful half.
  if (!isModelVerdict(value)) {
    return (
      <section className={CARD} aria-label="Automated review">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <p className={LABEL}>Automated review</p>
          <Chip label="No model ran" tone="slate" />
        </div>
        {value.verdict && (
          <dl className="mt-3 grid gap-3 sm:grid-cols-2">
            <Field label="Outcome" value={humanVerdict(value.verdict)} />
          </dl>
        )}
        {value.reason && <p className="mt-3 break-words text-sm leading-6 text-slate-700 [overflow-wrap:anywhere]">{value.reason}</p>}
        <p className="mt-2 text-xs text-slate-400">No model classified this one, so there is no model opinion to weigh. What the system did about it is below.</p>
      </section>
    );
  }

  const modelLabel = isLocal ? "Local Warden (on-device)" : "Cloud LLM";
  return (
    <section className={CARD} aria-label="AI verdict">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <p className={LABEL}>AI verdict</p>
        <Chip label={modelLabel} tone={isLocal ? "cyan" : "violet"} />
      </div>
      <dl className="mt-3 grid gap-3 sm:grid-cols-2">
        <Field label="Provider" value={value.provider} />
        {value.verdict && <Field label="Verdict" value={humanVerdict(value.verdict)} />}
        {value.risk_score != null && <Field label="Risk score" value={String(value.risk_score)} />}
      </dl>
      {value.reason && <p className="mt-3 break-words text-sm leading-6 text-slate-700 [overflow-wrap:anywhere]">{value.reason}</p>}
      <p className="mt-2 text-xs text-slate-400">Model classification is a signal; it does not by itself establish a block or containment.</p>
    </section>
  );
}

// --- Rules + MITRE.
function RulesMitreSection({ rules, mitre }: { rules: RuleHit[]; mitre: MitreRef[] }) {
  const ruleTone = (kind: string) =>
    kind === "sigma" ? "cyan" : kind === "yara" ? "violet" : kind === "correlation" ? "amber" : "slate";
  return (
    <section className={CARD} aria-label="Rules and MITRE">
      <p className={LABEL}>Rules & technique mapping</p>
      {mitre.length > 0 && (
        <div className="mt-3">
          <p className="mb-1.5 text-xs text-slate-500">MITRE ATT&CK</p>
          <div className="flex flex-wrap gap-1.5">
            {mitre.map((m) => (
              <Chip key={m.technique_id} label={`${m.technique_id}${m.technique_name ? ` · ${m.technique_name}` : ""}${m.tactic ? ` (${m.tactic})` : ""}`} tone="amber" />
            ))}
          </div>
        </div>
      )}
      {rules.length > 0 && (
        <div className="mt-3">
          <p className="mb-1.5 text-xs text-slate-500">Rules matched</p>
          <div className="flex flex-wrap gap-1.5">
            {rules.map((r) => (
              <Chip key={`${r.kind}:${r.id}`} label={`${r.kind}: ${r.name ?? r.id}`} tone={ruleTone(r.kind) as "slate"} />
            ))}
          </div>
        </div>
      )}
    </section>
  );
}

// --- Threat intelligence: source IP + geo map + reputation.
function ThreatIntelSection({ value }: { value: ThreatIntel }) {
  const geo = value.geo;
  const place = [geo?.city, geo?.country].filter(Boolean).join(", ");
  return (
    <section className={CARD} aria-label="Threat intelligence">
      <p className={LABEL}>Threat intelligence</p>
      <div className="mt-3 grid min-w-0 gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
        <div className="min-w-0 space-y-3">
          <dl className="grid gap-3 sm:grid-cols-2">
            {value.ip && <Field label="Source IP" value={value.ip} />}
            {place && <Field label="Location" value={place} />}
            {geo?.asn && <Field label="ASN" value={geo.asn} />}
            {geo?.isp && <Field label="Network" value={geo.isp} />}
          </dl>
          <div className="flex flex-wrap gap-1.5">
            {value.abuseipdb_score != null && (
              <Chip label={`AbuseIPDB ${value.abuseipdb_score}/100`} tone={value.abuseipdb_score >= 50 ? "rose" : "slate"} />
            )}
            {value.dshield && <Chip label="DShield attacker" tone="rose" />}
            {value.dna_fingerprint && <Chip label={`DNA ${value.dna_fingerprint.slice(0, 12)}…`} tone="violet" />}
            {value.campaign_ids.map((c) => (
              <Chip key={c} label={`Campaign ${c}`} tone="amber" />
            ))}
          </div>
          {(value.dna_fingerprint || value.campaign_ids.length > 0) && (
            <p className="text-xs text-slate-400">Behavioural DNA / campaign links are correlation signals, not proof of a single actor.</p>
          )}
        </div>
        {geo?.lat != null && geo?.lon != null ? (
          <GeoMiniMap lat={geo.lat} lon={geo.lon} label={place || value.ip || "source"} />
        ) : value.ip ? (
          <div className="flex items-center justify-center rounded-xl border border-dashed border-slate-300 bg-slate-50 px-4 py-8 text-center text-xs text-slate-500">
            No geolocation reported for this IP.
          </div>
        ) : null}
      </div>
    </section>
  );
}

// Privacy-safe inline graticule map (no external tiles / no network). Equirectangular
// projection: x = lon+180 (0..360), y = 90-lat (0..180). A marker + coordinate
// readout shows WHERE without pretending to be a detailed cartographic tile.
function GeoMiniMap({ lat, lon, label }: { lat: number; lon: number; label: string }) {
  const x = Math.min(360, Math.max(0, lon + 180));
  const y = Math.min(180, Math.max(0, 90 - lat));
  return (
    <figure className="min-w-0">
      <svg viewBox="0 0 360 180" className="h-auto w-full rounded-xl border border-slate-200 bg-slate-900" role="img" aria-label={`Approximate location: ${label}`}>
        <rect x="0" y="0" width="360" height="180" fill="#0f172a" />
        {/* graticule */}
        {[30, 60, 90, 120, 150].map((gy) => (
          <line key={`h${gy}`} x1="0" y1={gy} x2="360" y2={gy} stroke="#1e293b" strokeWidth="0.6" />
        ))}
        {[60, 120, 180, 240, 300].map((gx) => (
          <line key={`v${gx}`} x1={gx} y1="0" x2={gx} y2="180" stroke="#1e293b" strokeWidth="0.6" />
        ))}
        {/* equator + prime meridian */}
        <line x1="0" y1="90" x2="360" y2="90" stroke="#334155" strokeWidth="0.8" />
        <line x1="180" y1="0" x2="180" y2="180" stroke="#334155" strokeWidth="0.8" />
        {/* marker */}
        <circle cx={x} cy={y} r="8" fill="#22d3ee" opacity="0.18" />
        <circle cx={x} cy={y} r="3.2" fill="#22d3ee" stroke="#0f172a" strokeWidth="0.8" />
      </svg>
      <figcaption className="mt-1.5 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500">
        <span className="break-words [overflow-wrap:anywhere]">{label}</span>
        <span className="tabular-nums text-slate-400">{lat.toFixed(2)}, {lon.toFixed(2)}</span>
      </figcaption>
    </figure>
  );
}

// --- DNS lookups.
function DnsSection({ value }: { value: DnsLookup[] }) {
  const actionTone = (a: string | null | undefined) =>
    a === "enforce" || a === "block" || a === "blocked" ? "rose" : a === "would_block" || a === "observe" ? "amber" : "slate";
  return (
    <section className={CARD} aria-label="DNS lookups">
      <p className={LABEL}>DNS lookups</p>
      <ul className="mt-3 space-y-2">
        {value.map((d, i) => (
          <li key={`${d.domain}-${i}`} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-100 bg-slate-50 px-3 py-2">
            <span className="break-all font-mono text-sm text-slate-800">{d.domain}</span>
            <span className="flex flex-wrap gap-1.5">
              {d.action && <Chip label={d.action.replaceAll("_", " ")} tone={actionTone(d.action) as "slate"} />}
              {d.reason && <Chip label={d.reason} />}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

// --- Honeypot transcript.
function HoneypotSection({ value }: { value: HoneypotContext }) {
  return (
    <section className={CARD} aria-label="Honeypot session">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <p className={LABEL}>Honeypot session</p>
        <div className="flex flex-wrap gap-1.5">
          {value.protocol && <Chip label={value.protocol.toUpperCase()} tone="cyan" />}
          {value.credentials_seen != null && value.credentials_seen > 0 && (
            <Chip label={`${value.credentials_seen} credential${value.credentials_seen === 1 ? "" : "s"} captured`} tone="amber" />
          )}
        </div>
      </div>
      {value.commands.length > 0 ? (
        <div className="mt-3">
          <p className="mb-1 text-xs text-slate-500">What the intruder typed</p>
          <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-xl bg-slate-950 px-4 py-3 text-xs leading-6 text-emerald-100 [overflow-wrap:anywhere]">
            <code>{value.commands.map((c) => `$ ${c}`).join("\n")}</code>
          </pre>
        </div>
      ) : (
        <p className="mt-3 text-sm text-slate-600">Session recorded; no commands were captured.</p>
      )}
    </section>
  );
}
