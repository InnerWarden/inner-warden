import { useEffect, useRef, useState, type ReactNode } from "react";
import { TechnicalOnly } from "../components/TechnicalDetail";
import { When } from "../components/When";
import { formatCount, formatDay } from "../presentation";
import type { Attempt, Brief, Decision, NextStep, Segment, SessionFacts } from "./api";
import { asiLabel } from "./asi";
import { decisionLadder, messageLadder, NOT_CHECKED_AFTERWARDS, type LadderMark, type LadderStep } from "./ladder";
import { Ago, CopyCommand, HiddenChip, tokenWrap } from "./parts";
import { changesAgentConfig, restartFor, restartsAfter, type AgentRestart } from "./restart";
import { BODY_TEXT, H2, LINK_TEXT, META_TEXT, OutcomeWords, PANEL, RestartNote, SMALL_TEXT } from "./ui/blocks";
import { Icon } from "./ui/Icon";
import { ModePill, OutcomeMark } from "./ui/marks";
import {
  DECIDER_WORDS,
  HOST_REFUSED_WORDS,
  OUTCOME_WORDS,
  asVerdict,
  hostRefused,
  layerLine,
  reasonWords,
  shortSession,
  trustWord,
  withheldWords,
  type PlatformOs,
} from "./words";

/** A CLI sentence, printed as sent: text as text, a folder as code, a time through the page's clock. */
export function Segments({ segments }: { segments: readonly Segment[] }) {
  return (
    <>
      {segments.map((segment, index) =>
        segment.kind === "time" ? (
          <When key={index} at={segment.at} />
        ) : segment.kind === "code" ? (
          <code key={index} data-segment-code="" className={`rounded bg-(--iw-surface-2) px-1 font-mono text-[12.5px] text-(--iw-ink) ${tokenWrap(segment.text)}`}>{segment.text}</code>
        ) : (
          <span key={index}>{segment.text}</span>
        ),
      )}
    </>
  );
}

/** Why a decision's command box has no Copy: it is not the command that ran. */
export function notWholeWords(item: Pick<Decision, "commandWhole" | "hiddenCharacters">): string | undefined {
  if (item.commandWhole) return undefined;
  if (item.hiddenCharacters) return "Shown with its hidden characters written out, so there is nothing whole to copy.";
  return "Shortened when it was recorded, so there is nothing whole to copy.";
}

export { changesAgentConfig };

/** Whether the page is as wide as the two-column layout (lg). */
export function wideLayout(): boolean {
  return typeof window !== "undefined" && window.matchMedia?.("(min-width: 1024px)").matches === true;
}

const LADDER_MARK: Record<LadderMark, { mark: ReactNode; words: string }> = {
  done: { mark: <span className="block h-2.5 w-2.5 rounded-full bg-(--iw-ink-2)" />, words: "done" },
  no: { mark: <span className="text-(--iw-deny)"><Icon name="slashed-circle" className="h-3.5 w-3.5" /></span>, words: "no" },
  not_applicable: { mark: <span className="block h-2.5 w-2.5 rounded-full border-[1.5px] border-(--iw-ink-3)" />, words: "not done at this step" },
  unknown: { mark: <span className="block h-2.5 w-2.5 rounded-full border-[1.5px] border-dashed border-(--iw-unknown)" />, words: "not known" },
};

/**
 * The three steps, each with its mark and its words (the mark is never the
 * only signal), and under them, once, that nothing is checked afterwards.
 */
export function Ladder({ steps, label, afterwards = true }: { steps: readonly LadderStep[]; label: string; afterwards?: boolean }) {
  return (
    <div className="space-y-2">
      <ol aria-label={label} className="grid gap-1.5 sm:grid-cols-3">
        {steps.map((step) => {
          const mark = LADDER_MARK[step.mark];
          return (
            <li key={step.key} data-stage={step.key} data-mark={step.mark} className="min-w-0 rounded-lg bg-(--iw-surface-2) px-3 py-1.5">
              <p className="flex items-center gap-1.5 text-xs font-semibold text-(--iw-ink)">
                <span aria-hidden="true" className="flex h-3.5 w-3.5 items-center justify-center">{mark.mark}</span>
                {step.label}
                <span className="sr-only">: {mark.words}.</span>
              </p>
              <p className={`mt-0.5 ${SMALL_TEXT} text-(--iw-ink-2)`}>{step.words}</p>
            </li>
          );
        })}
      </ol>
      {afterwards ? <p data-not-checked-afterwards className={META_TEXT}>{NOT_CHECKED_AFTERWARDS}</p> : null}
    </div>
  );
}

/** One part of a decision: a heading and what goes under it. */
function Part({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <div data-part={id} className="min-w-0 space-y-2">
      <h3 className="text-sm leading-[21px] font-semibold text-(--iw-ink)">{title}</h3>
      {children}
    </div>
  );
}

function NextSteps({
  steps,
  item,
  restarts,
  onHideReason,
}: {
  steps: readonly NextStep[];
  item: Decision;
  /** Every connected agent's restart, for a switch that changes them all. */
  restarts?: readonly AgentRestart[];
  onHideReason?: (key: string) => void;
}) {
  if (steps.length === 0) return <p className={BODY_TEXT}>Nothing to do.</p>;
  const agent = item.agent ?? "your agent";
  const own: AgentRestart = { agent, words: restartFor(item.agentId ?? "", agent, undefined) };
  return (
    <div className="space-y-3">
      {steps.map((step) => (
        <div key={`${step.label}-${step.command ?? ""}`} data-step className="min-w-0 space-y-2 rounded-lg bg-(--iw-surface-2) p-3">
          <p className="text-sm leading-[21px] font-medium text-(--iw-ink)">{step.label}</p>
          {step.command === undefined ? null : <CopyCommand command={step.command} template={step.template === true} />}
          <p className={META_TEXT}>{step.line}</p>
          {restartsAfter(step.command, own, restarts).map((restart) => <RestartNote key={restart.agent} agent={restart.agent} words={restart.words} />)}
          {step.viewAction === "hide_reason" && onHideReason !== undefined && item.reason.key !== "none" ? (
            <button
              type="button"
              data-hide-reason={item.reason.key}
              onClick={() => onHideReason(item.reason.key)}
              className="min-h-9 rounded-md border border-(--iw-line-strong) bg-(--iw-surface) px-3 py-1.5 text-sm font-semibold text-(--iw-ink-2) hover:bg-(--iw-surface-2) pointer-coarse:min-h-11"
            >
              Hide “{item.reason.short}” in the list
            </button>
          ) : null}
        </div>
      ))}
    </div>
  );
}

/** Newer and Older, through the list the decision was opened from. */
function Neighbours({ onNewer, onOlder }: { onNewer?: () => void; onOlder?: () => void }) {
  const button = "inline-flex min-h-9 items-center gap-1 rounded-md px-2 text-sm font-semibold text-(--iw-accent) hover:bg-(--iw-surface-2) disabled:text-(--iw-ink-3) disabled:hover:bg-transparent pointer-coarse:min-h-11";
  return (
    <div className="flex items-center gap-1">
      <button type="button" onClick={onNewer} disabled={onNewer === undefined} className={button}>
        <span aria-hidden="true">←</span>Newer
      </button>
      <button type="button" onClick={onOlder} disabled={onOlder === undefined} className={button}>
        Older<span aria-hidden="true">→</span>
      </button>
    </div>
  );
}

/**
 * One decision (spec 6.3): what the guard did, as one sentence under its
 * outcome and the mode it was decided in; the command, whole; what
 * happened; what InnerWarden did, in three steps; what you can do, each
 * step that changes an agent's config followed by its restart; the
 * commands around it in its session; and, closed, the details an
 * investigator wants. No offer: the reader's own step is the heaviest
 * thing here.
 */
export function DecisionDetail({
  item,
  before,
  after,
  session,
  os,
  installed,
  onNewer,
  onOlder,
  onOpen,
  onSession,
  onHideReason,
  restarts,
  focusTitle = true,
}: {
  item: Decision;
  before: readonly Brief[];
  after: readonly Brief[];
  session?: SessionFacts;
  os: PlatformOs;
  installed: boolean;
  onNewer?: () => void;
  onOlder?: () => void;
  onOpen: (id: string) => void;
  onSession: (label: string) => void;
  /** Hide this decision's reason from the list: a view only (`hide=` in the address). */
  onHideReason?: (key: string) => void;
  /** Every connected agent's restart, for a step that switches them all. */
  restarts?: readonly AgentRestart[];
  /**
   * Move focus to the title when this decision is drawn: only when the
   * person opened it (a click, Enter, Newer or Older), never when arrow keys
   * on the list moved it or on a first load from an address.
   */
  focusTitle?: boolean;
}) {
  const title = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (focusTitle) title.current?.focus({ preventScroll: true });
    // Only a new decision moves focus, never a re-render of the same one.
  }, [item.id]);
  const steps = decisionLadder({ outcomeKey: item.outcomeKey, mode: item.mode, recommendation: item.recommendation, decidedBy: item.decidedBy });
  const notWhole = notWholeWords(item);
  const verdict = asVerdict(item.recommendation);
  const identity = item.identity;
  const hostDecided = identity?.trustSource === "host" && identity.hostDecision !== undefined;
  // A refusal of the host's own is the host's, whatever the general rules said.
  const refusedByHost = hostRefused(identity?.trustSource, item.decidedBy, verdict);
  const layered = identity?.layer === undefined || verdict === undefined
    ? undefined
    : refusedByHost
      ? { text: HOST_REFUSED_WORDS, conflict: false }
      : layerLine(identity.layer, verdict, identity.trust, item.agent ?? item.agentId ?? "this agent", hostDecided);
  // Why a relaxation did not apply, worded for this page: once, grey, no link.
  const withheld = !refusedByHost && identity !== undefined && (identity.relaxationWithheld || identity.hostWithheld !== undefined)
    ? withheldWords(os, installed, identity.hostWithheld !== undefined)
    : undefined;
  return (
    <div className="min-w-0 space-y-4">
      <section aria-labelledby="decision-title" data-decision={item.id} data-outcome-key={item.outcomeKey} className={`${PANEL} space-y-4`}>
        <div className="space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
            <p className={`flex flex-wrap items-center gap-x-3 gap-y-1 ${SMALL_TEXT} text-(--iw-ink-2)`}>
              <OutcomeWords outcome={item.outcomeKey} className="font-medium" />
              <ModePill mode={item.mode} />
              {item.recordedAt === undefined ? null : <Ago at={item.recordedAt} className={META_TEXT} />}
            </p>
            <Neighbours onNewer={onNewer} onOlder={onOlder} />
          </div>
          <h2 id="decision-title" ref={title} tabIndex={-1} style={{ outline: "none" }} className="text-lg leading-7 font-semibold text-(--iw-ink)">{item.did}</h2>
        </div>
        <div className="space-y-1.5">
          <CopyCommand command={item.command} copy={item.commandWhole} />
          {item.hiddenCharacters || notWhole !== undefined ? (
            <p className={`flex flex-wrap items-center gap-x-2 gap-y-1 ${META_TEXT}`}>
              {item.hiddenCharacters ? <HiddenChip /> : null}
              {notWhole === undefined ? null : <span data-not-whole>{notWhole}</span>}
            </p>
          ) : null}
        </div>
        {identity === undefined ? null : <DecisionIdentity item={item} />}
        <Part id="happened" title="What happened">
          <p className={BODY_TEXT}><Segments segments={item.happened} /></p>
        </Part>
        <Part id="did" title="What InnerWarden did">
          <Ladder steps={steps} label="What InnerWarden did with this decision" />
          {layered === undefined ? null : (
            <div className="space-y-1">
              <p data-decided-by-layer={identity?.layer} data-identity-conflict={layered.conflict ? "" : undefined} className={BODY_TEXT}>{layered.text}</p>
              {withheld === undefined ? null : <p data-relaxation-withheld className={META_TEXT}>{withheld}</p>}
            </div>
          )}
        </Part>
        <Part id="next" title="What you can do">
          <NextSteps steps={item.next} item={item} restarts={restarts} onHideReason={onHideReason} />
        </Part>
      </section>
      <AroundIt item={item} before={before} after={after} session={session} onOpen={onOpen} onSession={onSession} />
      <InvestigatorDetails item={item} />
    </div>
  );
}

/**
 * Who asked, from the instance's own record: its name, the instance and
 * session, and how far its word is backed. Drawn only where the decision
 * carries identity.
 */
function DecisionIdentity({ item }: { item: Decision }) {
  const identity = item.identity;
  if (identity === undefined) return null;
  const word = trustWord(identity.trust, identity.trustSource);
  const who = item.agent ?? item.agentId ?? "This agent";
  const session = identity.sessionId ?? item.session;
  return (
    <div data-case-identity className={`space-y-1 ${BODY_TEXT}`}>
      <p>
        {who}
        {identity.instanceId === undefined ? "" : `, instance ${identity.instanceId.slice(0, 8)}`}
        {session === "" ? "" : `, session ${shortSession(session)}`}
      </p>
      <p className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span data-trust={identity.trust} title={word.tooltip} className="inline-flex items-center rounded-full border border-(--iw-line) bg-(--iw-surface-2) px-2 py-0.5 text-xs font-semibold text-(--iw-ink-2)">
          {word.label}
        </span>
        {identity.trust === "host_verified" ? null : <span className={META_TEXT}>{reasonWords(identity.trustReason)}</span>}
      </p>
      <TechnicalOnly>
        <p className="font-mono text-[11px] text-(--iw-ink-3) [overflow-wrap:anywhere]">
          {identity.instanceId === undefined ? "No instance on record" : `Instance ${identity.instanceId}`}. Trust read by: the hook inside the jail ({identity.trustReason === "" ? "no reason recorded" : identity.trustReason}).
          {identity.layer === undefined ? "" : ` Deciding layer: ${identity.layer}${identity.profile === undefined ? "" : `, profile ${identity.profile}`}.`}
          {identity.trustSource === "host" ? ` Rules decided by: InnerWarden Pro on this host${identity.hostDecision === undefined ? "" : ` (decision ${identity.hostDecision})`}.` : ""}
        </p>
      </TechnicalOnly>
    </div>
  );
}

function AroundIt({
  item,
  before,
  after,
  session,
  onOpen,
  onSession,
}: {
  item: Decision;
  before: readonly Brief[];
  after: readonly Brief[];
  session?: SessionFacts;
  onOpen: (id: string) => void;
  onSession: (label: string) => void;
}) {
  const self: Brief = { id: item.id, command: item.command, hiddenCharacters: item.hiddenCharacters, outcomeKey: item.outcomeKey, recordedAt: item.recordedAt, flagged: true };
  const rows = [...before, self, ...after];
  // Only an agent the record names is named; otherwise "this session".
  const who = session?.agent ?? item.agent;
  return (
    <section aria-labelledby="around-title" className={`${PANEL} space-y-2`}>
      <h3 id="around-title" className={H2}>Around it</h3>
      {session === undefined || session.decisions === 0 ? null : (
        <p className={BODY_TEXT}>
          {who === undefined ? "In this session" : `In a session of ${who}`} ({shortSession(item.session)}): {formatCount(session.decisions)} {session.decisions === 1 ? "command" : "commands"}
          {session.firstAt === undefined ? "" : ` since ${formatDay(session.firstAt)}`}, {formatCount(session.flagged)} flagged.
        </p>
      )}
      <ul className="divide-y divide-(--iw-line)">
        {rows.map((row) => {
          const body = (
            <span className={`flex min-w-0 items-center gap-3 py-1.5 ${SMALL_TEXT}`}>
              <OutcomeMark outcome={row.outcomeKey} />
              <span className="min-w-0 flex-1 truncate font-mono text-[12.5px] text-(--iw-ink)" title={row.command}>{row.command}</span>
              {row.hiddenCharacters ? <span data-hidden-characters className="shrink-0 font-mono text-[11px] text-(--iw-ink-3)" title="Contains hidden characters">\u</span> : null}
              {/* The outcome in words for a screen reader at every width, and on
                  screen from sm: the mark alone is never the signal. */}
              <span data-outcome-words={row.outcomeKey} className="sr-only shrink-0 text-(--iw-ink-2) sm:not-sr-only">{OUTCOME_WORDS[row.outcomeKey]}</span>
              <span className={`shrink-0 whitespace-nowrap tabular-nums ${META_TEXT}`}>
                {row.recordedAt === undefined ? null : <Ago at={row.recordedAt} />}
              </span>
              {row.id === item.id ? <span className="shrink-0 text-xs font-semibold text-(--iw-accent)">this one</span> : null}
            </span>
          );
          return (
            <li key={row.id}>
              {row.id !== item.id && row.flagged ? (
                <button type="button" onClick={() => onOpen(row.id)} className="block w-full min-w-0 text-left hover:bg-(--iw-surface-2) pointer-coarse:min-h-11">{body}</button>
              ) : (
                body
              )}
            </li>
          );
        })}
      </ul>
      {item.session === "" ? null : (
        <button type="button" onClick={() => onSession(item.session)} className={`min-h-9 text-sm pointer-coarse:min-h-11 ${LINK_TEXT}`}>
          Show only this session
        </button>
      )}
    </section>
  );
}

const DETAILS_KEY = "iw-community-case-details-open";

function readOpen(): boolean {
  try {
    return window.localStorage.getItem(DETAILS_KEY) === "1";
  } catch {
    return false;
  }
}

/** A value to copy whole, for an investigator: an id, never a command. */
function CopyValue({ value, what }: { value: string; what: string }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  const copy = () => {
    try {
      void navigator.clipboard?.writeText(value).then(() => {
        setCopied(true);
        clearTimeout(timer.current);
        timer.current = setTimeout(() => setCopied(false), 1_500);
      }, () => undefined);
    } catch {
      // No clipboard here: the value is on screen to select.
    }
  };
  return (
    <button type="button" onClick={copy} aria-label={`Copy ${what}: ${value}`} className={`ml-2 text-xs pointer-coarse:min-h-11 ${LINK_TEXT}`}>
      <span aria-live="polite">{copied ? "Copied" : "Copy"}</span>
    </button>
  );
}

function InvestigatorDetails({ item }: { item: Decision }) {
  const [open, setOpen] = useState(readOpen);
  const toggle = (next: boolean) => {
    setOpen(next);
    try {
      window.localStorage.setItem(DETAILS_KEY, next ? "1" : "0");
    } catch {
      // Remembering is a convenience.
    }
  };
  const rows: [string, ReactNode][] = [
    ["Rule words", item.explanation || "none recorded"],
    ["Rules", item.rules.length === 0 ? "not kept by this record" : item.rules.join(", ")],
    ["Rule categories", item.categories.length === 0 ? "none" : item.categories.join(", ")],
    ["OWASP Agentic", item.asi.length === 0 ? "none" : item.asi.map(asiLabel).join("; ")],
    ["Risk", item.risk === undefined ? "not scored" : `${item.risk}, as the rules scored it; the scale is the rules' own`],
    ["Mode at decision", item.mode],
    ["Decided by", DECIDER_WORDS[item.decidedBy] === undefined ? item.decidedBy : `${DECIDER_WORDS[item.decidedBy]} (${item.decidedBy})`],
    ["Verdict and mode", `${item.recommendation}, ${item.mode}, outcome ${item.outcome}`],
    ["Decision", <>{item.id}<CopyValue value={item.id} what="decision id" /></>],
    ["Session", `${item.session}, step ${formatCount(item.seq)}`],
    ["Recorded", item.recordedAt === undefined ? "no time on record" : <When at={item.recordedAt} />],
    ["Channel and agent", `${item.channel}${item.agentId === undefined ? "" : `, ${item.agentId}`}`],
  ];
  return (
    <details open={open} onToggle={(event) => toggle(event.currentTarget.open)} className={PANEL}>
      <summary className={`min-h-9 cursor-pointer text-sm pointer-coarse:min-h-11 ${LINK_TEXT}`}>Details for investigators</summary>
      <dl className={`mt-3 grid gap-x-4 gap-y-1.5 text-xs text-(--iw-ink-2) sm:grid-cols-2`}>
        {rows.map(([term, value]) => (
          <div key={term} className="min-w-0">
            <dt className="font-semibold text-(--iw-ink)">{term}</dt>
            <dd className="break-words [overflow-wrap:anywhere]">{value}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}

/**
 * What a person can do about a message, in Community's own terms: turn
 * refusing on when the agent only records, or nothing, said with the reason.
 */
export function messageStep(outcomeKey: Attempt["outcomeKey"], hostMode: string): { text: string; command?: string } {
  if (outcomeKey === "stopped_by_innerwarden") return { text: "Nothing to do: InnerWarden stopped it." };
  if (hostMode === "monitor" || hostMode === "mixed" || hostMode === "partial") {
    return {
      text: "If your agent had obeyed, the guard would have screened what it ran. This refuses a deny from then on:",
      command: "innerwarden enforce",
    };
  }
  if (hostMode === "enforce") {
    // A hook judges shell commands and a proxy MCP calls: what is screened is
    // a deny refused, never "whatever your agent runs".
    return outcomeKey === "declined_by_agent"
      ? { text: "Nothing to do: your agent declined, and a deny from your connected agents is refused before it runs." }
      : { text: "Nothing to do here: a deny from your connected agents is refused before it runs." };
  }
  if (hostMode === "not_configured") {
    return {
      text: "No agent is connected to the guard, so nothing your agent runs is screened. To connect every agent found here, in monitor:",
      command: "innerwarden agents connect --all --monitor",
    };
  }
  return { text: "The mode could not be read, so this page claims none. To see it:", command: "innerwarden status" };
}

/** A message someone sent the agent, in the same parts as a decision. */
export function MessageDetail({
  item,
  hostMode = "unknown",
  restarts,
  focusTitle = true,
}: {
  item: Attempt;
  hostMode?: string;
  /** Every connected agent's restart, for a step that switches them all. */
  restarts?: readonly AgentRestart[];
  /** As on a decision: only an open the person made moves focus. */
  focusTitle?: boolean;
}) {
  const title = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (focusTitle) title.current?.focus({ preventScroll: true });
  }, [item.id]);
  const declined = item.outcomeKey === "declined_by_agent";
  const step = messageStep(item.outcomeKey, hostMode);
  return (
    <div className="min-w-0 space-y-4">
      <section aria-labelledby="decision-title" data-decision={item.id} data-outcome-key={item.outcomeKey} className={`${PANEL} space-y-4`}>
        <div className="space-y-2">
          <p className={`flex flex-wrap items-center gap-x-3 gap-y-1 ${SMALL_TEXT} text-(--iw-ink-2)`}>
            <OutcomeWords outcome={item.outcomeKey} className="font-medium" />
            <Ago at={item.at} className={META_TEXT} />
          </p>
          <h2 id="decision-title" ref={title} tabIndex={-1} style={{ outline: "none" }} className="text-lg leading-7 font-semibold text-(--iw-ink)">
            Someone on {item.channelWords} asked your agent to do something risky
          </h2>
        </div>
        <div className="space-y-1.5">
          <p className="break-words rounded-lg border border-(--iw-line) bg-(--iw-surface-2) px-3 py-2 text-sm leading-6 text-(--iw-ink) [overflow-wrap:anywhere]">{item.detail}</p>
          {item.hiddenCharacters ? (
            <p className={`flex flex-wrap items-center gap-x-2 gap-y-1 ${META_TEXT}`}>
              <HiddenChip />
              <span>Characters the chat did not show are written out, the way the model read them.</span>
            </p>
          ) : null}
        </div>
        <Part id="happened" title="What happened">
          <p className={BODY_TEXT}>Someone on {item.channelWords} sent this to your agent on <When at={item.at} />.</p>
        </Part>
        <Part id="did" title="What InnerWarden did">
          <p className={BODY_TEXT}>
            Recorded it. {item.decider}
            {declined ? "; nothing was refused, because observe records and does not block." : "."}
          </p>
          <Ladder steps={messageLadder(item.outcomeKey)} label="What InnerWarden did with this message" afterwards={false} />
        </Part>
        <Part id="next" title="What you can do">
          <div data-step className="min-w-0 space-y-2 rounded-lg bg-(--iw-surface-2) p-3">
            <p className="text-sm leading-[21px] text-(--iw-ink)">{step.text}</p>
            {step.command === undefined ? null : <CopyCommand command={step.command} />}
            {restartsAfter(step.command, { agent: "your agent", words: restartFor("", "your agent", undefined) }, restarts).map((restart) => (
              <RestartNote key={restart.agent} agent={restart.agent} words={restart.words} />
            ))}
          </div>
        </Part>
        <TechnicalOnly>
          <p className={`break-words [overflow-wrap:anywhere] ${META_TEXT}`}>
            {item.sender === undefined ? "No sender on record." : `Sender: ${item.sender}.`} Decided by: {item.deciderKey}. Recommendation: {item.recommendation}.
            {item.risk === undefined ? "" : ` Risk ${item.risk}, as the rules scored it.`}
          </p>
        </TechnicalOnly>
      </section>
    </div>
  );
}

/** Before a decision is opened, at a desk: what one says, in the order it says it. */
export function DecisionGuide() {
  return (
    <section aria-labelledby="decision-guide-title" className={`hidden lg:block ${PANEL} space-y-3`}>
      <h2 id="decision-guide-title" className={H2}>Pick a decision to see what happened</h2>
      <ol className={`list-decimal space-y-1.5 pl-5 ${BODY_TEXT}`}>
        <li><span className="font-medium text-(--iw-ink)">What happened.</span> Which agent asked, in which folder, and why the guard flagged it.</li>
        <li><span className="font-medium text-(--iw-ink)">What InnerWarden did.</span> Seen, decided, and whether it was refused.</li>
        <li><span className="font-medium text-(--iw-ink)">What you can do.</span> The command that changes what happens next time, ready to copy.</li>
      </ol>
      <p className={META_TEXT}>{NOT_CHECKED_AFTERWARDS}</p>
    </section>
  );
}
