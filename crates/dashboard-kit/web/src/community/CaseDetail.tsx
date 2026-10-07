import { useEffect, useRef, useState, type ReactNode } from "react";
import { TechnicalOnly } from "../components/TechnicalDetail";
import { Glyph } from "../components/icons";
import { When } from "../components/When";
import { STEP_MARK_CLASS, Steps, type Step } from "../components/viz";
import { formatCount, formatDay } from "../presentation";
import type { Attempt, Brief, Decision, NextStep, Segment, SessionFacts } from "./api";
import { asiLabel } from "./asi";
import { CHANNEL_GLYPH } from "./CaseRow";
import { caseLadder, messageLadder } from "./ladder";
import { OfferLine } from "./Offer";
import { caseOffer, messageOffer } from "./offers";
import { Ago, CARD, CopyCommand, Eyebrow, HiddenChip, OutcomeDot, tokenWrap } from "./parts";
import { CHANNEL_WORDS, DECIDER_WORDS, OUTCOME_WORDS, shortSession, type PlatformOs } from "./words";

/** A CLI sentence, printed as sent: text as text, a folder as code, a time through the page's clock. */
export function Segments({ segments }: { segments: readonly Segment[] }) {
  return (
    <>
      {segments.map((segment, index) =>
        segment.kind === "time" ? (
          <When key={index} at={segment.at} />
        ) : segment.kind === "code" ? (
          <code key={index} data-segment-code="" className={`rounded bg-slate-100 px-1 font-mono text-[13px] text-slate-900 ${tokenWrap(segment.text)}`}>{segment.text}</code>
        ) : (
          <span key={index}>{segment.text}</span>
        ),
      )}
    </>
  );
}

/**
 * The case's title, from structured fields: who, and what kind of thing it
 * was. "Ran" only where the record says it ran: a refusal was tried, and an
 * outcome the record does not hold was tried as far as anyone can say.
 */
export function caseTitle(item: Pick<Decision, "agent" | "channel" | "outcomeKey">): string {
  if (item.outcomeKey === "checked_only" || item.channel === "check") return "You checked a command by hand";
  const who = item.agent ?? "An agent";
  const thing = item.channel === "mcp" ? "a tool call" : "a command";
  if (item.outcomeKey === "refused_before_run") return `${who} tried ${thing} the guard refused`;
  if (item.outcomeKey === "unplaced") return `${who} tried ${thing} the guard flagged`;
  return `${who} ran ${thing} the guard flagged`;
}

/** Why a case's command box has no Copy: it is not the command that ran. */
export function notWholeWords(item: Pick<Decision, "commandWhole" | "hiddenCharacters">): string | undefined {
  if (item.commandWhole) return undefined;
  if (item.hiddenCharacters) return "Shown with its hidden characters written out, so there is nothing whole to copy.";
  return "Shortened when it was recorded, so there is nothing whole to copy.";
}

function Row({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1 sm:flex-row sm:gap-4">
      <dt className="shrink-0 text-sm font-semibold text-slate-500 sm:w-40">{term}</dt>
      <dd className="min-w-0 flex-1 text-sm leading-6 text-slate-800">{children}</dd>
    </div>
  );
}

function NextSteps({
  steps,
  reason,
  onHideReason,
}: {
  steps: readonly NextStep[];
  reason: Decision["reason"];
  onHideReason?: (key: string) => void;
}) {
  if (steps.length === 0) return <p className="text-slate-600">Nothing to do.</p>;
  return (
    <div className="space-y-3">
      {steps.map((step) => (
        <div key={`${step.label}-${step.command ?? ""}`}>
          <p className="font-semibold text-slate-900">{step.label}</p>
          {step.command === undefined ? null : (
            <CopyCommand command={step.command} template={step.template === true} className="mt-1" />
          )}
          <p className="mt-1 text-slate-600">{step.line}</p>
          {step.viewAction === "hide_reason" && onHideReason !== undefined && reason.key !== "none" ? (
            <button
              type="button"
              data-hide-reason={reason.key}
              onClick={() => onHideReason(reason.key)}
              className="mt-2 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm font-semibold text-slate-800 hover:bg-slate-50"
            >
              Hide “{reason.short}” in the list
            </button>
          ) : null}
        </div>
      ))}
    </div>
  );
}

function withSeenTime(steps: Step[], at: string | undefined): Step[] {
  if (at === undefined) return steps;
  return steps.map((step) => (step.key === "seen" ? { ...step, caption: <When at={at} relative />, captionWords: undefined } : step));
}

/**
 * One case, in three parts: what happened (who asked, where, why it was
 * flagged), what InnerWarden did (the four steps), and what you can do (the
 * CLI's commands, printed as sent). Then, when this situation has one, what
 * Active Defence would add; then the commands around it in its session; then
 * the details an investigator wants and nobody needs to act.
 */
export function CaseDetail({
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
  /** Hide this case's reason from the list: a view only (`hide=` in the address). */
  onHideReason?: (key: string) => void;
}) {
  const title = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    title.current?.focus({ preventScroll: true });
  }, [item.id]);
  const offer = caseOffer(item, os);
  const steps = withSeenTime(caseLadder({ outcomeKey: item.outcomeKey, mode: item.mode, decidedBy: item.decidedBy }), item.recordedAt);
  const notWhole = notWholeWords(item);
  return (
    <div className="min-w-0 space-y-4">
      <section aria-labelledby="case-title" data-case={item.id} data-outcome-key={item.outcomeKey} className={CARD}>
        <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
          <Eyebrow glyph={CHANNEL_GLYPH[item.channel]}>What your AI agent did · {CHANNEL_WORDS[item.channel]}</Eyebrow>
          <div className="flex items-center gap-1 text-sm">
            <button type="button" onClick={onNewer} disabled={onNewer === undefined} className="rounded-md px-1.5 py-0.5 font-semibold text-cyan-800 hover:bg-slate-100 hover:text-cyan-950 disabled:opacity-40">
              <span aria-hidden="true">← </span>Newer
            </button>
            <button type="button" onClick={onOlder} disabled={onOlder === undefined} className="rounded-md px-1.5 py-0.5 font-semibold text-cyan-800 hover:bg-slate-100 hover:text-cyan-950 disabled:opacity-40">
              Older<span aria-hidden="true"> →</span>
            </button>
          </div>
        </div>
        <h2 id="case-title" ref={title} tabIndex={-1} style={{ outline: "none" }} className="mt-1 text-lg font-semibold text-slate-950">{caseTitle(item)}</h2>
        <CopyCommand command={item.command} copy={item.commandWhole} className="mt-2" />
        {item.hiddenCharacters || notWhole !== undefined ? (
          <p className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-500">
            {item.hiddenCharacters ? <HiddenChip /> : null}
            {notWhole === undefined ? null : <span data-not-whole>{notWhole}</span>}
          </p>
        ) : null}
        <dl className="mt-3 space-y-3">
          <Row term="What happened">
            <Segments segments={item.happened} />
          </Row>
          <Row term="What InnerWarden did">
            <p>{item.did}</p>
            <div className="mt-1.5 max-w-md rounded-xl border border-slate-200 bg-slate-50 px-3 pb-1.5 pt-2.5">
              <Steps steps={steps} label="How far InnerWarden got with this case" captions compact className="w-full" />
            </div>
          </Row>
          <Row term="What you can do">
            <NextSteps steps={item.next} reason={item.reason} onHideReason={onHideReason} />
          </Row>
        </dl>
      </section>
      {offer === undefined ? null : <OfferLine offer={offer} installed={installed} />}
      <AroundIt item={item} before={before} after={after} session={session} onOpen={onOpen} onSession={onSession} />
      <InvestigatorDetails item={item} />
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
    <section aria-labelledby="around-title" className={CARD}>
      <h3 id="around-title" className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">Around it</h3>
      {session === undefined || session.decisions === 0 ? null : (
        <p className="mt-1 text-sm leading-6 text-slate-700">
          {who === undefined ? "In this session" : `In a session of ${who}`} ({shortSession(item.session)}): {formatCount(session.decisions)} {session.decisions === 1 ? "command" : "commands"}
          {session.firstAt === undefined ? "" : ` since ${formatDay(session.firstAt)}`}, {formatCount(session.flagged)} flagged.
        </p>
      )}
      <ul className="mt-2 divide-y divide-slate-100">
        {rows.map((row) => {
          const body = (
            <span className="flex min-w-0 items-center gap-3 py-1.5 text-sm">
              <OutcomeDot outcome={row.outcomeKey} />
              <span className="min-w-0 flex-1 truncate font-mono text-[13px] text-slate-900" title={row.command}>{row.command}</span>
              {row.hiddenCharacters ? <span data-hidden-characters className="shrink-0 font-mono text-[11px] text-slate-600" title="Contains hidden characters">\u</span> : null}
              {/* The words are the outcome for a screen reader at every width;
                  below sm the dot alone is drawn, and colour is never the
                  only signal a reader gets. */}
              <span data-outcome-words={row.outcomeKey} className="sr-only shrink-0 text-xs text-slate-600 sm:not-sr-only">{OUTCOME_WORDS[row.outcomeKey]}</span>
              <span className="shrink-0 whitespace-nowrap text-xs tabular-nums text-slate-500">
                {row.recordedAt === undefined ? null : <Ago at={row.recordedAt} />}
              </span>
              {row.id === item.id ? <span className="shrink-0 text-xs font-semibold text-cyan-700">this one</span> : null}
            </span>
          );
          return (
            <li key={row.id}>
              {row.id !== item.id && row.flagged ? (
                <button type="button" onClick={() => onOpen(row.id)} className="block w-full min-w-0 text-left hover:bg-slate-50">{body}</button>
              ) : (
                body
              )}
            </li>
          );
        })}
      </ul>
      {item.session === "" ? null : (
        <button type="button" onClick={() => onSession(item.session)} className="mt-2 text-sm font-semibold text-cyan-700 hover:text-cyan-900">
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
    ["Decided by", DECIDER_WORDS[item.decidedBy] === undefined ? item.decidedBy : `${DECIDER_WORDS[item.decidedBy]} (${item.decidedBy})`],
    ["Verdict and mode", `${item.recommendation}, ${item.mode}, outcome ${item.outcome}`],
    ["Decision", item.id],
    ["Session", `${item.session}, step ${formatCount(item.seq)}`],
    ["Recorded", item.recordedAt === undefined ? "no time on record" : <When at={item.recordedAt} />],
    ["Channel and agent", `${item.channel}${item.agentId === undefined ? "" : `, ${item.agentId}`}`],
  ];
  return (
    <details open={open} onToggle={(event) => toggle(event.currentTarget.open)} className={CARD}>
      <summary className="cursor-pointer text-sm font-semibold text-slate-800">Details for investigators</summary>
      <dl className="mt-3 grid gap-x-4 gap-y-1.5 text-xs text-slate-600 sm:grid-cols-2">
        {rows.map(([term, value]) => (
          <div key={term} className="min-w-0">
            <dt className="font-semibold text-slate-800">{term}</dt>
            <dd className="break-words [overflow-wrap:anywhere]">{value}</dd>
          </div>
        ))}
      </dl>
    </details>
  );
}

/**
 * What a person can do about a message, in Community's own terms, before any
 * offer: turn refusing on when the agent only watches, or nothing, said with
 * the reason.
 */
export function messageStep(outcomeKey: Attempt["outcomeKey"], hostMode: string): { text: string; command?: string } {
  if (outcomeKey === "stopped_by_innerwarden") return { text: "Nothing to do: InnerWarden stopped it." };
  if (hostMode === "monitor" || hostMode === "mixed" || hostMode === "partial") {
    return {
      text: "If your agent had obeyed, the guard would have screened what it ran. This refuses a deny from then on:",
      command: "innerwarden enforce",
    };
  }
  if (outcomeKey === "declined_by_agent") return { text: "Nothing to do: your agent declined, and the guard screens what it runs." };
  return { text: "Nothing to do here: the guard screens whatever your agent runs." };
}

/** A message someone sent the agent, in the same three parts. */
export function MessageDetail({ item, os, installed, hostMode = "unknown" }: { item: Attempt; os: PlatformOs; installed: boolean; hostMode?: string }) {
  const title = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    title.current?.focus({ preventScroll: true });
  }, [item.id]);
  const declined = item.outcomeKey === "declined_by_agent";
  const steps = withSeenTime(messageLadder(item.outcomeKey), item.at);
  const offer = messageOffer(os, item.outcomeKey);
  const step = messageStep(item.outcomeKey, hostMode);
  return (
    <div className="min-w-0 space-y-4">
      <section aria-labelledby="case-title" data-case={item.id} className={CARD}>
        <Eyebrow glyph="chat">Messages to your AI agent · {item.channelWords}</Eyebrow>
        <h2 id="case-title" ref={title} tabIndex={-1} style={{ outline: "none" }} className="mt-1 text-lg font-semibold text-slate-950">
          Someone on {item.channelWords} asked your agent to do something risky
        </h2>
        <p className="mt-3 break-words rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm leading-6 text-slate-900 [overflow-wrap:anywhere]">{item.detail}</p>
        {item.hiddenCharacters ? (
          <p className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-500">
            <HiddenChip />
            <span>Characters the chat did not show are written out, the way the model read them.</span>
          </p>
        ) : null}
        <dl className="mt-3 space-y-3">
          <Row term="What happened">
            Someone on {item.channelWords} sent this to your agent on <When at={item.at} />.
          </Row>
          <Row term="What InnerWarden did">
            <p>
              Recorded it. {item.decider}
              {declined ? "; nothing was enforced, because observe records and does not block." : "."}
            </p>
            <div className="mt-1.5 max-w-md rounded-xl border border-slate-200 bg-slate-50 px-3 pb-1.5 pt-2.5">
              <Steps steps={steps} label="How far InnerWarden got with this message" captions compact className="w-full" />
            </div>
          </Row>
          <Row term="What you can do">
            <p>{step.text}</p>
            {step.command === undefined ? null : <CopyCommand command={step.command} className="mt-1" />}
          </Row>
        </dl>
        <TechnicalOnly>
          <p className="mt-3 break-words text-xs text-slate-500 [overflow-wrap:anywhere]">
            {item.sender === undefined ? "No sender on record." : `Sender: ${item.sender}.`} Decided by: {item.deciderKey}. Recommendation: {item.recommendation}.
            {item.risk === undefined ? "" : ` Risk ${item.risk}, as the rules scored it.`}
          </p>
        </TechnicalOnly>
      </section>
      {offer === undefined ? null : <OfferLine offer={offer} installed={installed} />}
    </div>
  );
}

/**
 * Before a case is opened: how to read one, with the same marks every case
 * uses, so the legend is read once.
 */
export function CaseGuide() {
  const sample: Step[] = [
    { key: "seen", label: "Seen", mark: "done", words: "on record" },
    { key: "decided", label: "Decided", mark: "done", words: "decided" },
    { key: "enforced", label: "Enforced", mark: "not_applicable", words: "not done at this step" },
    { key: "verified", label: "Verified", mark: "unknown", words: "not checked in Community" },
  ];
  const legend: [Step["mark"], string][] = [
    ["done", "On record"],
    ["unknown", "Not checked in Community"],
    ["not_applicable", "Not done at this step"],
    ["no", "Judged unsafe, and it ran"],
  ];
  return (
    <section aria-labelledby="case-guide-title" className={`hidden lg:block ${CARD}`}>
      <p className="text-xs font-semibold uppercase tracking-[0.14em] text-cyan-700">How to read a case</p>
      <h2 id="case-guide-title" className="mt-1 text-lg font-semibold text-slate-950">Pick a case to see what happened</h2>
      <p className="mt-1 text-sm leading-6 text-slate-600">Every case answers three questions, in this order.</p>
      <ol className="mt-4 space-y-4 text-sm leading-6 text-slate-700">
        <li className="flex gap-3">
          <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-900 text-[11px] font-semibold text-white">1</span>
          <p><span className="font-semibold text-slate-900">What happened.</span> Which agent asked, in which folder, and why the guard flagged it.</p>
        </li>
        <li className="flex gap-3">
          <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-900 text-[11px] font-semibold text-white">2</span>
          <div className="min-w-0 flex-1">
            <p><span className="font-semibold text-slate-900">What InnerWarden did.</span> How far it got, in four steps:</p>
            <div className="mt-3 max-w-sm rounded-xl border border-slate-200 bg-slate-50 px-3 pb-2 pt-3">
              <Steps steps={sample} label="The four steps of a case" captions compact className="w-full" />
            </div>
            <ul className="mt-3 grid gap-x-4 gap-y-1.5 text-xs text-slate-600 sm:grid-cols-2">
              {legend.map(([mark, words]) => (
                <li key={mark} className="flex items-center gap-2">
                  <span className="flex h-3 w-3 shrink-0 items-center justify-center">
                    <span aria-hidden="true" data-mark={mark} className={`relative block ${STEP_MARK_CLASS[mark]}`} />
                  </span>
                  {words}
                </li>
              ))}
            </ul>
          </div>
        </li>
        <li className="flex gap-3">
          <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-900 text-[11px] font-semibold text-white">3</span>
          <p><span className="font-semibold text-slate-900">What you can do.</span> The command that changes what happens next time, ready to copy.</p>
        </li>
      </ol>
      <p className="mt-4 flex items-center gap-2 text-xs text-slate-500">
        <Glyph name="prompt" className="h-3.5 w-3.5" /> Shell command
        <Glyph name="plug" className="ml-2 h-3.5 w-3.5" /> MCP tool call
        <Glyph name="person" className="ml-2 h-3.5 w-3.5" /> Checked by hand
      </p>
    </section>
  );
}
