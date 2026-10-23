import { useMemo, type MouseEvent, type ReactNode } from "react";
import { TechnicalOnly } from "../../components/TechnicalDetail";
import { formatCount } from "../../presentation";
import { OUTCOME_STYLE, type OutcomeKey } from "../outcomeStyle";
import { CopyCommand } from "../parts";
import { restartNote, type RestartWords } from "../restart";
import { clockTime, type BandStep, type Restart, type Verdict, type VerdictAction, type VerdictTone } from "../verdict";
import { isTemplate, OUTCOME_WORDS } from "../words";
import { Icon, type IconName } from "./Icon";
import { Mark, MarkSwatch, OutcomeMark } from "./marks";

/**
 * The blocks a Community page is built from (spec 9.2, 9.3): one panel per
 * section, hierarchy from size and weight, colour only on marks and rails.
 */

export const PANEL = "min-w-0 rounded-[10px] border border-(--iw-line) bg-(--iw-surface) p-4 sm:p-5";
export const SMALL_TEXT = "text-[13px] leading-[18px]";
export const META_TEXT = `${SMALL_TEXT} text-(--iw-ink-3)`;
export const BODY_TEXT = "text-sm leading-[21px] text-(--iw-ink-2)";
export const H2 = "text-[15px] leading-[22px] font-semibold text-(--iw-ink)";
export const LINK_TEXT = "font-semibold text-(--iw-accent) underline-offset-2 hover:underline";
export const H3 = "text-sm leading-[21px] font-semibold text-(--iw-ink)";
export const PAGE_TITLE = "text-2xl leading-[30px] font-semibold tracking-tight text-(--iw-ink)";

/** A fixed-height block while the first answer is on its way: never a zero, never an empty list. */
export function Pending({ label, className = "h-24" }: { label: string; className?: string }) {
  return <div aria-busy="true" aria-label={label} className={`animate-pulse rounded-lg bg-(--iw-surface-2) ${className}`} />;
}

/** A command or a pattern inside a sentence, in the command face. */
export function Code({ children }: { children: ReactNode }) {
  return <code className="font-mono text-[12.5px]">{children}</code>;
}

/** A plain left click on a link is handled in the page; any other click is the browser's. */
export function onPlainClick(open: (() => void) | undefined) {
  return (event: MouseEvent<HTMLAnchorElement>) => {
    if (open === undefined || event.defaultPrevented || event.button !== 0) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    open();
  };
}

/** A section of a page: `section[aria-labelledby]` with its h2. */
export function Section({
  id,
  title,
  aside,
  children,
  className = "",
  tour,
}: {
  id: string;
  title: string;
  aside?: ReactNode;
  children: ReactNode;
  className?: string;
  tour?: string;
}) {
  return (
    <section id={id} aria-labelledby={`${id}-title`} data-tour={tour} className={`min-w-0 space-y-4 ${className}`}>
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h2 id={`${id}-title`} className={H2}>{title}</h2>
        {aside}
      </div>
      {children}
    </section>
  );
}

/** Where a count comes from, and the span it covers (T6). */
export function SourceLine({ children }: { children: ReactNode }) {
  return <p data-source className={META_TEXT}>{children}</p>;
}

/**
 * Something that could not be read, said as such: dashed, never a zero and
 * never "off". `children` is the sentence; `at` the last try; `onRetry` asks
 * again (a GET, nothing more).
 */
export function NotRead({
  children,
  at,
  onRetry,
  alert = false,
}: {
  children: ReactNode;
  at?: number;
  onRetry?: () => void;
  /** Said at once to a screen reader: a source the page is built on could not be read. */
  alert?: boolean;
}) {
  return (
    <div data-not-read role={alert ? "alert" : undefined} className={`rounded-lg border border-dashed border-(--iw-line-strong) bg-(--iw-surface) px-4 py-3 ${BODY_TEXT}`}>
      <p className="flex items-start gap-2">
        <span className="mt-0.5 text-(--iw-unknown)"><Icon name="dashed-circle" /></span>
        <span className="min-w-0">
          {children}
          {at === undefined ? null : <> Last tried {clockTime(at)}.</>}
        </span>
      </p>
      {onRetry === undefined ? null : (
        <button type="button" onClick={onRetry} className={`mt-2 min-h-9 text-sm pointer-coarse:min-h-11 ${LINK_TEXT}`}>
          Try again
        </button>
      )}
    </div>
  );
}

/** A native disclosure: closed until opened, and Escape or a second press closes it. */
export function Disclosure({ summary, children, open = false }: { summary: ReactNode; children: ReactNode; open?: boolean }) {
  return (
    <details data-disclosure open={open} className="min-w-0">
      <summary className={`min-h-9 cursor-pointer py-1 text-sm pointer-coarse:min-h-11 ${LINK_TEXT}`}>{summary}</summary>
      <div className="mt-3">{children}</div>
    </details>
  );
}

/** The outcome marks a list uses, each with its words. */
export function Legend({ outcomes, className = "" }: { outcomes: readonly OutcomeKey[]; className?: string }) {
  return (
    <ul data-legend className={`flex flex-wrap gap-x-4 gap-y-1 ${META_TEXT} ${className}`}>
      {outcomes.map((outcome) => (
        <li key={outcome} className="flex items-center gap-1.5">
          <Mark {...OUTCOME_STYLE[outcome]} />
          <span>{OUTCOME_WORDS[outcome]}</span>
        </li>
      ))}
    </ul>
  );
}

/**
 * The person's restart, after a step that changes an agent's config: how, and
 * why. Never that it restarted: only the person can do that.
 */
export function RestartNote({ agent, words }: { agent: string; words: RestartWords }) {
  return (
    <p data-restart={agent} className={`flex items-start gap-2 ${SMALL_TEXT} text-(--iw-ink-2)`}>
      <span className="mt-0.5 text-(--iw-ink-3)"><Icon name="terminal" /></span>
      <span className="min-w-0">{restartNote(agent, words)}</span>
    </p>
  );
}

/**
 * One step (T3): what it is for, one command, one line on what it does, and
 * the restarts it needs. A command with a `<placeholder>` is a template:
 * shown to fill in, never copied.
 */
export function StepBlock({ step, restarts = [] }: { step: BandStep; restarts?: readonly Restart[] }) {
  return (
    <div data-step className="min-w-0 space-y-2 rounded-lg bg-(--iw-surface-2) p-3">
      <p className="text-sm leading-[21px] font-medium text-(--iw-ink)">{step.label}</p>
      {step.command === undefined ? null : <CopyCommand command={step.command} template={isTemplate(step.command)} />}
      {step.line === undefined ? null : <p className={META_TEXT}>{step.line}</p>}
      {restarts.map((restart) => <RestartNote key={restart.agent} agent={restart.agent} words={restart.words} />)}
    </div>
  );
}

/** A big counted number and what it counts, with its mark; unknown is dashed, never a zero. */
export function CountStat({
  value,
  label,
  tone,
  fill,
}: {
  value: number | undefined;
  label: string;
  tone: "stopped" | "deny";
  fill: "solid" | "hatched";
}) {
  return (
    <div data-count={label} className="min-w-0">
      {value === undefined ? (
        <p className="flex h-8 items-center gap-2 text-sm text-(--iw-ink-2)">
          <span className="text-(--iw-unknown)"><Icon name="dashed-circle" /></span>
          Not read
        </p>
      ) : (
        <p className="text-[28px] leading-8 font-semibold tabular-nums text-(--iw-ink)">{formatCount(value)}</p>
      )}
      <p className={`mt-1 flex items-center gap-1.5 ${SMALL_TEXT} text-(--iw-ink-2)`}>
        <MarkSwatch tone={tone} fill={fill} />
        {label}
      </p>
    </div>
  );
}

const TONE_ICON: Record<VerdictTone, IconName> = {
  watch: "eye",
  stopped: "shield",
  needs: "triangle",
  exposed: "globe",
  unknown: "dashed-circle",
};

const TONE_ICON_COLOUR: Record<VerdictTone, string> = {
  watch: "text-(--iw-ink-3)",
  stopped: "text-(--iw-stopped)",
  needs: "text-(--iw-review)",
  exposed: "text-(--iw-deny)",
  unknown: "text-(--iw-unknown)",
};

function ActionBlock({ action, said = [], onOpenAgents }: { action: VerdictAction; said?: readonly string[]; onOpenAgents?: () => void }) {
  return (
    <div data-verdict-action className="min-w-0 space-y-3">
      {action.steps.map(({ step, restarts }) => (
        <StepBlock
          key={`${step.label}${step.command ?? ""}`}
          // A line the band already says beside the step (row 5) is not said twice.
          step={step.line !== undefined && said.includes(step.line) ? { ...step, line: undefined } : step}
          restarts={restarts}
        />
      ))}
      {action.restarts.length === 0 ? null : (
        <div className="space-y-2 rounded-lg bg-(--iw-surface-2) p-3">
          {action.restarts.map((restart) => <RestartNote key={restart.agent} agent={restart.agent} words={restart.words} />)}
          {action.after === undefined ? null : <p className={`${SMALL_TEXT} text-(--iw-ink-2)`}>{action.after}</p>}
        </div>
      )}
      {action.restarts.length === 0 && action.after !== undefined ? <p className={BODY_TEXT}>{action.after}</p> : null}
      {action.back === undefined ? null : (
        <div className="space-y-1.5">
          <p className={META_TEXT}>{action.back.label}</p>
          {action.back.command === undefined ? null : <CopyCommand command={action.back.command} />}
        </div>
      )}
      {action.nothing === undefined ? null : <p className="text-sm leading-[21px] font-medium text-(--iw-ink)">{action.nothing}</p>}
      {action.link === "agents" ? (
        <a href="?view=agents" onClick={onPlainClick(onOpenAgents)} className={`inline-flex min-h-9 items-center gap-1 text-sm pointer-coarse:min-h-11 ${LINK_TEXT}`}>
          See Agents <Icon name="arrow-right" className="h-3.5 w-3.5" />
        </a>
      ) : null}
    </div>
  );
}

/**
 * The verdict band: one headline, its lines, and the one next step (spec
 * 6.1). The tone sets the 4 px rail (`data-tone`, theme.css); the minimum
 * height keeps the skeleton from shifting the page when the answer comes.
 * `compact` is the Protection page's mode box: the same band, one column.
 */
export function VerdictBand({
  verdict,
  compact = false,
  id = "verdict",
  onOpenAgents,
  tour,
  extra,
  page,
}: {
  verdict: Verdict;
  compact?: boolean;
  id?: string;
  onOpenAgents?: () => void;
  tour?: string;
  /** More under the lines, in the band's own words (the Protection page's two definitions). */
  extra?: ReactNode;
  /**
   * The band is the page's own heading (the Overview): its headline is the
   * page's h1, named "<page>: <headline>" for a screen reader, and takes
   * focus when someone moves to the page.
   */
  page?: string;
}) {
  const frame = `${PANEL} border-l-4 border-l-(--iw-band) ${compact ? "" : "min-h-[188px] lg:min-h-[148px]"}`;
  if (verdict.row === 0 || verdict.headline === undefined) {
    return (
      <section id={id} data-tone="unknown" data-verdict-row={0} aria-busy="true" aria-label="Checking whether your agents are connected" data-tour={tour} className={frame}>
        <div className="h-6 w-2/3 animate-pulse rounded bg-(--iw-surface-2)" />
        <div className="mt-3 h-4 w-1/2 animate-pulse rounded bg-(--iw-surface-2)" />
      </section>
    );
  }
  const action = verdict.action;
  const Heading = page === undefined ? "h2" : "h1";
  return (
    <section id={id} data-tone={verdict.tone} data-verdict-row={verdict.row} aria-labelledby={`${id}-title`} data-tour={tour} className={frame}>
      <div className={compact ? "space-y-4" : "space-y-4 lg:grid lg:grid-cols-12 lg:gap-6 lg:space-y-0"}>
        <div className={`min-w-0 space-y-2 ${compact ? "" : "lg:col-span-7"}`}>
          <Heading id={`${id}-title`} tabIndex={page === undefined ? undefined : -1} className="flex items-start gap-2 text-xl leading-7 font-semibold text-(--iw-ink)">
            <span className={`mt-1.5 ${TONE_ICON_COLOUR[verdict.tone]}`}><Icon name={TONE_ICON[verdict.tone]} /></span>
            <span className="min-w-0">
              {page === undefined ? null : <span className="sr-only">{page}: </span>}
              {verdict.headline}
            </span>
          </Heading>
          {verdict.lines.map((line, index) => (
            <p key={index} className={BODY_TEXT}>{line}</p>
          ))}
          {extra}
        </div>
        {action === undefined ? null : (
          <div className={`min-w-0 ${compact ? "" : "lg:col-span-5"}`}>
            <ActionBlock action={action} said={verdict.lines} onOpenAgents={onOpenAgents} />
          </div>
        )}
      </div>
    </section>
  );
}

/** An outcome in words with its mark, for a row's second line or a key. */
export function OutcomeWords({ outcome, className = "" }: { outcome: OutcomeKey; className?: string }) {
  return (
    <span className={`inline-flex items-center gap-1.5 ${className}`}>
      <OutcomeMark outcome={outcome} />
      {OUTCOME_WORDS[outcome]}
    </span>
  );
}

const SECONDS = new Intl.DateTimeFormat("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" });

/**
 * The technical view's line under a section: when its answer came in, and
 * from which route. Kept until a new answer arrives; nothing before the first.
 */
export function ReadAt({ data, path }: { data: unknown; path: string }) {
  const at = useMemo(() => (data === undefined ? undefined : Date.now()), [data]);
  if (at === undefined) return null;
  return (
    <TechnicalOnly>
      <p data-read-at={path} className={META_TEXT}>Read at {SECONDS.format(at)} from {path}.</p>
    </TechnicalOnly>
  );
}
