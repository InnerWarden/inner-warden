import { useId, useRef, useState } from "react";
import { dismiss, dismissed } from "./dismiss";
import { INSTALLED_LINE, type Offer } from "./offers";
import { CopyCommand } from "./parts";

/**
 * One offer: what Active Defence would add here, one link out, and "Not now".
 *
 * No gradient, no icon, no badge, never a modal and never a blur: it is a
 * plain box with the product's name as its eyebrow. "Not now" hides it in
 * this browser (`dismiss.ts`) and moves focus to what comes next in the card,
 * so a keyboard reader is not dropped at the top of the page.
 */
export function OfferBox({ offer, installed, onDismissed }: { offer: Offer; installed: boolean; onDismissed?: () => void }) {
  const titleId = useId();
  const box = useRef<HTMLElement>(null);
  const [hidden, setHidden] = useState(() => dismissed(offer.slot));
  if (installed) return <InstalledLine />;
  if (hidden) return null;
  const hide = () => {
    const next = nextFocusable(box.current);
    dismiss(offer.slot);
    setHidden(true);
    onDismissed?.();
    next?.focus();
  };
  return (
    <aside
      ref={box}
      aria-labelledby={titleId}
      data-offer={offer.key}
      data-ad-state="offer"
      data-tour={offer.slot === "protection" ? undefined : "upgrade-offer"}
      className="rounded-xl border border-slate-200 bg-white p-4"
    >
      <p id={titleId} className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Active Defence</p>
      <p className="mt-1 text-sm leading-6 text-slate-700">{offer.body}</p>
      <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2">
        <a
          href={offer.href}
          target="_blank"
          rel="noreferrer"
          className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm font-semibold text-slate-800 hover:bg-slate-50"
        >
          {offer.action} <span aria-hidden="true">↗</span>
          <span className="sr-only"> (opens innerwarden.com)</span>
        </a>
        <button
          type="button"
          onClick={hide}
          aria-label="Not now: hide this offer"
          className="text-sm font-semibold text-slate-600 hover:text-slate-900"
        >
          Not now
        </button>
      </div>
    </aside>
  );
}

/**
 * An offer as one slate band, under a case rather than inside it: the
 * reader's own step stays the heaviest thing on the card. A text link, not a
 * button, so it never outweighs the Copy beside the reader's own command.
 * Same "Not now", same remembered slot as `OfferBox`.
 */
export function OfferLine({ offer, installed }: { offer: Offer; installed: boolean }) {
  const box = useRef<HTMLElement>(null);
  const [hidden, setHidden] = useState(() => dismissed(offer.slot));
  if (installed) return <InstalledLine />;
  if (hidden) return null;
  const hide = () => {
    const next = nextFocusable(box.current);
    dismiss(offer.slot);
    setHidden(true);
    next?.focus();
  };
  return (
    <aside
      ref={box}
      aria-label="Active Defence"
      data-offer={offer.key}
      data-ad-state="offer"
      data-tour="upgrade-offer"
      className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 text-sm leading-6 text-slate-600"
    >
      <span className="mr-1.5 text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-500">Active Defence</span>
      <span>{offer.body}</span>{" "}
      <span className="whitespace-nowrap">
        <a href={offer.href} target="_blank" rel="noreferrer" className="font-semibold text-cyan-700 hover:text-cyan-900">
          {offer.action} <span aria-hidden="true">↗</span>
          <span className="sr-only"> (opens innerwarden.com)</span>
        </a>
        <span aria-hidden="true" className="mx-1.5 text-slate-400">·</span>
        <button type="button" onClick={hide} aria-label="Not now: hide this offer" className="font-semibold text-slate-600 hover:text-slate-900">
          Not now
        </button>
      </span>
    </aside>
  );
}

/** The next element a keyboard can reach after `element`, inside the same section. */
function nextFocusable(element: HTMLElement | null): HTMLElement | null {
  if (element === null) return null;
  const scope = element.closest("section") ?? document.body;
  const all = Array.from(scope.querySelectorAll<HTMLElement>("a[href], button:not([disabled]), [tabindex]:not([tabindex='-1'])"));
  const after = all.find((candidate) => !element.contains(candidate) && (element.compareDocumentPosition(candidate) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0);
  if (after !== undefined) return after;
  const heading = scope.querySelector<HTMLElement>("h1, h2");
  if (heading !== null && !heading.hasAttribute("tabindex")) heading.setAttribute("tabindex", "-1");
  return heading;
}

/**
 * Said in place of every offer on a machine with Active Defence installed.
 * Claims installation and nothing about what runs there.
 */
export function InstalledLine() {
  return (
    <div data-ad-state="installed" className="rounded-xl border border-slate-200 bg-slate-50 p-4 text-sm leading-6 text-slate-700">
      <p>
        <span className="font-semibold text-slate-900">{INSTALLED_LINE.lead}</span> {INSTALLED_LINE.body}
      </p>
      <CopyCommand command={INSTALLED_LINE.command} className="mt-2" />
    </div>
  );
}
