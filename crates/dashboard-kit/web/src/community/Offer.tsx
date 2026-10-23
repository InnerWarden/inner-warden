import { useId, useRef, useState } from "react";
import { dismiss, dismissed } from "./dismiss";
import { INSTALLED_LINE, protectionOffer } from "./offers";
import { CopyCommand } from "./parts";
import { BODY_TEXT, LINK_TEXT, PANEL } from "./ui/blocks";

/**
 * The foot of Protection: the one generic line about the paid edition, one
 * link out ("Compare the editions") and "Not now", or, where the paid
 * edition is installed, the installed line in its place.
 *
 * No gradient, no icon, no badge, never a modal and never a blur. "Not now"
 * hides it in this browser (`dismiss.ts`) and moves focus to the page's
 * title, so a keyboard reader is not dropped at the top of the page. The
 * tour's upgrade step points at the wrapper, which stays either way.
 */
export function FooterOffer({ installed }: { installed: boolean }) {
  const offer = protectionOffer();
  const lineId = useId();
  const box = useRef<HTMLElement>(null);
  const [hidden, setHidden] = useState(() => dismissed(offer.slot));
  const hide = () => {
    dismiss(offer.slot);
    setHidden(true);
    const title = box.current?.ownerDocument.querySelector<HTMLElement>("main h1");
    title?.focus();
  };
  return (
    <div data-tour="upgrade" className="min-w-0">
      {installed ? (
        <InstalledLine />
      ) : hidden ? null : (
        <aside ref={box} aria-labelledby={lineId} data-offer={offer.key} data-ad-state="offer" className={PANEL}>
          <p id={lineId} className={BODY_TEXT}>{offer.body}</p>
          <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2">
            <a href={offer.href} target="_blank" rel="noreferrer" className={`${LINK_TEXT} text-sm pointer-coarse:inline-flex pointer-coarse:min-h-11 pointer-coarse:items-center`}>
              {offer.action} <span aria-hidden="true">↗</span>
              <span className="sr-only"> (opens innerwarden.com)</span>
            </a>
            <button
              type="button"
              onClick={hide}
              aria-label="Not now: hide this offer"
              className="text-sm font-semibold text-(--iw-ink-2) hover:text-(--iw-ink) pointer-coarse:min-h-11"
            >
              Not now
            </button>
          </div>
        </aside>
      )}
    </div>
  );
}

/**
 * Said in place of the offer on a machine where the paid edition is
 * installed. Claims installation and nothing about what runs there.
 */
export function InstalledLine() {
  return (
    <div data-ad-state="installed" className={PANEL}>
      <p className={BODY_TEXT}>
        <span className="font-semibold text-(--iw-ink)">{INSTALLED_LINE.lead}</span> {INSTALLED_LINE.body}
      </p>
      <CopyCommand command={INSTALLED_LINE.command} className="mt-2" />
    </div>
  );
}
