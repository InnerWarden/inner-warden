import type { OfferSlot } from "./dismiss";

/**
 * Everything Community says about the paid edition, and where.
 *
 * Two places and three sentences: the foot of Protection (`GENERIC_LINE`,
 * or `INSTALLED_LINE` where the paid edition is installed) and one tour step
 * (`TOUR_UPGRADE_LINE`, dropped where it is installed). Nothing on a
 * decision, an agent or the Overview. One link, with no query string, and
 * nothing is sent anywhere. The words are generic on purpose: this page is
 * public, and it says what the edition is for, never how it works.
 *
 * `copy.test.ts` holds every line of this folder that names the paid
 * edition to these sentences and to the attribution words that say which
 * layer decided a command.
 */

export const PRICING_URL = "https://innerwarden.com/pricing";
export const EDITIONS_URL = "https://innerwarden.com/docs/editions-and-guarantees";

/** The one offer, at the foot of Protection. */
export const GENERIC_LINE = "InnerWarden Pro adds host-level protection for Linux servers.";

/** The tour's last step before it ends. */
export const TOUR_UPGRADE_LINE =
  "Community screens what your AI agents try to run. InnerWarden Pro, the paid edition, adds host-level protection for Linux servers.";

export type Offer = {
  slot: OfferSlot;
  /** A stable name for the situation, for `data-offer`. */
  key: string;
  body: string;
  action: string;
  href: string;
};

/** The foot of Protection: the one line, one link, and "Not now". */
export function protectionOffer(): Offer {
  return {
    slot: "protection",
    key: "protection",
    body: GENERIC_LINE,
    action: "Compare the editions",
    href: EDITIONS_URL,
  };
}

/**
 * Said in place of the offer on a machine where the paid edition is
 * installed. INSTALLED, never armed: this dashboard runs without privileges
 * and cannot read the host stack, so it claims nothing about what runs there.
 */
export const INSTALLED_LINE = {
  lead: "InnerWarden Pro is installed on this host.",
  body: "This dashboard runs without privileges and cannot read it, so it does not say what is running there. Ask the host:",
  command: "innerwarden get status",
} as const;
