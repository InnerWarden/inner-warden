/**
 * "Not now" on an offer, remembered in this browser only.
 *
 * Storage can be missing, blocked or throwing (a private window, an embedded
 * view); each reads as NOT dismissed, so the worst a broken storage does is
 * show an offer once more. Nothing else ever re-shows a dismissed offer: the
 * key carries a copy version, and only changed copy moves it.
 */

export const OFFER_KEYS = {
  server: "iw-community-offer-v1:server",
  case: "iw-community-offer-v1:case",
  protection: "iw-community-offer-v1:protection",
} as const;

export type OfferSlot = keyof typeof OFFER_KEYS;

type OfferStorage = Pick<Storage, "getItem" | "setItem">;

function browserStorage(): OfferStorage | undefined {
  try {
    return typeof window === "undefined" ? undefined : window.localStorage;
  } catch {
    return undefined;
  }
}

export function dismissed(slot: OfferSlot, storage: OfferStorage | undefined = browserStorage()): boolean {
  try {
    const value = storage?.getItem(OFFER_KEYS[slot]);
    return value !== null && value !== undefined;
  } catch {
    return false;
  }
}

export function dismiss(slot: OfferSlot, storage: OfferStorage | undefined = browserStorage()): void {
  try {
    storage?.setItem(OFFER_KEYS[slot], new Date().toISOString());
  } catch {
    // Not remembering costs the reader the same offer once more; nothing else.
  }
}
