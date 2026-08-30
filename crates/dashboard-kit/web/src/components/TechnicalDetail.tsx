import { useCallback, useEffect, useState, type ReactNode } from "react";

/**
 * Two readers, one screen.
 *
 * Someone who bought this wants to know two things: is it working, and is
 * there anything I have to do. Someone auditing it wants to know exactly what
 * was proven, by whom, and what was only recorded. Those are different needs
 * and the screen had been answering the second one to both, so a healthy host
 * read as a wall of doubt: "Configured, not verified", "Authority unknown",
 * "mode unknown", "Local presence detected; installation not confirmed",
 * "Outcome claim withheld".
 *
 * Every one of those sentences is TRUE. That is why none of them are deleted
 * here. They move behind a switch instead, so the default answer is the plain
 * one and the evidence is one click away for whoever wants it.
 *
 * The rule this file enforces: nothing that changes what an operator should DO
 * may hide behind the switch. A real problem, a queued action, a host that
 * needs attention, all stay visible in both modes. What hides is the
 * PROVENANCE of a good state, never the existence of a bad one.
 */

const STORAGE_KEY = "innerwarden.technical-detail";

/** Read once, synchronously, so the first paint is already correct. */
function readStored(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.localStorage.getItem(STORAGE_KEY) === "on";
  } catch {
    // Private mode, blocked storage, embedded webview. The plain view is the
    // safe default: it never hides a problem, only the evidence behind a
    // healthy state.
    return false;
  }
}

/**
 * Whether the reader has asked for the technical view.
 *
 * Deliberately a tiny module-level store rather than a context provider: the
 * setting is read by leaf components all over the tree, and threading a
 * provider through the enterprise delta and the shared kit would mean the two
 * bundles could end up with different defaults.
 */
let current = readStored();
const listeners = new Set<(value: boolean) => void>();

export function technicalDetailEnabled(): boolean {
  return current;
}

export function setTechnicalDetail(next: boolean): void {
  current = next;
  try {
    window.localStorage.setItem(STORAGE_KEY, next ? "on" : "off");
  } catch {
    // Not persisting is survivable; not applying would not be.
  }
  for (const listener of listeners) listener(next);
}

export function useTechnicalDetail(): [boolean, (next: boolean) => void] {
  const [value, setValue] = useState(current);
  useEffect(() => {
    listeners.add(setValue);
    return () => {
      listeners.delete(setValue);
    };
  }, []);
  const set = useCallback((next: boolean) => setTechnicalDetail(next), []);
  return [value, set];
}

/**
 * Show `children` only in the technical view.
 *
 * Use for provenance, verification wording, digests, authority names and
 * anything whose absence would not change a decision. Do NOT use it to hide a
 * warning, a failure, or work that is waiting on someone.
 */
export function TechnicalOnly({ children }: { children: ReactNode }) {
  const [enabled] = useTechnicalDetail();
  if (!enabled) return null;
  return <>{children}</>;
}

/**
 * Pick the wording for the current reader.
 *
 * Both strings must be true. This is a register change, not a softening: if the
 * plain sentence would leave someone believing they are protected when they are
 * not, the plain sentence is wrong and no switch can fix it.
 *
 * # Why `enabled` is a parameter and not read from the store
 *
 * The first version read the module store directly, and that is a subscription
 * bug wearing a convenience: a component calling it does not re-render when the
 * switch flips, so the text stayed on the old register until something else
 * happened to re-render that subtree. Taking the flag as an argument makes the
 * caller hold it, and the only sane way to hold it in a component is
 * `useTechnicalDetail`, which subscribes. The mistake is now unavailable rather
 * than merely documented.
 *
 * Pure helpers outside React (list summarisers, sort keys) take the flag from
 * whoever called them, which is a component.
 */
export function plainOrTechnical(plain: string, technical: string, enabled: boolean): string {
  return enabled ? technical : plain;
}

/** The switch itself. Small, and it says what it does. */
export function TechnicalDetailToggle({ className = "" }: { className?: string }) {
  const [enabled, setEnabled] = useTechnicalDetail();
  return (
    <label className={`inline-flex cursor-pointer items-center gap-2 text-xs text-slate-600 ${className}`}>
      <input
        type="checkbox"
        checked={enabled}
        onChange={(event) => setEnabled(event.target.checked)}
        className="h-3.5 w-3.5 rounded border-slate-300"
      />
      <span>Show technical detail</span>
    </label>
  );
}
