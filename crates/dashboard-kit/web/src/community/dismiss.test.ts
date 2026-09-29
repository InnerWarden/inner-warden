import { describe, expect, it } from "vitest";
import { dismiss, dismissed, OFFER_KEYS } from "./dismiss";

function memory() {
  const store = new Map<string, string>();
  return {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => void store.set(key, value),
    store,
  };
}

const throwing = {
  getItem: () => {
    throw new Error("blocked");
  },
  setItem: () => {
    throw new Error("blocked");
  },
};

describe("Not now", () => {
  it("is remembered per slot, under a key that carries the copy version", () => {
    const storage = memory();
    expect(dismissed("case", storage)).toBe(false);
    dismiss("case", storage);
    expect(dismissed("case", storage)).toBe(true);
    expect(dismissed("server", storage)).toBe(false);
    for (const key of Object.values(OFFER_KEYS)) expect(key).toMatch(/-v1:/);
  });

  it("reads a storage that throws as not dismissed, and never throws itself", () => {
    expect(dismissed("server", throwing)).toBe(false);
    expect(() => dismiss("server", throwing)).not.toThrow();
    expect(dismissed("server", undefined)).toBe(false);
  });
});
