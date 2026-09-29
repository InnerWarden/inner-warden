/**
 * A Tailwind class that only a SHARED screen uses, for a composing build to
 * check that its stylesheet was generated from the kit's sources.
 *
 * A composed bundle's stylesheet holds only the classes its Tailwind scan
 * found; a scan that missed the kit tree still builds, and ships a page
 * without half its styles. The paid build proved the scan by looking for a
 * height class only the old Activity screen used: when that screen was
 * removed the sentinel went with it. This names one a shared screen keeps
 * (`screens/Home.tsx`), and a test fails the moment Home stops using it, so
 * the sentinel is moved on purpose, never lost by accident.
 *
 * No comment in the kit may spell the retired class out: Tailwind reads
 * comments too, and a class named in one would satisfy the old check for the
 * wrong reason (a test here holds it).
 */
export const SHARED_STYLESHEET_SENTINEL = "h-11";

/** Where the sentinel lives in the kit's own sources. */
export const SHARED_STYLESHEET_SENTINEL_SOURCE = "src/screens/Home.tsx";
