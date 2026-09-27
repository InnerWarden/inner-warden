/** How often the posture surfaces re-fetch.
 *
 * These polled every 5 seconds while the evidence behind them refreshes every
 * 20 minutes (the effect-canary interval), so 239 of every 240 requests
 * returned the same proof and the screen repainted anyway. The visible cost was
 * a freshness line reading "checked 0s ago" that reset as you watched it, which
 * reads as a system that never settles.
 *
 * Posture is a slow fact: what is armed changes on deploys and incidents, not
 * second to second. It now refreshes on a cadence the evidence can justify, and
 * an operator who wants an answer NOW presses Check now rather than waiting out
 * a poll. Faster-moving screens keep their own cadence; this is the posture
 * pair only.
 *
 * Its own module so Protection can bound how long a verification it made on
 * one read may be held (`heldAssurance`) without importing the shell.
 */
export const POSTURE_REFRESH_MS = 5 * 60_000;
