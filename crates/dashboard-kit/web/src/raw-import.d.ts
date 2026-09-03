/**
 * Vite's `?raw` suffix returns a module's source as a string. One test uses it
 * to assert that `Home` still passes the host's headline into `PostureHero`:
 * that wiring cannot be reached by rendering, because `Home` fills its state
 * from a `useEffect` and the server renderer does not run effects.
 *
 * Declared here rather than by pulling in `vite/client`, so the app's ambient
 * types stay limited to the one suffix that is actually used.
 */
declare module "*?raw" {
  const content: string;
  export default content;
}
