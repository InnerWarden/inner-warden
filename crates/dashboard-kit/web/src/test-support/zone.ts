/**
 * Pins the process's time zone for a test and hands back the undo.
 *
 * Every absolute time is printed in the reader's own zone, so a test that
 * pins markup containing one pins the zone too, or it passes on one machine
 * and fails on the next. Node applies an assignment to `TZ` at once. Read
 * through `globalThis` because the web tsconfig carries no Node types.
 */
type ProcessLike = { env: Record<string, string | undefined> };

export function pinZone(zone: string): () => void {
  const env = (globalThis as unknown as { process: ProcessLike }).process.env;
  const before = env.TZ;
  env.TZ = zone;
  return () => {
    if (before === undefined) delete env.TZ;
    else env.TZ = before;
  };
}
