/**
 * How a command is drawn in a row: in segments, and never with any of its
 * text taken away (T7). A row clamps from the END, so the start and the
 * middle are always on screen, and the whole command is in the row's title,
 * in the detail and in the copy.
 *
 * The one thing this does is draw a leading `cd <folder> && ` in muted ink,
 * so the command that ran after it reads first. Only when the folder is a
 * plain word: a folder holding a shell metacharacter (`$`, a backtick, `;`,
 * `|`, `&`, a bracket, a quote, a backslash or a newline) could itself run
 * something, and a muted segment must never be one a reader skims past.
 */
export type CommandSegment = { text: string; muted: boolean };

const PLAIN_CD = /^cd [^\s$`;|&()<>'"\\]+ && /;

export function commandSegments(command: string): CommandSegment[] {
  const prefix = PLAIN_CD.exec(command)?.[0];
  if (prefix === undefined) return [{ text: command, muted: false }];
  const rest = command.slice(prefix.length);
  return rest.length === 0 ? [{ text: prefix, muted: true }] : [{ text: prefix, muted: true }, { text: rest, muted: false }];
}

/** The text a set of segments draws: always the command it was made from. */
export function segmentsText(segments: readonly CommandSegment[]): string {
  return segments.map((segment) => segment.text).join("");
}
