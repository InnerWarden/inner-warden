/**
 * The ten published titles of the OWASP Top 10 for Agentic Applications
 * (2026), so a case never prints "ASI05" without saying what it is. The same
 * titles the guard's own taxonomy carries.
 */
export const ASI_NAMES: Readonly<Record<string, string>> = {
  ASI01: "Agent goal hijack",
  ASI02: "Tool misuse and exploitation",
  ASI03: "Identity and privilege abuse",
  ASI04: "Agentic supply chain vulnerabilities",
  ASI05: "Unexpected code execution",
  ASI06: "Memory and context poisoning",
  ASI07: "Insecure inter-agent communication",
  ASI08: "Cascading failures",
  ASI09: "Human-agent trust exploitation",
  ASI10: "Rogue agents",
};

/** "ASI05 Unexpected code execution", or the id alone when it is not one of the ten. */
export function asiLabel(id: string): string {
  const name = ASI_NAMES[id];
  return name === undefined ? id : `${id} ${name}`;
}
