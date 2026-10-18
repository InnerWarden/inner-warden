import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactElement } from "react";
import type { CommunityScreenContext } from "../App";
import type { AgentsResponse, DashboardMeta, TokenIntelligenceResponse } from "../api";
import { MachineIntelligenceSeed } from "../components/MachineIntelligence";
import { setTechnicalDetail } from "../components/TechnicalDetail";
import overviewFixture from "../../tests/fixtures/community/overview.json";
import page1 from "../../tests/fixtures/community/decisions-page-1.json";
import byId from "../../tests/fixtures/community/decisions-by-id.json";
import historyFixture from "../../tests/fixtures/community/history.json";
import agentsFixture from "../../tests/fixtures/community/agents.json";
import tokensFixture from "../../tests/fixtures/community/token-intelligence.json";
import { readDecisionDetail, readDecisionsPage, readHistory, readRecordHealth } from "./api";

/**
 * The identity screens (agent trust, lifecycle, instances, the layer that
 * decided, the Changes list and the one Active Defence line), rendered from a
 * payload that carries the fields, and from the CLI's own fixtures that do
 * not. What is asserted is what a reader sees.
 */
const answers = new Map<string, unknown>();

vi.mock("./poll", () => ({
  usePolled: (_load: unknown, _delay: number, key = "") => {
    const lookup = key.startsWith("{") ? "decisions" : key.startsWith("recent-without:") ? "recent-without" : key;
    const data = answers.get(lookup);
    return data === undefined
      ? { loading: true, stale: false, refresh: () => undefined }
      : { data, loading: false, stale: false, refresh: () => undefined };
  },
}));

const { CommunityOverview } = await import("./Overview");
const { CommunityAgents } = await import("./Agents");
const { CaseDetail } = await import("./CaseDetail");

const META: DashboardMeta = { version: "1.5.0", exposed: false, edition: "community", guardrail: { mode: "partial", guarded_agents: 3 } };

function context(meta: DashboardMeta = META): CommunityScreenContext {
  return {
    meta,
    metaStatus: "ready",
    navigate: () => undefined,
    search: "",
    bootstrap: { platform: { os: "macos", architecture: "arm64", enterprise_candidate: false, reason_code: null } } as never,
  };
}

const ID_A = "3f9a0c1e5b7d42a8c6e1f0b2d4a69c87";
const ID_B = "7a1b2c3d4e5f60718293a4b5c6d7e8f9";

function instance(id: string, trust: string, reason: string, extra: Record<string, unknown> = {}) {
  return {
    instance_id: id,
    trust,
    trust_reason: reason,
    trust_source: "jail",
    user: "dev",
    uid: 1000,
    project: "payments-api",
    mode: "enforce",
    started_at: "2026-10-16T09:12:03Z",
    last_activity_at: "2026-10-16T09:40:51Z",
    live: true,
    sessions: [{ session: "a1b2c3d4", first_at: "2026-10-16T09:12:10Z", last_at: "2026-10-16T09:40:51Z", case_id: "cmd:abc:0" }],
    technical: { jail_pid: 2778, jail_start_ticks: 1234567, pid_ns: 4026532220, scope_unit: `innerwarden-contain-${id}.scope`, launcher_path: "/home/dev/.local/bin/innerwarden", launcher_root_owned: false },
    ...extra,
  };
}

const CONFINE = { label: "Start it in a jail", command: "innerwarden contain --identity -- claude", line: "Runs Claude Code in a jail it cannot leave." };

/** The CLI's agents fixture with identity fields added to two of its agents. */
function withIdentity(): AgentsResponse {
  const agents = (agentsFixture as unknown as AgentsResponse).agents.map((agent) => {
    if (agent.id === "claude-code") {
      return {
        ...agent,
        lifecycle: "discovered",
        profile: { name: null, label: "General rules", source: null, confined_instances: 1, other_instances: 1, applies_from: "now" },
        trust: "host_verified",
        trust_reason: "confined_by_namespace",
        confine_step: CONFINE,
        decision_steps: [{ label: "To approve it:", command: "innerwarden agents approve claude-code", line: "You choose an owner and a profile." }],
        instances: [instance(ID_A, "host_verified", "confined_by_namespace"), instance(ID_B, "observed", "launcher_not_trusted", { live: true })],
      };
    }
    if (agent.id === "codex") {
      return {
        ...agent,
        running: true,
        lifecycle: "approved",
        lifecycle_by: "dev",
        lifecycle_at: "2026-10-15T08:00:00Z",
        owner: "maria",
        profile: { name: "engineering", label: "Engineering", source: "user", confined_instances: 0, other_instances: 0, applies_from: "now" },
        trust: "declared",
        trust_reason: "no_instance",
      };
    }
    return agent;
  });
  return { ...(agentsFixture as unknown as AgentsResponse), agents };
}

const DECISION_LINES = [
  { ts: "2026-10-16T10:00:00Z", action: "agent_approve", agent: "codex", by: "dev", result: "success", owner: "maria", profile_after: "Engineering" },
  { ts: "2026-10-16T11:00:00Z", action: "agent_profile", agent: "codex", by: "dev", result: "success", profile_before: "General rules", profile_after: "Engineering", confined_instances: 1 },
  { ts: "2026-10-16T12:00:00Z", action: "agent_revoke", agent: "claude-code", instance_id: ID_B, by: "dev", result: "failure: unknown_instance" },
];

function seed(agents: unknown = agentsFixture) {
  answers.clear();
  answers.set("overview", overviewFixture);
  answers.set("overview-record", overviewFixture);
  answers.set("recent-flagged", readDecisionsPage({ ...page1, items: page1.items.slice(0, 15) }));
  answers.set("decisions", readDecisionsPage(page1));
  answers.set("flagged-count", readDecisionsPage(page1));
  answers.set("agents", agents);
  answers.set("record-health", readRecordHealth({ recording: true }));
  answers.set("history", readHistory(historyFixture));
}

beforeEach(() => {
  seed();
  setTechnicalDetail(false);
  try {
    window.localStorage.clear();
  } catch {
    // No storage here: every offer reads as not dismissed.
  }
});
afterEach(() => setTechnicalDetail(false));

const render = (element: ReactElement, agents: unknown = agentsFixture) =>
  renderToStaticMarkup(
    <MachineIntelligenceSeed.Provider value={{ agents: agents as AgentsResponse, tokens: tokensFixture as unknown as TokenIntelligenceResponse }}>
      {element}
    </MachineIntelligenceSeed.Provider>,
  );

const ENTITIES: Record<string, string> = { "&#x27;": "'", "&quot;": '"', "&lt;": "<", "&gt;": ">", "&amp;": "&" };
function textOf(html: string): string {
  let text = html;
  let previous: string;
  do {
    previous = text;
    text = text.replace(/<[^<>]*>/g, "");
  } while (text !== previous);
  return text.replace(/&(?:#x27|quot|lt|gt|amp);/g, (entity) => ENTITIES[entity]);
}

const NEW_MARKERS = [
  "data-agent-identity",
  "data-trust",
  "data-instance",
  "data-lifecycle",
  "data-agent-trust",
  "data-agents-waiting",
  "data-agent-changes",
  "data-case-identity",
  "data-decided-by-layer",
  'data-offer="agent_kernel"',
  "Waits for your approval",
  "Profile:",
  "contain --identity",
  "data-profiles-invalid",
  "Invalid profiles file",
];

describe("with no identity data the screens are what they were", () => {
  for (const technical of [false, true]) {
    it(`Agents and Overview carry nothing new in the ${technical ? "technical" : "plain"} view`, () => {
      setTechnicalDetail(technical);
      for (const html of [render(<CommunityAgents context={context()} />), render(<CommunityOverview context={context()} />)]) {
        for (const marker of NEW_MARKERS) expect(html, marker).not.toContain(marker);
        expect(html).not.toContain(">Changes<");
      }
    });
  }

  it("the agents fixture yields rows with no identity, and the page draws the same with or without the context", () => {
    expect(render(<CommunityAgents context={context()} />)).toBe(render(<CommunityAgents />));
  });

  it("a case with no identity has no identity block and no layer line", () => {
    const [id] = Object.keys(byId);
    const detail = readDecisionDetail((byId as Record<string, unknown>)[id]);
    const html = render(<CaseDetail item={detail.item} before={[]} after={[]} os="macos" installed={false} onOpen={() => undefined} onSession={() => undefined} />);
    expect(html).not.toContain("data-case-identity");
    expect(html).not.toContain("data-decided-by-layer");
  });
});

describe("the Agents page with identity data", () => {
  it("shows the worst live instance's trust, the profile, the lifecycle and the instances", () => {
    seed(withIdentity());
    const html = render(<CommunityAgents context={context()} />, withIdentity());
    const row = html.slice(html.indexOf('data-agent="claude-code"'), html.indexOf('data-agent="codex"'));
    // The row says what its worst live instance says, not what it claims.
    expect(row).toContain('data-trust="observed"');
    expect(row).not.toMatch(/<li data-agent="claude-code"[^>]*>[\s\S]*?data-trust="host_verified"[\s\S]*?data-instance=/);
    const text = textOf(row);
    expect(text).toContain("Waits for your approval");
    expect(text).toContain("Profile: General rules");
    expect(text).toContain("dev in payments-api");
    expect(text).toContain("Refuses");
    expect(text).toContain("The launcher is installed in your home folder, so any program you run could replace it: install it system-wide.");
    expect(text).toContain("a1b2c3d4 (open case)");
    expect(text).toContain("Start it in a jail");
    expect(text).toContain("innerwarden contain --identity -- claude");
    expect(text).toContain("innerwarden agents approve claude-code");
    const codex = textOf(html.slice(html.indexOf('data-agent="codex"'), html.indexOf('data-agent="cursor"')));
    expect(codex).toContain("Owner: maria");
    expect(codex).toContain("Approved by dev");
    expect(codex).toContain("Profile: Engineering");
    expect(codex).toContain("Started without a jail: only its own word says what it is.");
    expect(codex).toContain("No instance started in a jail yet.");
  });

  it("makes one Active Defence line when a contained agent is shown, and the installed line on a host that has it", () => {
    seed(withIdentity());
    const html = render(<CommunityAgents context={context()} />, withIdentity());
    expect(html.match(/data-offer=/g)?.length).toBe(1);
    expect(html).toContain('data-offer="agent_kernel"');
    expect(textOf(html)).toContain("Contained agents are checked by the kernel with Active Defence.");
    expect([...html.matchAll(/href="(https:\/\/innerwarden\.com[^"]*)"/g)].map((m) => m[1])).toEqual(["https://innerwarden.com/pricing"]);
    const installed = render(<CommunityAgents context={context({ ...META, active_defence_installed: true })} />, withIdentity());
    expect(installed).not.toContain("data-offer");
    expect(installed).toContain('data-ad-state="installed"');
  });

  it("makes no offer when no instance is shown", () => {
    const only = withIdentity();
    only.agents = only.agents.map((agent) => ({ ...agent, instances: [] }));
    seed(only);
    expect(render(<CommunityAgents context={context()} />, only)).not.toContain("data-offer");
  });

  it("lists what people decided, newest as the CLI sent it, refusals included", () => {
    seed(withIdentity());
    answers.set("history", readHistory({ ...historyFixture, agent_decisions: DECISION_LINES }));
    const text = textOf(render(<CommunityAgents context={context()} />, withIdentity()));
    expect(text).toContain("dev approved Codex, owner maria, profile Engineering.");
    expect(text).toContain("dev changed the Codex profile from General rules to Engineering. Applies to 1 confined instance.");
    expect(text).toContain("dev tried to revoke instance 7a1b2c3d. Refused: unknown instance.");
  });

  it("says Protected or Protecting nowhere, in either view", () => {
    seed(withIdentity());
    for (const technical of [false, true]) {
      setTechnicalDetail(technical);
      const html = render(<CommunityAgents context={context()} />, withIdentity());
      expect(textOf(html)).not.toMatch(/\bProtect(ed|ing)\b/);
    }
  });

  it("keeps the colour jobs: amber only for the agent that waits for a person, never emerald", () => {
    seed(withIdentity());
    const html = render(<CommunityAgents context={context()} />, withIdentity());
    expect(html).not.toMatch(/emerald-/);
    for (const match of html.matchAll(/<span([^>]*)class="[^"]*amber-[^"]*"/g)) expect(match[1]).toContain("data-needs-you");
  });

  it("technical view adds the instance's facts and who decided its trust", () => {
    seed(withIdentity());
    setTechnicalDetail(true);
    const text = textOf(render(<CommunityAgents context={context()} />, withIdentity()));
    expect(text).toContain(`Instance ${ID_A}`);
    expect(text).toContain("Jail pid 2778, started at tick 1234567");
    expect(text).toContain("Trust read by: the hook inside the jail (launcher_not_trusted)");
    expect(text).not.toContain("Trust decided by");
    expect(text).toContain("Launcher /home/dev/.local/bin/innerwarden, owned by root: no");
  });
});

/** `withIdentity()` with user-namespace facts added to the technical block of each live instance. */
function withUserns(technicalFor: (id: string) => Record<string, unknown>): AgentsResponse {
  type Row = { instances?: { instance_id: string; technical?: object }[] };
  const base = withIdentity();
  return {
    ...base,
    agents: base.agents.map((agent) => ({
      ...agent,
      instances: ((agent as unknown as Row).instances ?? []).map((item) => ({ ...item, technical: { ...item.technical, ...technicalFor(item.instance_id) } })),
    })),
  } as unknown as AgentsResponse;
}

describe("user namespaces inside the jail, in the technical view", () => {
  const USERNS_A = { userns_closed: true };
  const USERNS_B = { userns_open_reason: "bwrap_too_old" };

  it("says they were closed by the sandbox filter, and nothing for a jail that did not", () => {
    const agents = withUserns((id) => (id === ID_A ? USERNS_A : USERNS_B));
    seed(agents);
    setTechnicalDetail(true);
    const text = textOf(render(<CommunityAgents context={context()} />, agents));
    expect(text).toContain("User namespaces closed inside the jail (sandbox filter).");
    expect(text.match(/User namespaces closed/g)?.length).toBe(1);
    expect(text).not.toContain("Bubblewrap here");
    // A value that is not `true` is not shown.
    const strange = withUserns(() => ({ userns_open_reason: "<b>x</b>", userns_closed: "yes" }));
    seed(strange);
    const other = textOf(render(<CommunityAgents context={context()} />, strange));
    expect(other).not.toContain("User namespaces closed");
    expect(other).not.toContain("Bubblewrap here");
  });

  it("is not a reason: the plain view, the trust and the reasons are what they were", () => {
    const base = withIdentity();
    seed(base);
    const before = render(<CommunityAgents context={context()} />, base);
    const agents = withUserns((id) => (id === ID_A ? USERNS_A : USERNS_B));
    seed(agents);
    const after = render(<CommunityAgents context={context()} />, agents);
    expect(after).toBe(before);
    expect(textOf(after)).not.toContain("namespaces");
  });
});

describe("the Overview with identity data", () => {
  it("says how far the agents are backed in one sentence, and counts the ones waiting", () => {
    const agents = withIdentity();
    seed(agents);
    const html = render(<CommunityOverview context={context()} />, agents);
    const text = textOf(html);
    // The CLI's payload claims host_verified for one instance; a reading from
    // inside the jail is shown at observed, so nothing here runs confined.
    expect(text).toContain("3 agents on this Mac. 2 run in a jail nothing outside it has confirmed; 1 runs as you, and only its own word says what it is.");
    expect(text).not.toContain("runs confined");
    expect(text).toContain("1 new agent waits for your approval.");
    const waiting = html.slice(html.indexOf("data-agents-waiting") - 80);
    expect(waiting.slice(0, 200)).toContain("data-needs-you");
  });

  it("adds nothing when the CLI sends no instance", () => {
    const agents = withIdentity();
    agents.agents = agents.agents.map((agent) => ({ ...agent, instances: [] }));
    seed(agents);
    expect(render(<CommunityOverview context={context()} />, agents)).not.toContain("data-agent-trust");
  });
});

describe("a case with identity", () => {
  function detailWith(identity: Record<string, unknown>, recommendation: string) {
    const entry = Object.values(byId as Record<string, { item: { recommendation: string; agent?: string } }>).find((e) => e.item.recommendation === recommendation)!;
    return readDecisionDetail({ ...entry, item: { ...entry.item, identity } });
  }
  const html = (identity: Record<string, unknown>, recommendation: string, os: "macos" | "linux" = "macos", installed = false) => {
    const detail = detailWith(identity, recommendation);
    return render(<CaseDetail item={detail.item} before={[]} after={[]} os={os} installed={installed} onOpen={() => undefined} onSession={() => undefined} />);
  };

  it("names the instance and session, the trust and why, and the layer that decided", () => {
    const out = html({ instance_id: ID_A, session_id: "a1b2c3d4-0000", trust: "observed", trust_reason: "launcher_not_trusted", deciding_layer: "general", profile: null, relaxation_withheld: true }, "review");
    const text = textOf(out);
    expect(text).toContain(`, instance 3f9a0c1e, session a1b2c3d4`);
    expect(text).toContain("Observed");
    expect(text).toContain("install it system-wide");
    expect(text).toContain("Sent for review by your general rules.");
    expect(text).toContain("Per-agent relaxations do not apply on macOS: a jail there has no boundary a witness outside it can check.");
    expect(out.match(/data-relaxation-withheld/g)?.length).toBe(1);
  });

  it("says why a relaxation did not apply in the words of the page it is on", () => {
    const withheld = { instance_id: ID_A, trust: "observed", trust_reason: "confined_by_namespace", deciding_layer: "general", profile: "claude-code", relaxation_withheld: true };
    expect(textOf(html(withheld, "review", "linux", false))).toContain(
      "Per-agent relaxations apply on Linux with Active Defence, for an agent started with innerwarden contain --identity.",
    );
    expect(textOf(html(withheld, "review", "linux", true))).toContain("Active Defence on this host did not decide this command, so your general rules decided.");
    const kept = { ...withheld, trust_source: "host", host_decision: "0f1e2d3c4b5a69788796a5b4c3d2e1f0", host_withheld: "a_word_never_heard" };
    const text = textOf(html(kept, "review", "linux", true));
    expect(text).toContain("Active Defence on this host kept your general rules for this command.");
    expect(text).not.toContain("a_word_never_heard");
    // The technical view names who read the trust and who decided the rules,
    // and still never the host's word: the one sentence is all it says.
    setTechnicalDetail(true);
    const technical = textOf(html(kept, "review", "linux", true));
    expect(technical).toContain("Trust read by: the hook inside the jail (confined_by_namespace).");
    expect(technical).toContain("Rules decided by: Active Defence on this host (decision 0f1e2d3c4b5a69788796a5b4c3d2e1f0).");
    expect(technical).not.toContain("Trust decided by");
    expect(technical).not.toContain("a_word_never_heard");
    expect(technical).not.toContain("Host word");
    setTechnicalDetail(false);
    const none = { ...withheld, relaxation_withheld: false };
    expect(html(none, "review", "linux", true)).not.toContain("data-relaxation-withheld");
  });

  it("words an allowance the host decided neutrally, at observed, with no green badge", () => {
    const decided = {
      instance_id: ID_A,
      trust: "host_verified",
      trust_reason: "host_decided",
      trust_source: "host",
      host_decision: "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
      deciding_layer: "agent_type",
      profile: "claude-code",
      relaxation_withheld: false,
    };
    const out = html(decided, "allow", "linux", true);
    const text = textOf(out);
    expect(text).toContain("decided by Active Defence on this host.");
    expect(out).not.toContain("data-identity-conflict");
    expect(text).toContain("Observed");
    expect(text).not.toContain("Confined");
    expect(out).toContain('title="Read from inside the jail; Active Defence on this host decided its rules."');
    // A host label without the host's decision is not taken as one.
    const bare = { ...decided, host_decision: undefined };
    expect(html(bare, "allow", "linux", true)).toContain("data-identity-conflict");
  });

  it("words a product rule as one nothing changes", () => {
    const text = textOf(html({ instance_id: ID_A, trust: "host_verified", trust_reason: "confined_by_namespace", deciding_layer: "hard", relaxation_withheld: false }, "deny"));
    expect(text).toContain("Refused by a product rule no setting changes. Nothing to change here.");
    expect(text).toContain("Observed");
    expect(text).not.toContain("Confined");
  });

  it("does not word an allowance by a profile for an instance that is not confined", () => {
    const out = html({ instance_id: ID_A, trust: "host_verified", trust_reason: "no_record", deciding_layer: "agent_type", profile: "engineering", relaxation_withheld: false }, "allow");
    const text = textOf(out);
    expect(out).toContain("data-identity-conflict");
    expect(text).toContain("nothing outside its jail confirmed the jail");
    expect(text).not.toContain("because this instance runs confined");
    expect(text).not.toContain("Confined");
  });
});

describe("an unusable profiles file is never silence", () => {
  it("says the file cannot be used, in the CLI's words, and guesses no decision", () => {
    const agents = {
      ...(agentsFixture as unknown as AgentsResponse),
      profiles_file: { state: "invalid", sentence: "The agent profiles file cannot be used (/etc/innerwarden/agent-profiles.toml: bad key)." },
    };
    seed(agents);
    const out = render(<CommunityAgents context={context()} />, agents);
    expect(out).toContain("data-profiles-invalid");
    const text = textOf(out);
    expect(text).toContain("Invalid profiles file");
    expect(text).toContain("The agent profiles file cannot be used (/etc/innerwarden/agent-profiles.toml: bad key).");
    expect(out).not.toContain("data-lifecycle");
  });
});
