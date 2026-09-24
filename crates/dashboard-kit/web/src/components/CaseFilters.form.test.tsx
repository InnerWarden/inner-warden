import { isValidElement, type ReactElement, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  appliedCaseView,
  CaseFilters,
  CaseFiltersForm,
  EMPTY_CASE_VIEW,
  writeCaseViewState,
  type CaseViewState,
} from "./CaseFilters";

/**
 * What each control on the Cases filter form does to the draft, and what
 * Apply and Clear hand back to the screen.
 *
 * This package has no DOM in its unit tests, so the form is driven the way the
 * browser drives it: render it with the draft handed in, find the control by
 * the label a person reads, call the handler it carries with the event a
 * browser would send, and render again with the draft that came back. The form
 * holds no state of its own (`CaseFiltersForm`), which is what makes that
 * possible; `CaseFilters` only keeps the draft between renders.
 */

type Props = Record<string, unknown> & { children?: ReactNode };
type Element = ReactElement<Props>;

/** The host elements the form draws, with every component in it rendered out. */
function hostElements(node: ReactNode): Element[] {
  if (Array.isArray(node)) return node.flatMap(hostElements);
  if (!isValidElement<Props>(node)) return [];
  if (typeof node.type === "function") {
    return hostElements((node.type as (props: Props) => ReactNode)(node.props));
  }
  return [node, ...hostElements(node.props.children)];
}

/** The text of a node, as a person reads it. */
function text(node: ReactNode): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(text).join("");
  if (isValidElement<Props>(node)) return text(node.props.children);
  return "";
}

/**
 * The one control whose label reads `label`. Labels here wrap their control,
 * so the control is the `select` or `input` inside the `label` whose own text
 * (before the control) is exactly `label`.
 */
function control(tree: Element[], label: string): Element {
  const matches = tree.filter((element) => {
    if (element.type !== "label") return false;
    const children = [element.props.children].flat();
    return typeof children[0] === "string" && children[0] === label;
  });
  if (matches.length !== 1) throw new Error(`expected one control labelled ${label}, found ${matches.length}`);
  const inside = hostElements(matches[0].props.children).filter((element) => element.type === "select" || element.type === "input");
  if (inside.length !== 1) throw new Error(`the label ${label} does not wrap exactly one control`);
  return inside[0];
}

function button(tree: Element[], name: string): Element {
  const found = tree.filter((element) => element.type === "button" && text(element).trim() === name);
  if (found.length !== 1) throw new Error(`expected one button named ${name}, found ${found.length}`);
  return found[0];
}

/**
 * A form the test can operate: it keeps the draft the way `CaseFilters` does,
 * and draws the form again after every change.
 */
function operate(start: CaseViewState, disabled = false) {
  let draft = start;
  const applied: CaseViewState[] = [];
  let cleared = 0;
  const draw = () => hostElements(
    <CaseFiltersForm
      draft={draft}
      disabled={disabled}
      onDraft={(update) => { draft = update(draft); }}
      onApply={(next) => applied.push(next)}
      onClear={() => { cleared += 1; }}
    />,
  );
  return {
    get draft() { return draft; },
    applied,
    get cleared() { return cleared; },
    tree: draw,
    choose(label: string, value: string) {
      const onChange = control(draw(), label).props.onChange as (event: { target: { value: string } }) => void;
      onChange({ target: { value } });
    },
    submit() {
      const form = draw().find((element) => element.type === "form");
      if (form === undefined) throw new Error("the filters draw no form");
      const preventDefault = vi.fn();
      (form.props.onSubmit as (event: { preventDefault: () => void }) => void)({ preventDefault });
      return preventDefault;
    },
    click(name: string) {
      (button(draw(), name).props.onClick as () => void)();
    },
  };
}

describe("the case filter form", () => {
  it("sends every choice on Apply, trimmed, from the first page", () => {
    const form = operate({ ...EMPTY_CASE_VIEW, cursor: "opaque-page-3" });
    form.choose("Search cases", "  curl  ");
    form.choose("Outcome", "failed");
    form.choose("Severity", "critical");
    form.choose("Status", "waiting");
    form.choose("Mode", "enforce");
    form.choose("Decision authority", "agent-guard");
    form.choose("Capability", "agent_boundary");
    form.choose("Time window", "7d");
    form.choose("Scope type", "agent");
    form.choose("Scope identifier", " agent:claude ");

    // Nothing is applied while the operator is still choosing.
    expect(form.applied).toEqual([]);
    const preventDefault = form.submit();

    // The page must not reload on submit: the filters travel in the address
    // bar through the screen, not through a form post.
    expect(preventDefault).toHaveBeenCalledOnce();
    expect(form.applied).toEqual([{
      ...EMPTY_CASE_VIEW,
      query: "curl",
      outcome: "failed",
      severity: "critical",
      status: "waiting",
      mode: "enforce",
      authority: "agent-guard",
      capability: "agent_boundary",
      window: "7d",
      scopeKind: "agent",
      scopeId: "agent:claude",
      // The cursor belonged to the old result set; new filters start again.
      cursor: null,
    }]);
  });

  it("keeps each choice in the draft the next render shows", () => {
    const form = operate(EMPTY_CASE_VIEW);
    form.choose("Status", "contained");
    expect(form.draft.status).toBe("contained");
    expect(control(form.tree(), "Status").props.value).toBe("contained");
    form.choose("Time window", "all");
    expect(control(form.tree(), "Time window").props.value).toBe("all");
    // The earlier choice survives the later one.
    expect(form.draft.status).toBe("contained");
  });

  /**
   * The identifier box is disabled under "All scopes", so an identifier left
   * in it could not be seen or edited and would still filter. Choosing All
   * scopes drops it; moving between two real scope types keeps it.
   */
  it("drops the scope identifier when the scope type goes back to all", () => {
    const form = operate({ ...EMPTY_CASE_VIEW, scopeKind: "agent", scopeId: "agent:claude" });
    form.choose("Scope type", "host");
    expect(form.draft.scopeId).toBe("agent:claude");
    form.choose("Scope type", "all");
    expect(form.draft.scopeKind).toBe("all");
    expect(form.draft.scopeId).toBe("");
  });

  it("shuts the identifier box until a scope type is chosen, and says so", () => {
    const shut = control(operate(EMPTY_CASE_VIEW).tree(), "Scope identifier");
    expect(shut.props.disabled).toBe(true);
    expect(shut.props.placeholder).toBe("Choose a scope type first");

    const open = control(operate({ ...EMPTY_CASE_VIEW, scopeKind: "workload" }).tree(), "Scope identifier");
    expect(open.props.disabled).toBe(false);
    expect(open.props.placeholder).toBe("workload:…");
  });

  it("clears without applying the draft", () => {
    const form = operate(EMPTY_CASE_VIEW);
    form.choose("Severity", "high");
    form.click("Clear");
    expect(form.cleared).toBe(1);
    expect(form.applied).toEqual([]);
  });

  it("disables every control and both buttons while the screen cannot filter", () => {
    const tree = operate({ ...EMPTY_CASE_VIEW, scopeKind: "agent" }, true).tree();
    const controls = tree.filter((element) => element.type === "select" || element.type === "input" || element.type === "button");
    // Ten controls and two buttons: a count, so a control added later is not
    // silently left out of the check.
    expect(controls).toHaveLength(12);
    for (const element of controls) expect(element.props.disabled, text(element) || String(element.type)).toBe(true);
  });

  /**
   * The draft lives in `CaseFilters` and starts from the value the screen
   * hands it, so a filter set by a link (the Overview's waiting queue) is what
   * the form shows on arrival.
   */
  it("starts from the value the screen hands it", () => {
    const html = renderToStaticMarkup(
      <CaseFilters value={{ ...EMPTY_CASE_VIEW, status: "waiting", window: "all" }} onApply={() => undefined} onClear={() => undefined} />,
    );
    expect(html).toContain('<option value="waiting" selected="">Waiting for a decision</option>');
    expect(html).toContain('<option value="all" selected="">All loaded time</option>');
  });

  /**
   * Agent sessions with nothing for a person to decide are recorded as
   * `observing` by the paid host and left out of the waiting queue, so the
   * only way to list them is to ask for that status by name.
   */
  it("offers the sessions that are only watched, in words a reader understands", () => {
    const html = renderToStaticMarkup(
      <CaseFilters value={{ ...EMPTY_CASE_VIEW, status: "observing" }} onApply={() => undefined} onClear={() => undefined} />,
    );
    expect(html).toContain('<option value="observing" selected="">Watched, nothing to decide</option>');
  });
});

describe("what Apply hands the screen", () => {
  it("trims every typed field and nothing chosen from a list", () => {
    const next = appliedCaseView({
      ...EMPTY_CASE_VIEW,
      query: " a ",
      authority: " operator ",
      capability: " host_visibility ",
      scopeId: " host:one ",
      outcome: "failed",
      cursor: "opaque",
      selectedCase: "case-1",
    });
    expect(next).toEqual({
      ...EMPTY_CASE_VIEW,
      query: "a",
      authority: "operator",
      capability: "host_visibility",
      scopeId: "host:one",
      outcome: "failed",
      cursor: null,
      selectedCase: "case-1",
    });
  });
});

/**
 * The filters travel in the address bar. A new filter pushes a history entry,
 * so Back returns to the previous view; a correction replaces the current one,
 * so Back does not step through it. The browser's history is handed in.
 */
describe("writing the view to the address bar", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function stubWindow() {
    const history = { pushState: vi.fn(), replaceState: vi.fn() };
    vi.stubGlobal("window", { location: { href: "https://dashboard.test/?view=overview" }, history });
    return history;
  }

  it("pushes a new entry by default", () => {
    const history = stubWindow();
    writeCaseViewState({ ...EMPTY_CASE_VIEW, status: "waiting" });
    expect(history.replaceState).not.toHaveBeenCalled();
    expect(history.pushState).toHaveBeenCalledOnce();
    const url = history.pushState.mock.calls[0][2] as URL;
    expect(url.searchParams.get("view")).toBe("cases");
    expect(url.searchParams.get("status")).toBe("waiting");
  });

  it("replaces the current entry when asked to", () => {
    const history = stubWindow();
    writeCaseViewState({ ...EMPTY_CASE_VIEW, window: "7d" }, "replace");
    expect(history.pushState).not.toHaveBeenCalled();
    expect(history.replaceState).toHaveBeenCalledOnce();
    expect((history.replaceState.mock.calls[0][2] as URL).searchParams.get("window")).toBe("7d");
  });
});
