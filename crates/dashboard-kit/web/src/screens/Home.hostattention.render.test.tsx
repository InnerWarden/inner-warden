import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { HostAttention } from "./Home";

/**
 * "8 addresses are waiting on you" was a dead end: a number, and no way to
 * the cases it counts. The way through is a button to the waiting queue, and
 * it is offered only when there is somewhere to go AND something to see.
 *
 * These RENDER the section. Reverting `through` to `onOpen !== undefined`
 * makes the second test fail: a link to an empty list under "nothing is
 * waiting".
 */
const waiting = { addresses_waiting: 8, counts: "distinct external addresses, today" };
const nothing = { addresses_waiting: 0, counts: "distinct external addresses, today" };

describe("the way through from what is waiting", () => {
  it("offers the queue when something is waiting and there is a Cases screen", () => {
    const html = renderToStaticMarkup(<HostAttention waiting={waiting} onOpen={() => undefined} />);
    expect(html).toContain("8 addresses are waiting on you");
    expect(html).toContain("See what is waiting");
    expect(html).toContain("<button");
  });

  it("offers nothing under good news", () => {
    const html = renderToStaticMarkup(<HostAttention waiting={nothing} onOpen={() => undefined} />);
    expect(html).toContain("Nothing on the host is waiting for you");
    expect(html).not.toContain("See what is waiting");
    expect(html).not.toContain("<button");
  });

  it("offers nothing when the shell has no Cases screen to open", () => {
    const html = renderToStaticMarkup(<HostAttention waiting={waiting} />);
    expect(html).toContain("8 addresses are waiting on you");
    expect(html).not.toContain("<button");
  });

  it("renders nothing at all for a build with no host layer", () => {
    expect(renderToStaticMarkup(<HostAttention waiting={undefined} onOpen={() => undefined} />)).toBe("");
  });
});
