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
    expect(html).toContain("See all waiting cases, from any day");
    expect(html).toContain("<button");
  });

  /**
   * The button used to read "See what is waiting" directly under "8
   * addresses", and opened every waiting CASE of ALL time: a list that can be
   * hundreds of rows long. What the reader is promised is now what they get,
   * and the difference is said beside the button, not left to be discovered.
   */
  it("says what the link opens, and that it is not the number above it", () => {
    const html = renderToStaticMarkup(<HostAttention waiting={waiting} onOpen={() => undefined} />);
    expect(html).not.toContain("See what is waiting");
    expect(html).toContain("cases rather than addresses");
    expect(html).toContain("cases as well as the host");
    expect(html).toContain("longer than this number");
  });

  it("offers nothing under good news", () => {
    const html = renderToStaticMarkup(<HostAttention waiting={nothing} onOpen={() => undefined} />);
    expect(html).toContain("Nothing on the host is waiting for you");
    expect(html).not.toContain("waiting cases");
    expect(html).not.toContain("<button");
  });

  it("offers nothing when the shell has no Cases screen to open", () => {
    const html = renderToStaticMarkup(<HostAttention waiting={waiting} />);
    expect(html).toContain("8 addresses are waiting on you");
    expect(html).not.toContain("<button");
    // The note explains the link; without the link it would explain nothing.
    expect(html).not.toContain("longer than this number");
  });

  it("renders nothing at all for a build with no host layer", () => {
    expect(renderToStaticMarkup(<HostAttention waiting={undefined} onOpen={() => undefined} />)).toBe("");
  });
});
