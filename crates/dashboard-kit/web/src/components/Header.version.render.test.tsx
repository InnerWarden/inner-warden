import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, describe, expect, it } from "vitest";

import { Header, shortVersion } from "./Header";
import { setTechnicalDetail } from "./TechnicalDetail";

/**
 * The header printed "v0.16.66+g267f0bd58c3206867776988f2c20f458435f4968",
 * forty characters of build next to the product's name. A reader names the
 * release; the build is the evidence, and it is one switch away.
 */

afterEach(() => setTechnicalDetail(false));

const VERSION = "0.16.66+g267f0bd58c3206867776988f2c20f458435f4968";

const render = () => renderToStaticMarkup(
  <Header editionLabel="Enterprise" version={VERSION} navigation={[]} activeRoute="home" homeRoute="home" onNavigate={() => undefined} status={null} />,
);

describe("the version in the header", () => {
  it("is the release in the plain view, with the whole build on hover", () => {
    const html = render();
    expect(html).toContain(">v0.16.66</span>");
    expect(html).toContain(`title="v${VERSION}"`);
    expect(html).not.toContain(`>v${VERSION}<`);
  });

  it("is the whole build in the technical view", () => {
    setTechnicalDetail(true);
    expect(render()).toContain(`>v${VERSION}</span>`);
  });

  it("keeps a version with no build as it is", () => {
    expect(shortVersion("0.16.66")).toBe("0.16.66");
    expect(shortVersion("0.16.66-rc.1+abc")).toBe("0.16.66-rc.1");
  });
});
