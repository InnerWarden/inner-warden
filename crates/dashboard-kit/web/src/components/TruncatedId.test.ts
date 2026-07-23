import { it, expect } from "vitest";
import { friendlyId } from "./TruncatedId";
it("truncates a real hashed id + keeps full", () => {
  const full = "case:incident:ec06a299015601590958851357bd60c0e65e787b4dc658369b7f1db340a54598";
  const r = friendlyId(full);
  expect(r.label).toBe("case incident");
  expect(r.short).toBe("ec06a299…");
  expect(r.full).toBe(full);
});
it("humanizes evidence prefix", () => {
  const r = friendlyId("event:sqlite-incident:1a66e0d50f6ccf5a68415a9ce360ae9fa355975febaf131c141b6a534a008993");
  expect(r.label).toBe("event sqlite incident");
  expect(r.short).toBe("1a66e0d5…");
});
it("shows a non-hash id verbatim", () => {
  const r = friendlyId("case:incident:agent_guard:cmd:abc");
  expect(r.short).toBeNull();
  expect(r.label).toBe("case:incident:agent_guard:cmd:abc");
});
