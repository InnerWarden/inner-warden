import { expect, test } from "@playwright/test";

test("Enterprise mounts the shared shell without inventing host outcomes", async ({ page }) => {
  const communityOverviewRequests: string[] = [];
  page.on("request", (request) => {
    if (request.url().includes("/api/overview")) communityOverviewRequests.push(request.url());
  });

  await page.goto("/");

  await expect(page.getByText("Enterprise", { exact: true })).toBeVisible();
  await expect(page.getByText("Authenticated", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Enterprise posture adapter not declared" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Posture" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Runtime assurance foundation" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "No layers reported" })).toHaveCount(0);
  await expect(page.getByText("Verified active enforcement", { exact: true })).toHaveCount(0);
  expect(communityOverviewRequests).toEqual([]);
});
