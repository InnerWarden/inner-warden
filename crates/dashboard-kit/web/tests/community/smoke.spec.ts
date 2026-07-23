import { expect, test } from "@playwright/test";

test("Community works with every Enterprise producer absent", async ({ page }) => {
  const postureRequests: string[] = [];
  page.on("request", (request) => {
    if (request.url().includes("/api/dashboard/v1/posture")) postureRequests.push(request.url());
  });

  await page.goto("/");

  await expect(page.getByText("Community", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Connect an agent to start screening its actions." })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Dashboard views" })).toContainText("Overview");
  await expect(page.getByRole("navigation", { name: "Dashboard views" })).toContainText("Activity");
  await expect(page.getByText("InnerWarden Enterprise", { exact: true })).toHaveCount(0);
  expect(postureRequests).toEqual([]);
});
