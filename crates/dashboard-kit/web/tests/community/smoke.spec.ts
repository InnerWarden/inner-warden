import { expect, test } from "@playwright/test";
import { COMMUNITY_TABS } from "./support";

test("Community works with every Enterprise producer absent", async ({ page }) => {
  const postureRequests: string[] = [];
  page.on("request", (request) => {
    if (request.url().includes("/api/dashboard/v1/posture")) postureRequests.push(request.url());
  });

  await page.goto("/");

  await expect(page.getByText("Community", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "What is happening here" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Dashboard views" }).getByRole("button")).toHaveText(COMMUNITY_TABS.map(([label]) => label));
  await expect(page.getByText("InnerWarden Enterprise", { exact: true })).toHaveCount(0);
  expect(postureRequests).toEqual([]);
});
