import { expect, test } from "@playwright/test";

test("real local workflow, denied action and evidence rendering", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await expect.poll(() => page.locator("#input").inputValue()).toContain('"');
  await page.locator("#evaluate").click();
  await expect(page.locator("#decision")).toHaveText("failure");
  await expect(page.locator("#findings .evidence").first()).toBeVisible();
  await page.screenshot({ path: "docs/workbench.png", fullPage: true });
  await page.locator("#input").fill('{"unexpected":"<script>alert(1)</script>"}');
  await page.locator("#evaluate").click();
  await expect(page.locator("#decision")).toContainText("failed");
  expect(errors).toEqual([]);
});
