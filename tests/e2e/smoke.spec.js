import { expect, test } from "@playwright/test";

const RULE = "proc_creation_win_certutil_download";
const INCIDENT = "cloudflare-thanksgiving-2023";

// 每个测试都收集页面报错和失败的同站请求，最后统一断言为空
let problems;
test.beforeEach(async ({ page }) => {
  problems = [];
  page.on("pageerror", e => problems.push(`pageerror: ${e.message}`));
  page.on("console", m => m.type() === "error" && problems.push(`console: ${m.text()}`));
  page.on("response", r => r.url().includes("localhost") && r.status() >= 400 && problems.push(`${r.status()} ${r.url()}`));
});
test.afterEach(() => expect(problems).toEqual([]));

test.describe("root redirect", () => {
  test("English browsers go to /en/", async ({ browser }) => {
    const page = await (await browser.newContext({ locale: "en-AU" })).newPage();
    await page.goto("./");
    await expect(page).toHaveURL(/\/blueteam-library\/en\/$/);
  });
  test("Chinese browsers go to /zh/", async ({ browser }) => {
    const page = await (await browser.newContext({ locale: "zh-CN" })).newPage();
    await page.goto("./");
    await expect(page).toHaveURL(/\/blueteam-library\/zh\/$/);
  });
});

for (const lang of ["zh", "en"]) {
  test(`home (${lang}) shows stats, the observatory and links that work`, async ({ page }) => {
    await page.goto(`./${lang}/`);
    await expect(page.locator("html")).toHaveAttribute("lang", lang === "zh" ? "zh-CN" : "en");
    const rules = Number((await page.locator(".tile b").first().textContent()).replace(/\D/g, ""));
    expect(rules).toBeGreaterThan(100);
    await expect(page.locator("#obs.obs-ready")).toBeVisible();
    await expect(page.locator("#streamCard a")).toHaveCount(1);
    const pause = page.locator("[data-pause]");
    await expect(pause).toHaveAttribute("aria-pressed", "false");
    await pause.click();
    await expect(pause).toHaveAttribute("aria-pressed", "true");
    // every internal link on the page resolves
    const hrefs = await page.locator("a[href^='/blueteam-library/']").evaluateAll(as => [...new Set(as.map(a => a.getAttribute("href")))]);
    for (const h of hrefs) expect((await page.request.get(h)).status(), h).toBe(200);
  });
}

test("rules list filters, searches, sorts and pages through results", async ({ page }) => {
  await page.goto("./en/rules/");
  const count = page.locator(".toolbar .muted");
  await expect(page.locator(".card")).toHaveCount(30);
  const total = Number((await count.textContent()).split(" ")[0]);
  expect(total).toBeGreaterThan(100);

  // tactic filter: URL, chip state and count all change, and keyboard focus stays on the chip
  const chip = page.locator('[data-f="tactic"][data-v="TA0006"]');
  await chip.focus();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/tactic=TA0006/);
  await expect(page.locator('[data-f="tactic"][data-v="TA0006"]')).toHaveAttribute("aria-pressed", "true");
  await expect(page.locator('[data-f="tactic"][data-v="TA0006"]')).toBeFocused();
  const filtered = Number((await count.textContent()).split(" ")[0]);
  expect(filtered).toBeLessThan(total);
  await expect(page.getByRole("status")).toHaveText(`${filtered} results`);

  // search inside the filter, with highlighted matches
  await page.locator("#lq input").fill("lsass");
  await page.locator("#lq input").press("Enter");
  await expect(page).toHaveURL(/q=lsass/);
  await expect(page.locator(".card mark").first()).toHaveText(/lsass/i);

  // sort by severity puts the highest level first
  await page.locator("#sort").selectOption("sev");
  await expect(page).toHaveURL(/sort=sev/);
  const first = await page.locator(".card .sev").first().getAttribute("class");
  expect(first).toMatch(/sev-(critical|high)/);

  // clearing returns the full list, and "load more" adds cards and moves focus to the first new one
  await page.getByRole("link", { name: "Clear filters" }).click();
  await expect(page.locator(".card")).toHaveCount(30);
  await page.locator("#more").click();
  await expect(page.locator(".card")).toHaveCount(90);
  await expect(page.locator(".card a.title").nth(30)).toBeFocused();
});

test("filters in the URL are applied on load", async ({ page }) => {
  await page.goto("./zh/rules/?platform=aws&level=high");
  await expect(page.locator('[data-f="platform"][data-v="aws"]')).toHaveClass(/on/);
  for (const badge of await page.locator(".card .sev").all()) await expect(badge).toHaveClass(/sev-high/);
});

test("a card opens its rule page, which shows source, licence and the Sigma rule", async ({ page }) => {
  await page.goto("./zh/search/?q=certutil");
  await page.locator(`.card a.title[href$="/rules/${RULE}/"]`).click();
  await expect(page).toHaveURL(new RegExp(`/zh/rules/${RULE}/$`));
  await expect(page.locator("h1")).toHaveText("使用 certutil 下载文件");
  await expect(page.locator(".srcbox a").first()).toHaveAttribute("href", /github\.com\/SigmaHQ\/sigma\/blob\//);
  await expect(page.locator(".srcbox")).toContainText("Detection Rule License (DRL) 1.1");
  await expect(page.locator(".code-wrap pre")).toContainText("detection:");
});

test("copy button copies the Sigma rule", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto(`./en/rules/${RULE}/`);
  await page.locator("[data-copy]").click();
  await expect(page.locator("[data-copy]")).toHaveText("Copied");
  expect(await page.evaluate(() => navigator.clipboard.readText())).toContain("title:");
});

test("incident page links to its related rules", async ({ page }) => {
  await page.goto(`./en/incidents/${INCIDENT}/`);
  await expect(page.locator(".timeline li").first()).toBeVisible();
  const related = page.locator(".detail .card").first();
  const href = await related.getAttribute("href");
  await related.click();
  await expect(page).toHaveURL(new RegExp(href + "$"));
  await expect(page.locator("h1")).toBeVisible();
});

test("saving a rule shows it on the Saved page, and unsaving removes it", async ({ page }) => {
  await page.goto("./en/rules/");
  const star = page.locator(".card .star").first();
  const key = await star.getAttribute("data-star");
  await expect(star).toHaveAttribute("aria-pressed", "false");
  await star.click();
  await expect(star).toHaveAttribute("aria-pressed", "true");
  await expect(page).toHaveURL(/\/en\/rules\/$/);   // the star does not follow the card's link

  await page.goto("./en/starred/");
  await expect(page.locator(".card")).toHaveCount(1);
  await page.locator(`.card [data-star="${key}"]`).click();
  await expect(page.locator(".card")).toHaveCount(0);
  await expect(page.locator(".empty")).toContainText("Nothing saved yet");
});

test("language switch keeps the current page", async ({ page }) => {
  await page.goto(`./zh/rules/${RULE}/`);
  await page.locator("a.lang").click();
  await expect(page).toHaveURL(new RegExp(`/en/rules/${RULE}/$`));
  await expect(page.locator("a.lang")).toHaveText("中文");
});

test("theme choice is applied and remembered", async ({ page }) => {
  await page.goto("./en/");
  await page.locator('[data-theme-set="dark"]').click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await expect(page.locator('[data-theme-set="dark"]')).toHaveAttribute("aria-pressed", "true");
  await page.goto("./en/about/");
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  expect(bg).toBe("rgb(7, 11, 18)");
});

test("matrix cells open the filtered rule list", async ({ page }) => {
  await page.goto("./en/matrix/");
  await expect(page.locator(".cell")).toHaveCount(15);
  await page.locator('.cell[href*="tactic=TA0002"]').click();
  await expect(page).toHaveURL(/rules\/\?tactic=TA0002/);
  await expect(page.locator('[data-f="tactic"][data-v="TA0002"]')).toHaveAttribute("aria-pressed", "true");
});

test("skip link moves focus to the main content", async ({ page }) => {
  await page.goto("./en/about/");
  await page.keyboard.press("Tab");
  await expect(page.locator("a.skip")).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/#main$/);
});

test("pressing / focuses the search box", async ({ page }) => {
  await page.goto("./en/");
  await page.locator("body").press("/");
  await expect(page.locator("input[name=q]")).toBeFocused();
});

test("mobile layout shows the tab bar and no horizontal scroll", async ({ browser }) => {
  const page = await (await browser.newContext({ viewport: { width: 375, height: 740 } })).newPage();
  for (const p of ["en/", "zh/rules/", `en/rules/${RULE}/`, `zh/incidents/${INCIDENT}/`]) {
    await page.goto(`./${p}`);
    await expect(page.locator(".tabbar")).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, p).toBeLessThanOrEqual(0);
  }
});
