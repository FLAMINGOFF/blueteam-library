import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// axe-core 自动检查 WCAG 2.1 A/AA，两种语言、两种配色都跑一遍。
const RULE = "proc_creation_win_certutil_download";        // 带中文翻译、关联事件的精选规则
const INCIDENT = "cloudflare-thanksgiving-2023";             // 有关联规则的人工复盘
const PAGES = [
  ["home", "", ".obs-ready"],
  ["rules", "rules/", ".card"],
  ["rules filtered", "rules/?tactic=TA0006&level=high", ".chip.on"],
  ["rule", `rules/${RULE}/`, ".srcbox"],
  ["incidents", "incidents/", ".card"],
  ["incident", `incidents/${INCIDENT}/`, ".timeline"],
  ["original rule", "rules/btl_aws_s3_acl_grants_public_access/", "#try-result:not(:empty)"],
  ["original incident", "incidents/btl-sim-phish-to-ntds/", ".timeline"],
  ["matrix", "matrix/", ".hc"],
  ["search", "search/?q=lsass", ".card"],
  ["starred (empty)", "starred/", ".empty:not(:empty)"],
  ["about", "about/", "h1"]
];

for (const scheme of ["light", "dark"]) {
  for (const lang of ["zh", "en"]) {
    test.describe(`${scheme} ${lang}`, () => {
      test.use({ colorScheme: scheme });
      for (const [name, path, ready] of PAGES) {
        test(`no axe violations: ${name}`, async ({ page }) => {
          await page.goto(`./${lang}/${path}`);
          await page.locator(ready).first().waitFor();
          // 首页规则流每隔几秒滑入一张新卡片：先暂停动效、等动画结束，免得 axe 量到半透明的中间帧
          if (name === "home") {
            await page.locator("[data-pause]").click();
            await page.evaluate(() => Promise.all(document.getAnimations().filter(a => a.effect?.getTiming().iterations !== Infinity).map(a => a.finished.catch(() => {}))));
          }
          const { violations } = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
          const summary = violations.map(v => `${v.id} (${v.impact}): ${v.nodes.length}× e.g. ${v.nodes[0].target.join(" ")}`);
          expect(summary).toEqual([]);
        });
      }
    });
  }
}
