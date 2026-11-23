import { defineConfig } from "astro/config";

// 【待定】正式域名确定后填写 site，用于 sitemap / canonical / hreflang
export default defineConfig({
  site: "https://example.com",
  trailingSlash: "ignore",
  i18n: { defaultLocale: "zh", locales: ["zh", "en"], routing: { prefixDefaultLocale: true, redirectToDefaultLocale: true } },
  markdown: { shikiConfig: { themes: { light: "github-light", dark: "github-dark" } } }
});
