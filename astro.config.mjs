import { defineConfig } from "astro/config";

// 部署在 GitHub Pages 项目页；若改用自定义域名，删掉 base 并修改 site
export default defineConfig({
  site: "https://flamingoff.github.io",
  base: "/blueteam-library",
  trailingSlash: "ignore",
  // redirectToDefaultLocale 关掉：根路径用 src/pages/index.astro 按浏览器语言跳转，而不是一律跳到 /zh/
  i18n: { defaultLocale: "zh", locales: ["zh", "en"], routing: { prefixDefaultLocale: true, redirectToDefaultLocale: false } },
  markdown: { shikiConfig: { themes: { light: "github-light", dark: "github-dark" } } }
});
