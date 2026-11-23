import { defineConfig } from "astro/config";

// 部署在 GitHub Pages 项目页；若改用自定义域名，删掉 base 并修改 site
export default defineConfig({
  site: "https://flamingoff.github.io",
  base: "/blueteam-library",
  trailingSlash: "ignore",
  i18n: { defaultLocale: "zh", locales: ["zh", "en"], routing: { prefixDefaultLocale: true, redirectToDefaultLocale: true } },
  markdown: { shikiConfig: { themes: { light: "github-light", dark: "github-dark" } } }
});
