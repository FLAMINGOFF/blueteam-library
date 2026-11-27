import { defineConfig } from "@playwright/test";

// 针对生产构建（astro preview 提供 dist/）运行；先 npm run build
export default defineConfig({
  testDir: "tests/e2e",
  fullyParallel: true,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["github"], ["list"]] : "list",
  use: {
    baseURL: "http://localhost:4321/blueteam-library/", trace: "off",
    // 本地可用 PW_CHROMIUM 指向已装好的 Chromium；CI 里用 playwright install 装的
    launchOptions: process.env.PW_CHROMIUM ? { executablePath: process.env.PW_CHROMIUM } : {}
  },
  webServer: { command: "npm run preview -- --port 4321", url: "http://localhost:4321/blueteam-library/zh/", reuseExistingServer: !process.env.CI }
});
