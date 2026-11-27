import js from "@eslint/js";
import globals from "globals";

// .astro / .ts 文件由 `astro check` 做类型检查；这里只检查纯 JS：浏览器脚本、Node 脚本和测试。
export default [
  { ignores: ["dist/", ".astro/", ".lighthouseci/", "node_modules/", "test-results/", "playwright-report/"] },
  js.configs.recommended,
  { files: ["public/**/*.js"], languageOptions: { sourceType: "script", globals: globals.browser } },
  { files: ["scripts/**/*.mjs", "tests/**/*.js", "*.config.js", "*.config.mjs"], languageOptions: { globals: globals.node } },
  // e2e 测试里 page.evaluate 的回调在浏览器里执行
  { files: ["tests/e2e/**/*.js"], languageOptions: { globals: { ...globals.node, ...globals.browser } } }
];
