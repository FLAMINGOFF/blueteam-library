# 蓝队检测与复盘库 / Blue Team Detection & Incident Library

[![CI](https://github.com/FLAMINGOFF/blueteam-library/actions/workflows/ci.yml/badge.svg)](https://github.com/FLAMINGOFF/blueteam-library/actions/workflows/ci.yml)
[![Lighthouse performance](https://img.shields.io/endpoint?url=https%3A%2F%2Fflamingoff.github.io%2Fblueteam-library%2Fbadges%2Flighthouse-performance.json)](#质量保障)
[![Lighthouse accessibility](https://img.shields.io/endpoint?url=https%3A%2F%2Fflamingoff.github.io%2Fblueteam-library%2Fbadges%2Flighthouse-accessibility.json)](#质量保障)
[![Lighthouse best practices](https://img.shields.io/endpoint?url=https%3A%2F%2Fflamingoff.github.io%2Fblueteam-library%2Fbadges%2Flighthouse-best-practices.json)](#质量保障)
[![Lighthouse SEO](https://img.shields.io/endpoint?url=https%3A%2F%2Fflamingoff.github.io%2Fblueteam-library%2Fbadges%2Flighthouse-seo.json)](#质量保障)

收录网络公开的检测规则与安全事件报告的中英双语静态网站（Astro）。本站不发布原创规则。

## 本地运行
```bash
npm install
npm run dev        # http://localhost:4321
npm run build      # 输出到 dist/
```

## 质量保障
每次推送和 PR 都会跑 [CI 工作流](.github/workflows/ci.yml)，**全部通过才会发布到 GitHub Pages**。

| 检查 | 覆盖内容 |
| --- | --- |
| **ESLint + astro check** | 浏览器脚本、Node 脚本的 lint；`.astro` / `.ts` 的类型检查 |
| **单元测试**（Vitest，1400+） | SigmaHQ 导入转换（战术映射、日期、署名与许可证、保留人工中文字段）、CISA 抓取的纯函数（RSS/HTML 解析、KEV 分组与模板、关联规则打分、模型输出清洗）、中英文案成对，以及**每一条规则和每一篇复盘**都通过站点字段校验、ATT&CK 编号合法、关联规则真实存在 |
| **浏览器测试**（Playwright） | 根路径按浏览器语言跳转、筛选/搜索/排序/加载更多、收藏、语言与主题切换、复制规则、矩阵跳转、跳到正文、`/` 快捷键、手机宽度无横向滚动，全程无报错和 404 |
| **无障碍**（axe-core） | 10 类页面 × 中英 × 深浅色，按 WCAG 2.1 A/AA 自动检查 |
| **Lighthouse CI** | 对生产构建的首页、规则列表、规则详情、事件详情打分；顶部徽章是最近一次 `main` 构建中各页面的最低分 |

本地运行：
```bash
npm run lint
npm test            # 单元测试 + 内容校验
npm run build
npm run test:e2e    # 浏览器 + 无障碍测试（首次需 npx playwright install chromium）
npm run lighthouse  # Lighthouse CI，并生成 dist/badges/ 徽章文件
npm run check       # 前四步一起跑
```

## 内容结构
- `src/content/rules/*.md`：检测规则。由导入脚本从 SigmaHQ 生成，YAML front-matter 存元数据，正文是原始 Sigma 规则。
  - 可人工补充 `title_zh`、`summary_zh`、`notes_zh`、`notes_en`、`featured`，重新导入时会保留。
  - `source`（来源名、原始链接、许可证）为必填，缺失会导致构建失败。
- `src/content/incidents/*.md`：事件复盘。**只写本站自己的摘要**（中英双语字段），附原文链接，不转载原文。
- `src/i18n.ts`：界面文案与 ATT&CK 战术名称。

## 同步 SigmaHQ
```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma /tmp/sigma
npm run import:sigma -- /tmp/sigma            # 默认导入几个常用目录
npm run import:sigma -- /tmp/sigma rules/windows   # 或指定目录
```
`.github/workflows/sync-sigma.yml` 每周自动同步，构建和内容校验通过后直接提交到 main，再触发 CI，CI 全部通过后部署。

## 每日自动收录 CISA 通报
`.github/workflows/daily-advisories.yml` 每天墨尔本时间约 9:00 运行 `scripts/fetch-advisories.mjs`：
- **CISA KEV**：把每天新加入“已知被利用漏洞目录”的漏洞汇总成一篇复盘（`cisa-kev-日期`）。
- **CISA 联合通报**（AA 编号）：读取原文，生成中英文摘要（时间线、根因、防守要点、ATT&CK、检测思路）（`cisa-aa..`）。
- 关联规则：按 CVE 标签和 ATT&CK 技术自动匹配已有规则。
- 提交前先跑构建和单元测试（含内容校验），不合格的自动生成内容不会进 main；提交后触发 CI，全部通过才部署。
- 解析、模板和打分逻辑在 `scripts/lib/advisories.mjs`（纯函数，有单元测试）；SigmaHQ 转换逻辑在 `scripts/lib/sigma.mjs`。
- 生成的条目带 `generated: true`，页面会提示“自动生成，以原文为准”。只放自写摘要和原文链接，不转载原文。
- 需要仓库 Secret `ANTHROPIC_API_KEY`（Settings → Secrets and variables → Actions）。没有时只生成 KEV 模板汇总，跳过联合通报。
- 本地试运行：`ANTHROPIC_API_KEY=... npm run fetch:advisories -- --dry-run`

## 新增一篇事件复盘
复制 `src/content/incidents/` 中任一文件，按字段填写：标题/摘要/时间线等中英双语、`source.url` 原文链接、`related_rules` 关联规则文件名。

## 许可与署名
- SigmaHQ 规则：Detection Rule License (DRL) 1.1，页面必须保留作者、原规则链接、许可证声明（规则页已自动展示）。
- 事件报告：原文版权归发布方，本站只放摘要与链接。CISA 等美国政府通报一般为公有领域。
