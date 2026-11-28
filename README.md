# 蓝队检测与复盘库 / Blue Team Detection & Incident Library

[![CI](https://github.com/FLAMINGOFF/blueteam-library/actions/workflows/ci.yml/badge.svg)](https://github.com/FLAMINGOFF/blueteam-library/actions/workflows/ci.yml)
[![Lighthouse performance](https://img.shields.io/endpoint?url=https%3A%2F%2Fflamingoff.github.io%2Fblueteam-library%2Fbadges%2Flighthouse-performance.json)](#quality)
[![Lighthouse accessibility](https://img.shields.io/endpoint?url=https%3A%2F%2Fflamingoff.github.io%2Fblueteam-library%2Fbadges%2Flighthouse-accessibility.json)](#quality)
[![Lighthouse best practices](https://img.shields.io/endpoint?url=https%3A%2F%2Fflamingoff.github.io%2Fblueteam-library%2Fbadges%2Flighthouse-best-practices.json)](#quality)
[![Lighthouse SEO](https://img.shields.io/endpoint?url=https%3A%2F%2Fflamingoff.github.io%2Fblueteam-library%2Fbadges%2Flighthouse-seo.json)](#quality)

**English** · [中文](#中文)

🔗 **Live site:** https://flamingoff.github.io/blueteam-library/

## English

A bilingual (English / 中文) static site, built with Astro, that collects public detection rules and security incident reports and organizes them by MITRE ATT&CK. Every collected item keeps its source, original authors, link and license, and a small set of **original rules and tabletop write-ups** is marked as such.

- **Original rules**: 8 Sigma rules written for this site (Windows, Linux, AWS CloudTrail), each with sample logs it must catch and look-alikes it must ignore. The samples are evaluated on every build, and the page shows the result.
- **Try it and export**: every rule page lets you edit a JSON log and see live whether the rule matches, and exports the rule as Splunk SPL and Elastic KQL (raw or ECS field names). Both use a small Sigma engine in `src/lib/sigma-engine.js` that handles about 95% of the collected rules.
- **Detection rules**: about 1,400 Sigma rules synced from [SigmaHQ](https://github.com/SigmaHQ/sigma), filterable by source, tactic, platform, severity and status, with the original rule, false positives and references.
- **Incident reviews**: our own structured summaries of public reports (timeline, root cause, lessons for defenders, detection ideas, related rules), with a link to the original.
- **ATT&CK coverage**: rule counts per tactic, plus a heatmap of every Enterprise technique showing how many rules cover it and where the gaps are.
- **Detection Observatory** on the home page: a live rule stream, a 3D star map of rules by tactic and a tactic spectrum, with a pause button and `prefers-reduced-motion` support.
- Search, saved items (stored in your browser only), light/dark theme, mobile layout.

### Run locally
```bash
npm install
npm run dev        # http://localhost:4321
npm run build      # output in dist/
```

### Quality
Every push and pull request runs the [CI workflow](.github/workflows/ci.yml). **The site is deployed to GitHub Pages only if all of it passes.**

| Check | What it covers |
| --- | --- |
| **ESLint + astro check** | Lint for browser and Node scripts; type checking for `.astro` / `.ts` |
| **Unit tests** (Vitest, 2,900+) | The Sigma engine (modifiers, conditions, SPL and KQL output), every sample log of every rule, SigmaHQ import mapping (tactics, dates, attribution and license, preserved hand-written Chinese fields), the CISA fetcher's pure functions (RSS/HTML parsing, KEV grouping and template, related-rule scoring, model output cleanup), paired EN/中文 strings, and **every rule and incident** passing the site schema with valid ATT&CK IDs and existing related rules |
| **Browser tests** (Playwright) | Root redirect by browser language, filter/search/sort/load more, saving, language and theme switch, copy rule, matrix links, skip link, `/` shortcut, no horizontal scroll on mobile, and no errors or 404s throughout |
| **Accessibility** (axe-core) | WCAG 2.1 A/AA scan of 10 page types × both languages × light and dark |
| **Lighthouse CI** | Scores the production build's home, rule list, rule and incident pages. The badges above show the lowest score from the latest run on `main` |

```bash
npm run lint
npm test            # unit tests + content checks
npm run build
npm run test:e2e    # browser + accessibility tests (first run: npx playwright install chromium)
npm run lighthouse  # Lighthouse CI, writes badge files to dist/badges/
npm run check       # the first four together
```

### Content
- `src/content/rules/*.md`: detection rules, generated from SigmaHQ by the import script. YAML front matter holds the metadata; the body is the original Sigma rule.
  - You can add `title_zh`, `summary_zh`, `notes_zh`, `notes_en` and `featured` by hand; re-imports keep them.
  - `source` (name, original link, license) is required; the build fails without it.
- `src/content/incidents/*.md`: incident reviews. **Only our own summary** (bilingual fields) and a link to the original, never the original text.
- Original rules are `src/content/rules/btl_*.md` with `original: true`, author FLAMINGOFF and a `samples` list (`name`, `expect`, `event`). Tests check that the front matter matches the Sigma rule in the body and that every sample gives the expected result.
- Original tabletop write-ups are `src/content/incidents/btl-sim-*.md` with `original: true`; the page says they are fictional.
- `src/i18n.ts`: UI strings and ATT&CK tactic names. Field schemas live in `src/schemas.ts`.
- `src/data/attack.json`: trimmed MITRE ATT&CK Enterprise data for the heatmap. Refresh with `node scripts/update-attack.mjs`.

### Syncing SigmaHQ
```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma /tmp/sigma
npm run import:sigma -- /tmp/sigma                 # default rule folders
npm run import:sigma -- /tmp/sigma rules/windows   # or pick folders
```
`.github/workflows/sync-sigma.yml` syncs weekly. If the build and content checks pass it commits to `main` and triggers CI, which deploys once everything passes.

### Daily CISA advisories
`.github/workflows/daily-advisories.yml` runs `scripts/fetch-advisories.mjs` every day at about 9:00 Melbourne time:
- **CISA KEV**: each day's additions to the Known Exploited Vulnerabilities catalog become one review (`cisa-kev-<date>`).
- **CISA joint advisories** (AA IDs): reads the advisory and writes a bilingual summary (timeline, root cause, lessons, ATT&CK, detection ideas) (`cisa-aa..`).
- Related rules are matched by CVE tags and ATT&CK techniques.
- Build and unit tests (including content checks) run before committing, so bad generated content never reaches `main`; the commit then triggers CI, which deploys only if everything passes.
- Parsing, templates and scoring are in `scripts/lib/advisories.mjs` (pure functions with unit tests); the SigmaHQ mapping is in `scripts/lib/sigma.mjs`.
- Generated entries carry `generated: true` and the page notes they are automatic and the original prevails.
- Needs the repository secret `ANTHROPIC_API_KEY` (Settings → Secrets and variables → Actions). Without it only the KEV template summary is generated and joint advisories are skipped.
- Dry run locally: `ANTHROPIC_API_KEY=... npm run fetch:advisories -- --dry-run`

### Adding an incident review
Copy any file in `src/content/incidents/` and fill in the fields: bilingual title, summary, timeline and so on, `source.url` for the original report, and `related_rules` with rule file names.

### Licenses and attribution
- SigmaHQ rules: Detection Rule License (DRL) 1.1. Pages must keep the author, a link to the original rule and the license notice; every rule page shows all three.
- Incident reports: originals belong to their publishers; this site only has summaries and links. US government advisories such as CISA's are generally public domain.
- Original rules and tabletop write-ups: written by FLAMINGOFF for this site and released under the Detection Rule License (DRL) 1.1, the same licence as SigmaHQ.
- MITRE ATT&CK® data © The MITRE Corporation, used under its [terms of use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).

---

## 中文

[English](#english) · **中文**

收录网络公开的检测规则与安全事件报告的中英双语静态网站（Astro），按 ATT&CK 组织。收录内容都保留来源、原作者、链接和许可证；另有少量**原创规则和模拟演练复盘**，单独标注。

- **原创规则**：本站编写的 8 条 Sigma 规则（Windows、Linux、AWS CloudTrail），每条都带应命中和不应命中的样例日志，每次构建都会自动验证，规则页展示结果。
- **试一试与导出**：每个规则页都能编辑 JSON 日志实时查看是否命中，并能一键导出 Splunk SPL 和 Elastic KQL（原字段名或 ECS 字段名）。两者都基于 `src/lib/sigma-engine.js` 里的小型 Sigma 引擎，能处理约 95% 的收录规则。
- **ATT&CK 覆盖热力图**：列出企业矩阵的全部技术，显示每个技术被多少条规则覆盖、哪里是空白。

### 本地运行
```bash
npm install
npm run dev        # http://localhost:4321
npm run build      # 输出到 dist/
```

### 质量保障
每次推送和 PR 都会跑 [CI 工作流](.github/workflows/ci.yml)，**全部通过才会发布到 GitHub Pages**。

| 检查 | 覆盖内容 |
| --- | --- |
| **ESLint + astro check** | 浏览器脚本、Node 脚本的 lint；`.astro` / `.ts` 的类型检查 |
| **单元测试**（Vitest，2900+） | Sigma 引擎（修饰符、条件、SPL / KQL 输出）、每条规则的每条样例日志、SigmaHQ 导入转换（战术映射、日期、署名与许可证、保留人工中文字段）、CISA 抓取的纯函数（RSS/HTML 解析、KEV 分组与模板、关联规则打分、模型输出清洗）、中英文案成对，以及**每一条规则和每一篇复盘**都通过站点字段校验、ATT&CK 编号合法、关联规则真实存在 |
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

### 内容结构
- `src/content/rules/*.md`：检测规则。由导入脚本从 SigmaHQ 生成，YAML front-matter 存元数据，正文是原始 Sigma 规则。
  - 可人工补充 `title_zh`、`summary_zh`、`notes_zh`、`notes_en`、`featured`，重新导入时会保留。
  - `source`（来源名、原始链接、许可证）为必填，缺失会导致构建失败。
- `src/content/incidents/*.md`：事件复盘。**只写本站自己的摘要**（中英双语字段），附原文链接，不转载原文。
- 原创规则是 `src/content/rules/btl_*.md`，带 `original: true`、作者 FLAMINGOFF 和 `samples` 样例日志（`name`、`expect`、`event`）。测试会检查 front-matter 与正文 Sigma 规则一致，且每条样例的结果符合预期。
- 原创模拟演练是 `src/content/incidents/btl-sim-*.md`，带 `original: true`，页面会注明是虚构场景。
- `src/i18n.ts`：界面文案与 ATT&CK 战术名称。字段定义在 `src/schemas.ts`。
- `src/data/attack.json`：热力图用的精简 MITRE ATT&CK 企业矩阵数据，用 `node scripts/update-attack.mjs` 更新。

### 同步 SigmaHQ
```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma /tmp/sigma
npm run import:sigma -- /tmp/sigma            # 默认导入几个常用目录
npm run import:sigma -- /tmp/sigma rules/windows   # 或指定目录
```
`.github/workflows/sync-sigma.yml` 每周自动同步，构建和内容校验通过后直接提交到 main，再触发 CI，CI 全部通过后部署。

### 每日自动收录 CISA 通报
`.github/workflows/daily-advisories.yml` 每天墨尔本时间约 9:00 运行 `scripts/fetch-advisories.mjs`：
- **CISA KEV**：把每天新加入“已知被利用漏洞目录”的漏洞汇总成一篇复盘（`cisa-kev-日期`）。
- **CISA 联合通报**（AA 编号）：读取原文，生成中英文摘要（时间线、根因、防守要点、ATT&CK、检测思路）（`cisa-aa..`）。
- 关联规则：按 CVE 标签和 ATT&CK 技术自动匹配已有规则。
- 提交前先跑构建和单元测试（含内容校验），不合格的自动生成内容不会进 main；提交后触发 CI，全部通过才部署。
- 解析、模板和打分逻辑在 `scripts/lib/advisories.mjs`（纯函数，有单元测试）；SigmaHQ 转换逻辑在 `scripts/lib/sigma.mjs`。
- 生成的条目带 `generated: true`，页面会提示“自动生成，以原文为准”。只放自写摘要和原文链接，不转载原文。
- 需要仓库 Secret `ANTHROPIC_API_KEY`（Settings → Secrets and variables → Actions）。没有时只生成 KEV 模板汇总，跳过联合通报。
- 本地试运行：`ANTHROPIC_API_KEY=... npm run fetch:advisories -- --dry-run`

### 新增一篇事件复盘
复制 `src/content/incidents/` 中任一文件，按字段填写：标题/摘要/时间线等中英双语、`source.url` 原文链接、`related_rules` 关联规则文件名。

### 许可与署名
- SigmaHQ 规则：Detection Rule License (DRL) 1.1，页面必须保留作者、原规则链接、许可证声明（规则页已自动展示）。
- 事件报告：原文版权归发布方，本站只放摘要与链接。CISA 等美国政府通报一般为公有领域。
- 原创规则与模拟演练：由 FLAMINGOFF 为本站编写，与 SigmaHQ 相同，采用 Detection Rule License (DRL) 1.1。
- MITRE ATT&CK® 数据版权归 The MITRE Corporation，按其[使用条款](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/)引用。
