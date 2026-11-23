# 蓝队检测与复盘库 / Blue Team Detection & Incident Library

收录网络公开的检测规则与安全事件报告的中英双语静态网站（Astro）。本站不发布原创规则。

## 本地运行
```bash
npm install
npm run dev        # http://localhost:4321
npm run build      # 输出到 dist/
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
`.github/workflows/sync-sigma.yml` 每周自动同步，构建通过后直接提交到 main 并触发部署。

## 每日自动收录 CISA 通报
`.github/workflows/daily-advisories.yml` 每天墨尔本时间约 9:00 运行 `scripts/fetch-advisories.mjs`：
- **CISA KEV**：把每天新加入“已知被利用漏洞目录”的漏洞汇总成一篇复盘（`cisa-kev-日期`）。
- **CISA 联合通报**（AA 编号）：读取原文，生成中英文摘要（时间线、根因、防守要点、ATT&CK、检测思路）（`cisa-aa..`）。
- 关联规则：按 CVE 标签和 ATT&CK 技术自动匹配已有规则。
- 生成的条目带 `generated: true`，页面会提示“自动生成，以原文为准”。只放自写摘要和原文链接，不转载原文。
- 需要仓库 Secret `ANTHROPIC_API_KEY`（Settings → Secrets and variables → Actions）。没有时只生成 KEV 模板汇总，跳过联合通报。
- 本地试运行：`ANTHROPIC_API_KEY=... npm run fetch:advisories -- --dry-run`

## 新增一篇事件复盘
复制 `src/content/incidents/` 中任一文件，按字段填写：标题/摘要/时间线等中英双语、`source.url` 原文链接、`related_rules` 关联规则文件名。

## 许可与署名
- SigmaHQ 规则：Detection Rule License (DRL) 1.1，页面必须保留作者、原规则链接、许可证声明（规则页已自动展示）。
- 事件报告：原文版权归发布方，本站只放摘要与链接。CISA 等美国政府通报一般为公有领域。
