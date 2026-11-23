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
`.github/workflows/sync-sigma.yml` 每周自动同步并开 PR。

## 新增一篇事件复盘
复制 `src/content/incidents/` 中任一文件，按字段填写：标题/摘要/时间线等中英双语、`source.url` 原文链接、`related_rules` 关联规则文件名。

## 许可与署名
- SigmaHQ 规则：Detection Rule License (DRL) 1.1，页面必须保留作者、原规则链接、许可证声明（规则页已自动展示）。
- 事件报告：原文版权归发布方，本站只放摘要与链接。CISA 等美国政府通报一般为公有领域。
