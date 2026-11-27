#!/usr/bin/env node
// 从 SigmaHQ 仓库导入规则为 Markdown。用法：
//   node scripts/import-sigma.mjs <sigma 仓库路径> [规则子目录...]
// 已存在的文件会保留人工填写的中文字段（title_zh / summary_zh / notes_zh / notes_en / featured）。
// 许可：SigmaHQ 规则采用 Detection Rule License 1.1，必须保留作者、原规则链接与许可证声明。
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import * as yaml from "js-yaml";
import { keptFields, toFrontMatter, toMarkdown } from "./lib/sigma.mjs";

const [repo, ...dirsArg] = process.argv.slice(2);
if (!repo) { console.error("usage: import-sigma.mjs <sigma-repo> [dirs...]"); process.exit(1); }
const dirs = dirsArg.length ? dirsArg : [
  "rules/windows/process_creation", "rules/windows/process_access",
  "rules/cloud/aws", "rules/linux/process_creation", "rules/network/dns"
];
const OUT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../src/content/rules");
let commit = "main";
try { commit = execSync("git rev-parse HEAD", { cwd: repo }).toString().trim(); } catch { /* 不是 git 仓库时用 main */ }

function walk(d) {
  return fs.readdirSync(d, { withFileTypes: true }).flatMap(e =>
    e.isDirectory() ? walk(path.join(d, e.name)) : e.name.endsWith(".yml") ? [path.join(d, e.name)] : []);
}

fs.mkdirSync(OUT, { recursive: true });
let n = 0, skipped = 0;
for (const dir of dirs) {
  for (const file of walk(path.join(repo, dir))) {
    const raw = fs.readFileSync(file, "utf8");
    let r;
    try { r = yaml.load(raw); } catch { skipped++; continue; }
    const slug = path.basename(file, ".yml");
    const out = path.join(OUT, slug + ".md");
    const kept = keptFields(fs.existsSync(out) ? fs.readFileSync(out, "utf8") : "");
    const fm = toFrontMatter(r, { rel: path.relative(repo, file), commit, kept });
    if (!fm) { skipped++; continue; }
    fs.writeFileSync(out, toMarkdown(fm, raw));
    n++;
  }
}
console.log(`imported ${n} rules, skipped ${skipped}, from commit ${commit}`);
