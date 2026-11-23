#!/usr/bin/env node
// 从 SigmaHQ 仓库导入规则为 Markdown。用法：
//   node scripts/import-sigma.mjs <sigma 仓库路径> [规则子目录...]
// 已存在的文件会保留人工填写的中文字段（title_zh / summary_zh / notes_zh / notes_en / featured）。
// 许可：SigmaHQ 规则采用 Detection Rule License 1.1，必须保留作者、原规则链接与许可证声明。
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import * as yaml from "js-yaml";

const [repo, ...dirsArg] = process.argv.slice(2);
if (!repo) { console.error("usage: import-sigma.mjs <sigma-repo> [dirs...]"); process.exit(1); }
const dirs = dirsArg.length ? dirsArg : [
  "rules/windows/process_creation", "rules/windows/process_access",
  "rules/cloud/aws", "rules/linux/process_creation", "rules/network/dns"
];
const OUT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../src/content/rules");
const KEEP = ["title_zh", "summary_zh", "notes_zh", "notes_en", "featured"];

const TACTIC = {
  "reconnaissance": "TA0043", "resource-development": "TA0042", "initial-access": "TA0001",
  "execution": "TA0002", "persistence": "TA0003", "privilege-escalation": "TA0004",
  "defense-evasion": "TA0005", "credential-access": "TA0006", "discovery": "TA0007",
  "lateral-movement": "TA0008", "collection": "TA0009", "exfiltration": "TA0010",
  "command-and-control": "TA0011", "impact": "TA0040"
};
let commit = "main";
try { commit = execSync("git rev-parse HEAD", { cwd: repo }).toString().trim(); } catch {}

function walk(d) {
  return fs.readdirSync(d, { withFileTypes: true }).flatMap(e =>
    e.isDirectory() ? walk(path.join(d, e.name)) : e.name.endsWith(".yml") ? [path.join(d, e.name)] : []);
}
function readExisting(file) {
  if (!fs.existsSync(file)) return {};
  const m = fs.readFileSync(file, "utf8").match(/^---\n([\s\S]*?)\n---/);
  if (!m) return {};
  const fm = yaml.load(m[1]) || {};
  return Object.fromEntries(KEEP.filter(k => fm[k] != null).map(k => [k, fm[k]]));
}
const asDate = v => v instanceof Date ? v.toISOString().slice(0, 10) : (v ? String(v).replace(/\//g, "-") : undefined);

fs.mkdirSync(OUT, { recursive: true });
let n = 0, skipped = 0;
for (const dir of dirs) {
  for (const file of walk(path.join(repo, dir))) {
    const raw = fs.readFileSync(file, "utf8");
    let r;
    try { r = yaml.load(raw); } catch { skipped++; continue; }
    if (!r || !r.title || !r.detection) { skipped++; continue; }
    if (r.status === "deprecated" || r.status === "unsupported") { skipped++; continue; }
    const tags = r.tags || [];
    const rel = path.relative(repo, file);
    const slug = path.basename(file, ".yml");
    const ls = r.logsource || {};
    const fm = {
      title: r.title,
      summary: (r.description || "").trim(),
      sigma_id: r.id,
      status: r.status || "unknown",
      level: r.level || "informational",
      platform: ls.product || ls.service || "other",
      logsource: [ls.product, ls.category, ls.service].filter(Boolean).join(" / "),
      tactics: [...new Set(tags.filter(t => t.startsWith("attack.") && TACTIC[t.slice(7)]).map(t => TACTIC[t.slice(7)]))],
      techniques: [...new Set(tags.filter(t => /^attack\.t\d{4}/i.test(t)).map(t => t.slice(7).toUpperCase()))],
      author: r.author || "Unknown",
      date: asDate(r.date),
      modified: asDate(r.modified),
      falsepositives: r.falsepositives || [],
      references: (r.references || []).slice(0, 8),
      source: {
        name: "SigmaHQ",
        url: `https://github.com/SigmaHQ/sigma/blob/${commit}/${rel}`,
        license: "DRL-1.1",
        license_url: "https://github.com/SigmaHQ/Detection-Rule-License"
      },
      format: "Sigma",
      ...readExisting(path.join(OUT, slug + ".md"))
    };
    Object.keys(fm).forEach(k => fm[k] === undefined && delete fm[k]);
    const body = "```yaml\n" + raw.trimEnd() + "\n```\n";
    fs.writeFileSync(path.join(OUT, slug + ".md"), "---\n" + yaml.dump(fm, { lineWidth: 200 }) + "---\n\n" + body);
    n++;
  }
}
console.log(`imported ${n} rules, skipped ${skipped}, from commit ${commit}`);
