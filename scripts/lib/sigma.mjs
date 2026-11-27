// 把一条 SigmaHQ 规则（已解析的 YAML 对象）转换成本站规则 Markdown 的 front-matter。
// 纯函数，不读写文件，方便单元测试；scripts/import-sigma.mjs 负责遍历目录和写文件。
import * as yaml from "js-yaml";

// Sigma 标签里的战术名 → ATT&CK 战术编号（v20：defense-evasion 拆为 Stealth 与 Defense Impairment）
export const TACTIC = {
  "reconnaissance": "TA0043", "resource-development": "TA0042", "initial-access": "TA0001",
  "execution": "TA0002", "persistence": "TA0003", "privilege-escalation": "TA0004",
  "defense-evasion": "TA0005", "stealth": "TA0005", "defense-impairment": "TA0112", "credential-access": "TA0006", "discovery": "TA0007",
  "lateral-movement": "TA0008", "collection": "TA0009", "exfiltration": "TA0010",
  "command-and-control": "TA0011", "impact": "TA0040"
};
// 重新导入时保留的人工字段
export const KEEP = ["title_zh", "summary_zh", "notes_zh", "notes_en", "featured"];

export const asDate = v => v instanceof Date ? v.toISOString().slice(0, 10) : (v ? String(v).replace(/\//g, "-") : undefined);

export function splitFrontMatter(txt) {
  const m = txt.match(/^---\n([\s\S]*?)\n---\n?/);
  return m ? { data: yaml.load(m[1]) || {}, body: txt.slice(m[0].length) } : { data: {}, body: txt };
}

// 从已存在的规则文件里取出人工字段
export function keptFields(existingText) {
  if (!existingText) return {};
  const { data } = splitFrontMatter(existingText);
  return Object.fromEntries(KEEP.filter(k => data[k] != null).map(k => [k, data[k]]));
}

// 返回 null 表示跳过（缺字段、已废弃）
export function toFrontMatter(r, { rel, commit = "main", kept = {} }) {
  if (!r || !r.title || !r.detection) return null;
  if (r.status === "deprecated" || r.status === "unsupported") return null;
  const tags = r.tags || [];
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
    ...kept
  };
  Object.keys(fm).forEach(k => fm[k] === undefined && delete fm[k]);
  return fm;
}

export const toMarkdown = (fm, raw) => "---\n" + yaml.dump(fm, { lineWidth: 200 }) + "---\n\n" + "```yaml\n" + raw.trimEnd() + "\n```\n";
