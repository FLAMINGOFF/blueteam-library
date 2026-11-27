// 每日 CISA 抓取脚本用到的纯函数（不联网、不读写文件），方便单元测试。
import * as yaml from "js-yaml";

export const TACTICS = ["TA0043","TA0042","TA0001","TA0002","TA0003","TA0004","TA0005","TA0112","TA0006","TA0007","TA0008","TA0009","TA0011","TA0010","TA0040"];

export const decode = s => s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&");
export function htmlToText(html) {
  const main = html.match(/<main[\s\S]*?<\/main>/i)?.[0] || html;
  return decode(main.replace(/<(script|style|nav|header|footer)[\s\S]*?<\/\1>/gi, " ")
    .replace(/<\/(p|div|li|h\d|tr|br)>/gi, "\n").replace(/<[^>]+>/g, " "))
    .replace(/[ \t]+/g, " ").replace(/ *\n[\s]*/g, "\n").trim();
}

// 规则索引：CVE 标签与 ATT&CK 技术 → 规则 slug。files 为 [{ slug, text }]（text 是规则 Markdown 全文）
export function buildRuleIndex(files) {
  const byCve = new Map(), byTech = new Map();
  for (const { slug, text: txt } of files) {
    for (const m of txt.matchAll(/cve\.(\d{4}-\d{4,})/gi)) {
      const k = "CVE-" + m[1]; (byCve.get(k) || byCve.set(k, new Set()).get(k)).add(slug);
    }
    const fm = yaml.load(txt.match(/^---\n([\s\S]*?)\n---/)?.[1] || "") || {};
    for (const t of fm.techniques || []) (byTech.get(t) || byTech.set(t, []).get(t)).push(slug);
  }
  return { byCve, byTech };
}
export function relatedRules(idx, cves = [], techniques = []) {
  const out = new Set();
  for (const c of cves) for (const s of idx.byCve.get(c) || []) out.add(s);
  // 再按技术匹配：子技术（如 T1059.001）记 2 分，父技术记 1 分，至少 2 分才算相关，最多补到 6 条
  const score = new Map();
  for (const t of techniques) for (const s of idx.byTech.get(t) || []) score.set(s, (score.get(s) || 0) + (t.includes(".") ? 2 : 1));
  for (const [s, v] of [...score].sort((a, b) => b[1] - a[1])) { if (out.size >= 6 || v < 2) break; out.add(s); }
  return [...out];
}

// RSS → [{ title, link, date }]
export function parseRss(rss) {
  return [...rss.matchAll(/<item>([\s\S]*?)<\/item>/g)].map(m => {
    const tag = t => decode(m[1].match(new RegExp(`<${t}[^>]*>([\\s\\S]*?)</${t}>`))?.[1] || "").trim();
    return { title: tag("title"), link: tag("link"), date: new Date(tag("pubDate") || Date.now()).toISOString().slice(0, 10) };
  });
}
// 联合通报链接里的 AA 编号（小写），不是联合通报返回 undefined
export const advisoryId = link => link.match(/\/(aa\d{2}-\d{3}[a-z]?)\b/i)?.[1]?.toLowerCase();

// KEV 目录按加入日期分组，只保留 since（含）之后的
export function groupKevByDate(kev, since) {
  const byDate = new Map();
  for (const v of kev.vulnerabilities || []) if (v.dateAdded >= since) (byDate.get(v.dateAdded) || byDate.set(v.dateAdded, []).get(v.dateAdded)).push(v);
  return [...byDate].sort();
}

// 清洗模型输出：技术编号大写去重并校验格式，标签转小写短横线
export function normalizeSummary(j) {
  j.techniques = [...new Set(j.techniques.map(t => t.toUpperCase()).filter(t => /^T\d{4}(\.\d{3})?$/.test(t)))];
  j.tags = [...new Set(j.tags.map(t => t.toLowerCase().replace(/[^a-z0-9-]+/g, "-")).filter(Boolean))].slice(0, 8);
  return j;
}

// KEV 某一天新增漏洞的模板汇总（没有 API Key 或模型失败时使用）
export function kevTemplate(date, vs) {
  const ransom = vs.filter(v => v.knownRansomwareCampaignUse === "Known");
  const list = vs.map(v => `${v.vendorProject} ${v.product}（${v.cveID}）`).join("、");
  const listEn = vs.map(v => `${v.vendorProject} ${v.product} (${v.cveID})`).join(", ");
  return {
    title: { zh: `CISA KEV 新增 ${vs.length} 个已被在野利用的漏洞（${date}）`, en: `CISA adds ${vs.length} known exploited vulnerabilit${vs.length > 1 ? "ies" : "y"} to KEV (${date})` },
    summary: {
      zh: `CISA 于 ${date} 将以下漏洞加入已知被利用漏洞（KEV）目录：${list}。${ransom.length ? `其中 ${ransom.length} 个已知被用于勒索软件活动。` : ""}收录意味着已有可靠的在野利用证据，应优先修复。`,
      en: `On ${date} CISA added to the Known Exploited Vulnerabilities catalog: ${listEn}.${ransom.length ? ` ${ransom.length} of them ${ransom.length > 1 ? "are" : "is"} known to be used in ransomware campaigns.` : ""} Listing means there is reliable evidence of exploitation in the wild; prioritize remediation.`
    },
    sector: { zh: "多行业（使用受影响产品的组织）", en: "Multiple sectors (users of affected products)" },
    severity: ransom.length ? "critical" : "high",
    tactics: ["TA0001"], techniques: [], tags: ["kev", "vulnerability", ...(ransom.length ? ["ransomware"] : [])],
    initial_access: { zh: "利用已知漏洞（各漏洞细节见 CVE 与厂商通告）", en: "Exploitation of known vulnerabilities (see each CVE and vendor advisory)" },
    detected_by: { zh: "CISA 基于可靠的在野利用证据收录", en: "Added by CISA based on reliable evidence of active exploitation" },
    timeline: [
      ...vs.map(v => ({ date, zh: `${v.cveID}（${v.vendorProject} ${v.product}）加入 KEV`, en: `${v.cveID} (${v.vendorProject} ${v.product}) added to KEV` })),
      ...[...new Set(vs.map(v => v.dueDate))].sort().map(d => ({ date: d, zh: "美国联邦机构修复截止日（BOD 22-01）", en: "Remediation due date for US federal agencies (BOD 22-01)" }))
    ],
    root_cause: {
      zh: "受影响产品存在已被利用的漏洞：" + vs.map(v => `${v.cveID} ${v.vulnerabilityName}`).join("；"),
      en: "Affected products contain exploited vulnerabilities: " + vs.map(v => `${v.cveID} ${v.vulnerabilityName}`).join("; ")
    },
    lessons: [
      { zh: "盘点资产，确认是否使用上述产品及受影响版本，优先处理面向互联网的实例", en: "Inventory assets for the listed products and versions; start with internet-facing instances" },
      { zh: "按厂商指引修补或缓解；无法缓解时按 CISA 要求停用该产品", en: "Patch or mitigate per vendor guidance; discontinue the product if no mitigation exists, as CISA advises" },
      { zh: "修补前后回溯相关日志，排查是否已被利用", en: "Review logs from before and after patching for signs of prior exploitation" }
    ],
    detection_ideas: [
      { zh: "在 Web/应用日志中检索针对受影响产品的异常请求与报错", en: "Search web/app logs for anomalous requests and errors against the affected products" },
      { zh: "监控受影响服务进程派生命令行、脚本解释器或发起异常外连", en: "Watch the affected service processes for spawning shells or interpreters, or unusual outbound connections" }
    ]
  };
}
