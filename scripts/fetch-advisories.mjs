#!/usr/bin/env node
// 每日抓取 CISA 公开通报，生成本站自写的中英双语复盘摘要（src/content/incidents/*.md）。
//
// 来源：
//   1. CISA 已知被利用漏洞目录（KEV）JSON：按“加入日期”每天汇总成一篇
//   2. CISA 网络安全通报 RSS：只取 AA 开头的联合通报（ICS 通报数量太多，默认不收）
//
// 用法：node scripts/fetch-advisories.mjs [--dry-run]
// 环境变量：
//   ANTHROPIC_API_KEY  有则用 Claude 生成中英文摘要；没有则只按模板生成 KEV 汇总，跳过联合通报
//   LOOKBACK_DAYS      回看天数，默认 3（漏跑几天也能补上）
//   MAX_NEW            每次最多新增几篇，默认 6（控制成本）
//   CLAUDE_MODEL       默认 claude-opus-5-5
//
// 版权：CISA 作品属美国政府作品，一般为公有领域；联合通报可能含外国伙伴机构内容。
// 无论哪种来源，本站都只放自写摘要 + 原文链接，并注明“以原文为准”，不整篇转载。
import fs from "node:fs";
import path from "node:path";
import * as yaml from "js-yaml";

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const OUT = path.join(ROOT, "src/content/incidents");
const RULES = path.join(ROOT, "src/content/rules");
const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const RSS_URL = "https://www.cisa.gov/cybersecurity-advisories/cybersecurity-advisories.xml";
const UA = "blueteam-library-bot (+https://github.com/FLAMINGOFF/blueteam-library)";

const DRY = process.argv.includes("--dry-run");
const LOOKBACK = Number(process.env.LOOKBACK_DAYS || 3);
const MAX_NEW = Number(process.env.MAX_NEW || 6);
const MODEL = process.env.CLAUDE_MODEL || "claude-opus-5-5";
const today = new Date().toISOString().slice(0, 10);
const since = new Date(Date.now() - LOOKBACK * 864e5).toISOString().slice(0, 10);

const LICENSE = "美国政府作品，通常属公有领域；本站提供自写摘要与链接，以原文为准 / US government work, generally public domain; our own summary and link, the original prevails";
const TACTICS = ["TA0043","TA0042","TA0001","TA0002","TA0003","TA0004","TA0005","TA0112","TA0006","TA0007","TA0008","TA0009","TA0011","TA0010","TA0040"];

// ---------- 工具 ----------
async function get(url, type = "text") {
  for (let i = 0; i < 3; i++) {
    try {
      const r = await fetch(url, { headers: { "user-agent": UA } });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return type === "json" ? r.json() : r.text();
    } catch (e) {
      if (i === 2) throw new Error(`${url}: ${e.message}`);
      await new Promise(s => setTimeout(s, 2000 * (i + 1)));
    }
  }
}
const existing = () => fs.readdirSync(OUT).map(f => f.replace(/\.md$/, ""));
const has = prefix => existing().some(s => s === prefix || s.startsWith(prefix + "-"));
const decode = s => s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
  .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&");
function htmlToText(html) {
  const main = html.match(/<main[\s\S]*?<\/main>/i)?.[0] || html;
  return decode(main.replace(/<(script|style|nav|header|footer)[\s\S]*?<\/\1>/gi, " ")
    .replace(/<\/(p|div|li|h\d|tr|br)>/gi, "\n").replace(/<[^>]+>/g, " "))
    .replace(/[ \t]+/g, " ").replace(/\n\s*\n+/g, "\n").trim();
}

// 规则索引：CVE 标签与 ATT&CK 技术 → 规则 slug
function ruleIndex() {
  const byCve = new Map(), byTech = new Map();
  for (const f of fs.readdirSync(RULES)) {
    const slug = f.replace(/\.md$/, "");
    const txt = fs.readFileSync(path.join(RULES, f), "utf8");
    for (const m of txt.matchAll(/cve\.(\d{4}-\d{4,})/gi)) {
      const k = "CVE-" + m[1]; (byCve.get(k) || byCve.set(k, new Set()).get(k)).add(slug);
    }
    const fm = yaml.load(txt.match(/^---\n([\s\S]*?)\n---/)?.[1] || "") || {};
    for (const t of fm.techniques || []) (byTech.get(t) || byTech.set(t, []).get(t)).push(slug);
  }
  return { byCve, byTech };
}
function relatedRules(idx, cves = [], techniques = []) {
  const out = new Set();
  for (const c of cves) for (const s of idx.byCve.get(c) || []) out.add(s);
  // 再按技术匹配：子技术（如 T1059.001）记 2 分，父技术记 1 分，至少 2 分才算相关，最多补到 6 条
  const score = new Map();
  for (const t of techniques) for (const s of idx.byTech.get(t) || []) score.set(s, (score.get(s) || 0) + (t.includes(".") ? 2 : 1));
  for (const [s, v] of [...score].sort((a, b) => b[1] - a[1])) { if (out.size >= 6 || v < 2) break; out.add(s); }
  return [...out];
}

// ---------- Claude ----------
let client = null;
if (process.env.ANTHROPIC_API_KEY) {
  const { default: Anthropic } = await import("@anthropic-ai/sdk");
  client = new Anthropic();
}
const bi = { type: "object", additionalProperties: false, required: ["zh", "en"], properties: { zh: { type: "string" }, en: { type: "string" } } };
const SCHEMA = {
  type: "object", additionalProperties: false,
  required: ["title", "summary", "sector", "actor", "severity", "tactics", "techniques", "tags", "initial_access", "detected_by", "timeline", "root_cause", "lessons", "detection_ideas"],
  properties: {
    title: bi, summary: bi, sector: bi,
    actor: { type: "string", description: "攻击者/团伙名称，未知时为空字符串" },
    severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
    tactics: { type: "array", items: { type: "string", enum: TACTICS } },
    techniques: { type: "array", items: { type: "string", description: "ATT&CK 技术编号，如 T1190 或 T1059.001" } },
    tags: { type: "array", items: { type: "string", description: "小写英文短标签，如 ransomware" } },
    initial_access: bi, detected_by: bi, root_cause: bi,
    timeline: { type: "array", items: { type: "object", additionalProperties: false, required: ["date", "zh", "en"], properties: { date: { type: "string" }, zh: { type: "string" }, en: { type: "string" } } } },
    lessons: { type: "array", items: bi },
    detection_ideas: { type: "array", items: bi }
  }
};
const SYSTEM = `你是蓝队分析师，为一个中英双语的“安全事件复盘库”网站写结构化摘要。
要求：
- 只依据提供的原文，不编造原文没有的事实、日期、IOC 或攻击者；原文没写的就写“通报未说明 / Not stated in the advisory”。
- 用你自己的话概括，不要大段照抄原文句子（可保留产品名、CVE、文件名、命令等专有名词）。
- 中文用简体，专业术语可附英文；英文简洁。每个字段 1–3 句。
- timeline 按时间顺序，日期格式 YYYY-MM-DD 或 YYYY-MM；lessons 3–6 条可执行的防守要点；detection_ideas 2–5 条可落地的检测思路（日志源 + 可观察行为）。
- tactics 用 ATT&CK v20 战术编号（TA0005=Stealth 隐蔽，TA0112=Defense Impairment 防御削弱）；techniques 只填原文明确提到或能直接对应的技术。`;

async function summarize(userText) {
  const res = await client.beta.messages.create({
    model: MODEL, max_tokens: 16000,
    betas: ["server-side-fallback-2026-07-01"], fallbacks: "default",
    output_config: { effort: "medium", format: { type: "json_schema", schema: SCHEMA } },
    system: SYSTEM,
    messages: [{ role: "user", content: userText }]
  });
  if (res.stop_reason === "refusal") throw new Error("模型拒绝：" + (res.stop_details?.category || "unknown"));
  if (res.stop_reason === "max_tokens") throw new Error("输出被截断");
  const text = res.content.filter(b => b.type === "text").map(b => b.text).join("");
  const j = JSON.parse(text);
  j.techniques = [...new Set(j.techniques.map(t => t.toUpperCase()).filter(t => /^T\d{4}(\.\d{3})?$/.test(t)))];
  j.tags = [...new Set(j.tags.map(t => t.toLowerCase().replace(/[^a-z0-9-]+/g, "-")).filter(Boolean))].slice(0, 8);
  return j;
}

// ---------- 写文件 ----------
function write(slug, data) {
  if (!data.actor) delete data.actor;
  data.generated = true;   // 页面据此显示“自动生成摘要”提示
  const body = `---\n${yaml.dump(data, { lineWidth: 200, noRefs: true })}---\n`;
  const file = path.join(OUT, slug + ".md");
  if (DRY) console.log(`[dry-run] ${file}\n${body}`);
  else fs.writeFileSync(file, body);
  console.log("新增", slug);
}

// ---------- KEV 每日汇总 ----------
function kevTemplate(date, vs) {
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

async function doKev(idx, budget) {
  const kev = await get(KEV_URL, "json");
  const byDate = new Map();
  for (const v of kev.vulnerabilities || []) if (v.dateAdded >= since) (byDate.get(v.dateAdded) || byDate.set(v.dateAdded, []).get(v.dateAdded)).push(v);
  let n = 0;
  for (const [date, vs] of [...byDate].sort()) {
    const slug = `cisa-kev-${date}`;
    if (has(slug) || n >= budget) continue;
    let d = kevTemplate(date, vs);
    if (client) {
      try {
        const facts = vs.map(({ cveID, vendorProject, product, vulnerabilityName, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, cwes, notes }) =>
          ({ cveID, vendorProject, product, vulnerabilityName, shortDescription, requiredAction, dueDate, knownRansomwareCampaignUse, cwes, notes }));
        const s = await summarize(`以下是 CISA 于 ${date} 加入 KEV 目录的漏洞（JSON，来自 CISA 官方数据）。请把这一天的新增写成一篇汇总复盘：标题需包含“CISA KEV”、数量和日期 ${date}；timeline 写入 KEV 日期与修复截止日；root_cause 概括每个漏洞的成因；lessons 和 detection_ideas 要针对这些具体产品。\n\n${JSON.stringify(facts, null, 1)}`);
        d = { ...s, tags: [...new Set(["kev", ...s.tags])] };
      } catch (e) { console.warn(`KEV ${date} 用模板代替：${e.message}`); }
    }
    const cves = vs.map(v => v.cveID);
    write(slug, {
      ...d, published: date, publisher: "CISA",
      related_rules: relatedRules(idx, cves, d.techniques),
      source: { name: "CISA", title: `Known Exploited Vulnerabilities Catalog — ${cves.join(", ")}`, url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(cves[0])}`, license: LICENSE },
      added: today
    });
    n++;
  }
  return n;
}

// ---------- 联合通报（AA 编号） ----------
async function doAdvisories(idx, budget) {
  if (!client) { console.log("未设置 ANTHROPIC_API_KEY，跳过联合通报摘要"); return 0; }
  const rss = await get(RSS_URL);
  const items = [...rss.matchAll(/<item>([\s\S]*?)<\/item>/g)].map(m => {
    const tag = t => decode(m[1].match(new RegExp(`<${t}[^>]*>([\\s\\S]*?)</${t}>`))?.[1] || "").trim();
    return { title: tag("title"), link: tag("link"), date: new Date(tag("pubDate") || Date.now()).toISOString().slice(0, 10) };
  });
  let n = 0;
  for (const it of items) {
    const id = it.link.match(/\/(aa\d{2}-\d{3}[a-z]?)\b/i)?.[1]?.toLowerCase();
    if (!id || it.date < since || n >= budget) continue;
    const slug = `cisa-${id}`;
    if (has(slug)) continue;
    try {
      const text = htmlToText(await get(it.link)).slice(0, 150000);
      const s = await summarize(`原文标题：${it.title}\n原文链接：${it.link}\n发布日期：${it.date}\n\n请为这篇 CISA 联合网络安全通报写复盘摘要。原文正文如下：\n\n${text}`);
      const cves = [...new Set(text.match(/CVE-\d{4}-\d{4,}/g) || [])];
      write(slug, {
        ...s, published: it.date, publisher: "CISA" + (/FBI/.test(text.slice(0, 3000)) ? " / FBI" : ""),
        related_rules: relatedRules(idx, cves, s.techniques),
        source: { name: "CISA", title: `${it.title} (${id.toUpperCase()})`, url: it.link, license: LICENSE },
        added: today
      });
      n++;
    } catch (e) { console.warn(`跳过 ${id}：${e.message}`); }
  }
  return n;
}

const idx = ruleIndex();
let total = 0, failed = 0;
for (const job of [doAdvisories, doKev]) {
  try { total += await job(idx, MAX_NEW - total); }
  catch (e) { failed++; console.error(`${job.name} 失败：${e.message}`); }
}
console.log(`完成：新增 ${total} 篇${client ? "" : "（模板模式）"}`);
if (failed === 2) process.exit(1);
