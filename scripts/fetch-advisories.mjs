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
import { TACTICS, htmlToText, buildRuleIndex, relatedRules, parseRss, advisoryId, groupKevByDate, normalizeSummary, kevTemplate } from "./lib/advisories.mjs";

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
  return normalizeSummary(JSON.parse(text));
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

async function doKev(idx, budget) {
  const kev = await get(KEV_URL, "json");
  let n = 0;
  for (const [date, vs] of groupKevByDate(kev, since)) {
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
  const items = parseRss(rss);
  let n = 0;
  for (const it of items) {
    const id = advisoryId(it.link);
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

const idx = buildRuleIndex(fs.readdirSync(RULES).filter(f => f.endsWith(".md")).map(f => ({ slug: f.replace(/\.md$/, ""), text: fs.readFileSync(path.join(RULES, f), "utf8") })));
let total = 0, failed = 0;
for (const job of [doAdvisories, doKev]) {
  try { total += await job(idx, MAX_NEW - total); }
  catch (e) { failed++; console.error(`${job.name} 失败：${e.message}`); }
}
console.log(`完成：新增 ${total} 篇${client ? "" : "（模板模式）"}`);
if (failed === 2) process.exit(1);
