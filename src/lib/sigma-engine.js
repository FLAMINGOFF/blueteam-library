// 一个小型 Sigma 引擎：把规则的 detection 编译成语法树，然后
//   1. match(ast, event)  在 JSON 日志上求值（规则页的“样例日志验证”和“试一试”用）
//   2. toSplunk(ast) / toKql(ast, { ecs })  转成 Splunk SPL 与 Elastic KQL 查询
// 只覆盖 Sigma 规范里最常用的部分；遇到不支持的写法会抛出 SigmaUnsupported，页面据此显示“暂不支持”。
// 纯 JS、无依赖：Astro 构建时、浏览器里和单元测试里用的是同一份代码。

export class SigmaUnsupported extends Error {
  constructor(message) { super(message); this.name = "SigmaUnsupported"; }
}
const unsupported = msg => { throw new SigmaUnsupported(msg); };

const KNOWN_MODS = new Set(["contains", "startswith", "endswith", "all", "re", "i", "m", "s", "windash", "cidr", "gt", "gte", "lt", "lte", "exists", "cased"]);
const DASHES = ["-", "/", "–", "—", "―"];

// ---------------------------------------------------------------- 编译

/** 把 detection（已解析的 YAML 对象）编译成语法树 */
export function compile(detection) {
  if (!detection || typeof detection !== "object") unsupported("missing detection");
  if (detection.timeframe) unsupported("timeframe / correlation");
  const ids = {};
  for (const [name, def] of Object.entries(detection)) if (name !== "condition") ids[name] = searchNode(def);
  const conds = [].concat(detection.condition ?? []);
  if (!conds.length) unsupported("missing condition");
  const trees = conds.map(c => parseCondition(String(c), ids));
  return trees.length === 1 ? trees[0] : { type: "or", items: trees };
}

function searchNode(def) {
  if (Array.isArray(def)) {
    if (def.length && def.every(x => x && typeof x === "object" && !Array.isArray(x))) return { type: "or", items: def.map(mapNode) };
    if (def.every(x => x === null || typeof x !== "object")) return { type: "keyword", values: def.map(String) };
    unsupported("mixed list in search identifier");
  }
  if (def && typeof def === "object") return mapNode(def);
  if (def !== null && def !== undefined) return { type: "keyword", values: [String(def)] };
  unsupported("empty search identifier");
}

function mapNode(map) {
  const items = Object.entries(map).map(([key, raw]) => {
    const [field, ...mods] = key.split("|");
    for (const m of mods) if (!KNOWN_MODS.has(m)) unsupported(`modifier |${m}`);
    if (!field) unsupported("keyword modifiers");
    const values = Array.isArray(raw) ? raw : [raw];
    if (values.some(v => v !== null && typeof v === "object")) unsupported("nested value");
    return { type: "field", field, mods, values, all: mods.includes("all") };
  });
  return items.length === 1 ? items[0] : { type: "and", items };
}

function parseCondition(src, ids) {
  if (src.includes("|")) unsupported("aggregation in condition");
  const tokens = src.match(/\(|\)|[^\s()]+/g) || [];
  let i = 0;
  const peek = () => tokens[i]?.toLowerCase();
  const names = pattern => {
    const all = Object.keys(ids);
    const list = pattern === "them" ? all.filter(n => !n.startsWith("_"))
      : all.filter(n => new RegExp("^" + pattern.split("*").map(escRe).join(".*") + "$").test(n));
    if (!list.length) unsupported(`no identifier matches "${pattern}"`);
    return list;
  };
  function or() {
    const items = [and()];
    while (peek() === "or") { i++; items.push(and()); }
    return items.length === 1 ? items[0] : { type: "or", items };
  }
  function and() {
    const items = [not()];
    while (peek() === "and") { i++; items.push(not()); }
    return items.length === 1 ? items[0] : { type: "and", items };
  }
  function not() {
    if (peek() === "not") { i++; return { type: "not", item: not() }; }
    return primary();
  }
  function primary() {
    const t = tokens[i++];
    if (t === undefined) unsupported("unexpected end of condition");
    if (t === "(") { const n = or(); if (tokens[i++] !== ")") unsupported("missing )"); return n; }
    const lower = t.toLowerCase();
    if ((lower === "1" || lower === "all" || lower === "any") && peek() === "of") {
      i++;
      const pat = tokens[i++];
      if (!pat) unsupported("missing pattern after 'of'");
      const items = names(pat).map(n => ids[n]);
      return items.length === 1 ? items[0] : { type: lower === "all" ? "and" : "or", items };
    }
    if (!(t in ids)) unsupported(`unknown identifier "${t}"`);
    return ids[t];
  }
  const tree = or();
  if (i < tokens.length) unsupported(`unexpected "${tokens[i]}"`);
  return tree;
}

const escRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// ---------------------------------------------------------------- 值模式

// Sigma 通配符：* 任意串，? 单字符，\* \? \\ 为字面量。返回 [{ lit } | { star } | { q }] 片段
function pieces(value) {
  const out = [];
  let lit = "";
  for (let k = 0; k < value.length; k++) {
    const c = value[k];
    if (c === "\\" && value[k + 1] !== undefined && "*?\\".includes(value[k + 1])) { lit += value[++k]; continue; }
    if (c === "*" || c === "?") { if (lit) out.push({ lit }); lit = ""; out.push(c === "*" ? { star: true } : { q: true }); continue; }
    lit += c;
  }
  if (lit) out.push({ lit });
  return out;
}

function windash(v) {
  // 行首或空格后的 - / 展开成各种破折号写法
  let variants = [""];
  for (let k = 0; k < v.length; k++) {
    const c = v[k];
    const atWord = k === 0 || v[k - 1] === " ";
    variants = atWord && (c === "-" || c === "/") ? variants.flatMap(p => DASHES.map(d => p + d)) : variants.map(p => p + c);
  }
  return variants;
}

// 字段的每个值 → 片段数组（已套上 contains/startswith/endswith）。
// 在片段层面加通配符，避免值以 \ 结尾时和追加的 * 拼成转义序列 \*
const STAR = { star: true };
function patterns(node) {
  const { mods } = node;
  return node.values.flatMap(v => {
    if (v === null) return [null];
    const list = mods.includes("windash") ? windash(String(v)) : [String(v)];
    return list.map(x => {
      const ps = pieces(x);
      return mods.includes("contains") ? [STAR, ...ps, STAR] : mods.includes("startswith") ? [...ps, STAR] : mods.includes("endswith") ? [STAR, ...ps] : ps;
    });
  });
}
const kw = v => [STAR, ...pieces(v), STAR];

const kind = node => node.mods.includes("re") ? "re"
  : node.mods.includes("cidr") ? "cidr"
  : node.mods.includes("exists") ? "exists"
  : ["gt", "gte", "lt", "lte"].find(m => node.mods.includes(m)) || "str";

// ---------------------------------------------------------------- 求值

function lookup(event, field) {
  if (event == null || typeof event !== "object") return undefined;
  if (Array.isArray(event)) {
    // 数组（如 CloudTrail 的 Grant 列表）：对每个元素取值并摊平
    const found = event.map(e => lookup(e, field)).filter(v => v !== undefined).flat();
    return found.length ? found : undefined;
  }
  if (field in event) return event[field];
  const lower = field.toLowerCase();
  const key = Object.keys(event).find(k => k.toLowerCase() === lower);
  if (key !== undefined) return event[key];
  if (field.includes(".")) {
    const [head, ...rest] = field.split(".");
    return lookup(lookup(event, head), rest.join("."));
  }
  return undefined;
}

const asText = v => typeof v === "object" ? JSON.stringify(v) : String(v);

function strRegex(ps, cased) {
  const re = ps.map(p => p.star ? "[\\s\\S]*" : p.q ? "[\\s\\S]" : escRe(p.lit)).join("");
  return new RegExp("^" + re + "$", cased ? "" : "i");
}

function ipv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s).trim());
  return m && m.slice(1).every(x => +x < 256) ? m.slice(1).reduce((a, x) => a * 256 + +x, 0) : null;
}
function inCidr(ip, cidr) {
  const [base, bits = "32"] = String(cidr).split("/");
  const a = ipv4(ip), b = ipv4(base), n = Number(bits);
  if (a === null || b === null || !(n >= 0 && n <= 32)) return false;
  const size = 2 ** (32 - n);
  return Math.floor(a / size) === Math.floor(b / size);
}

function fieldMatches(node, event) {
  const raw = lookup(event, node.field);
  const k = kind(node);
  if (k === "exists") return node.values.some(v => (raw !== undefined && raw !== null) === (v === true || String(v).toLowerCase() === "true"));
  const vals = Array.isArray(raw) ? raw : [raw];
  const test = pat => {
    if (pat === null) return raw === undefined || raw === null || raw === "";
    if (raw === undefined || raw === null) return false;
    return vals.some(v => {
      const text = asText(v);
      if (k === "re") {
        const flags = ["i", "m", "s"].filter(f => node.mods.includes(f)).join("");
        return new RegExp(pat, flags).test(text);
      }
      if (k === "cidr") return inCidr(text, pat);
      if (k !== "str") {
        const a = Number(text), b = Number(pat);
        if (Number.isNaN(a) || Number.isNaN(b)) return false;
        return k === "gt" ? a > b : k === "gte" ? a >= b : k === "lt" ? a < b : a <= b;
      }
      return strRegex(pat, node.mods.includes("cased")).test(text);
    });
  };
  const pats = k === "re" || k === "cidr" || k === "gt" || k === "gte" || k === "lt" || k === "lte" ? node.values.map(v => v === null ? null : String(v)) : patterns(node);
  return node.all ? pats.every(test) : pats.some(test);
}

/** 在一条 JSON 日志上求值 */
export function match(node, event) {
  switch (node.type) {
    case "and": return node.items.every(n => match(n, event));
    case "or": return node.items.some(n => match(n, event));
    case "not": return !match(node.item, event);
    case "field": return fieldMatches(node, event);
    case "keyword": {
      const text = asText(event);
      return node.values.some(v => strRegex(kw(v), false).test(text));
    }
  }
  return false;
}

/** 便捷函数：编译并求值，同时列出哪些检索标识命中（页面展示用） */
export function explain(detection, event) {
  const ast = compile(detection);
  const hits = Object.keys(detection).filter(k => k !== "condition" && k !== "timeframe").filter(k => {
    try { return match(compile({ [k]: detection[k], condition: k }), event); } catch { return false; }
  });
  return { matched: match(ast, event), hits };
}

// ---------------------------------------------------------------- 转换

const wrap = (s, parent) => parent ? `(${s})` : s;

function convert(node, leaf, ops, parent = false) {
  switch (node.type) {
    case "and": return wrap(node.items.map(n => convert(n, leaf, ops, true)).join(ops.and), parent);
    case "or": return wrap(node.items.map(n => convert(n, leaf, ops, true)).join(ops.or), parent);
    case "not": {
      const inner = convert(node.item, leaf, ops, true);
      return ops.not + (inner.startsWith("(") || !/\s/.test(inner) ? inner : `(${inner})`);
    }
    default: return leaf(node, parent);
  }
}

// --- Splunk SPL
const splQuote = s => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
function splValue(ps) {
  return splQuote(ps.map(p => {
    if (p.q) unsupported("? wildcard (Splunk)");
    if (p.star) return "*";
    if (p.lit.includes("*")) unsupported("literal * (Splunk)");
    return p.lit;
  }).join(""));
}
function splLeaf(node, parent) {
  if (node.type === "keyword") {
    const vs = node.values.map(v => splValue(kw(v)));
    return vs.length === 1 ? vs[0] : wrap(vs.join(" OR "), parent);
  }
  const f = node.field, k = kind(node);
  if (/[\s="]/.test(f)) unsupported(`field name "${f}"`);
  if (k === "re") unsupported("regular expression (Splunk search)");
  if (node.mods.includes("cased")) unsupported("case-sensitive match (Splunk search)");
  if (k === "exists") return wrap(node.values.map(v => (v === true || String(v) === "true") ? `${f}=*` : `NOT ${f}=*`).join(" OR "), parent && node.values.length > 1);
  const pats = k === "str" ? patterns(node) : node.values.map(v => v === null ? null : String(v));
  const parts = pats.map(p => {
    if (p === null) return `NOT ${f}=*`;
    if (k === "cidr") return `${f}=${splQuote(p)}`;
    if (k !== "str") { if (Number.isNaN(Number(p))) unsupported("non-numeric comparison"); return `${f}${{ gt: ">", gte: ">=", lt: "<", lte: "<=" }[k]}${p}`; }
    return `${f}=${splValue(p)}`;
  });
  if (parts.length === 1) return parts[0];
  if (!node.all && k === "str" && !pats.includes(null)) return `${f} IN (${pats.map(splValue).join(", ")})`;
  return wrap(parts.join(node.all ? " AND " : " OR "), parent);
}
/** Sigma → Splunk SPL 搜索表达式（不含 index/sourcetype，需按环境补上） */
export const toSplunk = ast => convert(ast, splLeaf, { and: " AND ", or: " OR ", not: "NOT " });

// --- Elastic KQL
export const ECS = {
  Image: "process.executable", OriginalFileName: "process.pe.original_file_name", CommandLine: "process.command_line",
  ParentImage: "process.parent.executable", ParentCommandLine: "process.parent.command_line", CurrentDirectory: "process.working_directory",
  ProcessId: "process.pid", ParentProcessId: "process.parent.pid", User: "user.name", Product: "process.pe.product",
  Description: "process.pe.description", Company: "process.pe.company", Computer: "host.name",
  TargetFilename: "file.path", TargetObject: "registry.path", Details: "registry.data.strings",
  DestinationIp: "destination.ip", DestinationPort: "destination.port", DestinationHostname: "destination.domain",
  SourceIp: "source.ip", SourcePort: "source.port", QueryName: "dns.question.name",
  eventName: "event.action", eventSource: "event.provider", awsRegion: "cloud.region",
  sourceIPAddress: "source.address", userAgent: "user_agent.original", errorCode: "aws.cloudtrail.error_code",
  "userIdentity.type": "aws.cloudtrail.user_identity.type", "userIdentity.arn": "aws.cloudtrail.user_identity.arn"
};
const KQL_SPECIAL = /[\\():<>"*{}\s]/g;
const kqlEsc = s => s.replace(KQL_SPECIAL, c => "\\" + c);
const kqlQuote = s => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
function kqlValue(ps) {
  if (ps.some(p => p.q)) unsupported("? wildcard (KQL)");
  if (!ps.some(p => p.star)) return kqlQuote(ps.map(p => p.lit).join(""));
  return ps.map(p => p.star ? "*" : kqlEsc(p.lit)).join("");
}
function kqlLeaf(node, parent, ecs) {
  if (node.type === "keyword") {
    const vs = node.values.map(v => kqlValue(kw(v)));
    return vs.length === 1 ? vs[0] : wrap(vs.join(" or "), parent);
  }
  const f = ecs ? (ECS[node.field] || node.field) : node.field, k = kind(node);
  if (/[\s:"()]/.test(f)) unsupported(`field name "${f}"`);
  if (k === "re") unsupported("regular expression (KQL)");
  if (k === "exists") return wrap(node.values.map(v => (v === true || String(v) === "true") ? `${f}:*` : `not ${f}:*`).join(" or "), parent && node.values.length > 1);
  const pats = k === "str" ? patterns(node) : node.values.map(v => v === null ? null : String(v));
  const vals = pats.map(p => {
    if (p === null) return null;
    if (k === "cidr") return kqlQuote(p);
    if (k !== "str") { if (Number.isNaN(Number(p))) unsupported("non-numeric comparison"); return { op: { gt: ">", gte: ">=", lt: "<", lte: "<=" }[k], v: p }; }
    return kqlValue(p);
  });
  const one = v => v === null ? `not ${f}:*` : typeof v === "object" ? `${f} ${v.op} ${v.v}` : `${f}:${v}`;
  if (vals.length === 1) return one(vals[0]);
  if (!node.all && vals.every(v => typeof v === "string")) return `${f}:(${vals.join(" or ")})`;
  return wrap(vals.map(one).join(node.all ? " and " : " or "), parent);
}
/** Sigma → Elastic KQL。ecs: true 时把常见 Sysmon / CloudTrail 字段名换成 ECS 字段 */
export const toKql = (ast, { ecs = false } = {}) => convert(ast, (n, p) => kqlLeaf(n, p, ecs), { and: " and ", or: " or ", not: "not " });

/** 一次性生成规则页需要的全部转换结果；不支持的写法返回 { error } */
export function exportsFor(detection) {
  const safe = fn => { try { return { query: fn() }; } catch (e) { if (e instanceof SigmaUnsupported) return { error: e.message }; throw e; } };
  let ast;
  try { ast = compile(detection); } catch (e) {
    if (!(e instanceof SigmaUnsupported)) throw e;
    return { splunk: { error: e.message }, kql: { error: e.message }, kqlEcs: { error: e.message } };
  }
  return { splunk: safe(() => toSplunk(ast)), kql: safe(() => toKql(ast)), kqlEcs: safe(() => toKql(ast, { ecs: true })) };
}
