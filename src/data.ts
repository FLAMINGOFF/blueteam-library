import { getCollection, type CollectionEntry } from "astro:content";
import type { Lang } from "./i18n";
import { LEVELS } from "./i18n";

export type Rule = CollectionEntry<"rules">;
export type Incident = CollectionEntry<"incidents">;

let _rules: Rule[] | null = null;
let _inc: Incident[] | null = null;
export async function rules() {
  _rules ??= (await getCollection("rules")).sort((a, b) =>
    (b.data.modified || b.data.date || "").localeCompare(a.data.modified || a.data.date || ""));
  return _rules;
}
export async function incidents() {
  _inc ??= (await getCollection("incidents")).sort((a, b) => b.data.published.localeCompare(a.data.published));
  return _inc;
}
export const ruleTitle = (r: Rule, lang: Lang) => (lang === "zh" && r.data.title_zh) || r.data.title;
export const ruleSummary = (r: Rule, lang: Lang) => (lang === "zh" && r.data.summary_zh) || r.data.summary;
export const translated = (r: Rule) => !!r.data.title_zh;

// 列表/搜索用的精简索引（客户端筛选）
export async function index(lang: Lang) {
  const rs = (await rules()).map(r => ({
    k: "r", id: r.id, t: ruleTitle(r, lang), te: r.data.title, s: ruleSummary(r, lang).slice(0, 220),
    lv: r.data.level, lr: LEVELS[r.data.level]?.rank ?? 9, st: r.data.status, pf: r.data.platform,
    ta: r.data.tactics, te2: r.data.techniques, d: r.data.modified || r.data.date || "", au: r.data.author, src: r.data.source.name
  }));
  const is = (await incidents()).map(i => ({
    k: "i", id: i.id, t: i.data.title[lang], s: i.data.summary[lang].slice(0, 220), lv: i.data.severity,
    lr: LEVELS[i.data.severity]?.rank ?? 9, sec: i.data.sector[lang], ta: i.data.tactics, te2: i.data.techniques,
    tg: i.data.tags, d: i.data.published, ac: i.data.actor || "", src: i.data.publisher
  }));
  return { rules: rs, incidents: is };
}
