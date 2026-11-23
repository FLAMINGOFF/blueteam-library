import type { APIRoute } from "astro";
import { langPaths, TACTIC_ORDER, tacticName, LEVELS, type Lang } from "../../i18n";
import { rules, incidents, ruleTitle } from "../../data";
export const getStaticPaths = langPaths;
// 首页动态图形用的精简数据：[slug, 标题, 战术序号, 严重度序号, 更新日期]
export const GET: APIRoute = async ({ params }) => {
  const lang = params.lang as Lang;
  const rs = await rules(), is = await incidents();
  const tIdx = (ids: string[]) => { const i = TACTIC_ORDER.indexOf(ids[0]); return i < 0 ? -1 : i; };
  return new Response(JSON.stringify({
    tactics: TACTIC_ORDER.map(id => [id, tacticName(lang, id), rs.filter(r => r.data.tactics.includes(id)).length]),
    rules: rs.map(r => [r.id, ruleTitle(r, lang), tIdx(r.data.tactics), LEVELS[r.data.level]?.rank ?? 4, r.data.modified || r.data.date || ""]),
    incidents: is.map(i => [i.id, i.data.title[lang], i.data.tactics.map(x => TACTIC_ORDER.indexOf(x)).filter(x => x >= 0), i.data.published])
  }), { headers: { "Content-Type": "application/json" } });
};
