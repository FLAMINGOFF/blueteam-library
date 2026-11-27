// 内容完整性：每篇规则和复盘都必须能通过站点的字段校验，并且互相引用的东西真实存在。
// 每日抓取机器人在提交前也会跑这些测试，不合格的自动生成内容不会进入 main。
import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { splitFrontMatter } from "../../scripts/lib/sigma.mjs";
import { incidentSchema, ruleSchema } from "../../src/schemas";
import { LEVELS, STATUS, TACTICS } from "../../src/i18n";

const load = dir => fs.readdirSync(dir).filter(f => f.endsWith(".md")).sort()
  .map(f => ({ slug: f.slice(0, -3), ...splitFrontMatter(fs.readFileSync(path.join(dir, f), "utf8")) }));
const rules = load("src/content/rules");
const incidents = load("src/content/incidents");
const ruleSlugs = new Set(rules.map(r => r.slug));

const DAY = /^\d{4}-\d{2}-\d{2}$/;
const TECH = /^T\d{4}(\.\d{3})?$/;
const SLUG = /^[a-z0-9][a-z0-9_-]*$/;
const https = u => /^https:\/\//.test(u);

it("has content to show", () => {
  expect(rules.length).toBeGreaterThan(100);
  expect(incidents.length).toBeGreaterThan(0);
});

describe("detection rules", () => {
  it.each(rules.map(r => [r.slug, r]))("%s", (slug, { data, body }) => {
    const parsed = ruleSchema.safeParse(data);
    expect(parsed.error?.issues ?? []).toEqual([]);
    expect(slug).toMatch(SLUG);
    expect(Object.keys(LEVELS)).toContain(data.level);
    expect(Object.keys(STATUS)).toContain(data.status);
    for (const t of data.tactics) expect(Object.keys(TACTICS)).toContain(t);
    for (const t of data.techniques) expect(t).toMatch(TECH);
    for (const k of ["date", "modified"]) if (data[k]) expect(data[k]).toMatch(DAY);
    // DRL 1.1 requires attribution: author, a link to the original and the licence
    expect(data.author.trim()).not.toBe("");
    expect(https(data.source.url)).toBe(true);
    if (data.source.name === "SigmaHQ") {
      expect(data.source.license).toBe("DRL-1.1");
      expect(data.source.url).toMatch(/^https:\/\/github\.com\/SigmaHQ\/sigma\/blob\/[^/]+\/rules\/.+\.yml$/);
    }
    // the body is the original rule in a fenced YAML block
    expect(body.trim()).toMatch(/^```yaml\n[\s\S]+\n```$/);
    // a translated title needs a translated summary too, or the page mixes languages
    if (data.title_zh) expect(data.summary_zh).toBeTruthy();
  });

  it("has unique Sigma IDs", () => {
    const ids = rules.map(r => r.data.sigma_id).filter(Boolean);
    expect(ids.length - new Set(ids).size).toBe(0);
  });
});

describe("incident reviews", () => {
  it.each(incidents.map(i => [i.slug, i]))("%s", (slug, { data }) => {
    const parsed = incidentSchema.safeParse(data);
    expect(parsed.error?.issues ?? []).toEqual([]);
    expect(slug).toMatch(SLUG);
    expect(data.published).toMatch(DAY);
    expect(data.added).toMatch(DAY);
    expect(https(data.source.url)).toBe(true);
    for (const t of data.tactics) expect(Object.keys(TACTICS)).toContain(t);
    for (const t of data.techniques) expect(t).toMatch(TECH);
    // every bilingual field is filled in both languages
    const bi = [data.title, data.summary, data.sector, data.initial_access, data.detected_by, data.root_cause, ...data.lessons, ...(data.detection_ideas || []), ...data.timeline];
    for (const b of bi) { expect(b.zh.trim()).not.toBe(""); expect(b.en.trim()).not.toBe(""); }
    expect(data.timeline.length).toBeGreaterThan(0);
    expect(data.lessons.length).toBeGreaterThan(0);
    // related rules must point at rules that exist, or the page renders a broken link
    for (const r of data.related_rules || []) expect(ruleSlugs, `related rule ${r}`).toContain(r);
  });
});
