// 内容完整性：每篇规则和复盘都必须能通过站点的字段校验，并且互相引用的东西真实存在。
// 每日抓取机器人在提交前也会跑这些测试，不合格的自动生成内容不会进入 main。
import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import * as yaml from "js-yaml";
import { splitFrontMatter, toFrontMatter } from "../../scripts/lib/sigma.mjs";
import { explain, exportsFor } from "../../src/lib/sigma-engine.js";
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

const sigmaOf = body => yaml.load(body.match(/```yaml\n([\s\S]*?)\n```/)[1]);
const originals = rules.filter(r => r.data.original);

describe("Sigma engine on every rule", () => {
  it.each(rules.map(r => [r.slug, r]))("%s exports or reports why not", (slug, { body }) => {
    const e = exportsFor(sigmaOf(body).detection);   // throws only on engine bugs, not on unsupported Sigma
    for (const k of ["splunk", "kql", "kqlEcs"]) expect(e[k].query || e[k].error, k).toBeTruthy();
  });

  it("can export at least 90% of rules", () => {
    const ok = rules.filter(r => exportsFor(sigmaOf(r.body).detection).splunk.query).length;
    expect(ok / rules.length).toBeGreaterThan(0.9);
  });
});

describe("original rules", () => {
  it("there are some", () => expect(originals.length).toBeGreaterThanOrEqual(5));

  it.each(originals.map(r => [r.slug, r]))("%s", (slug, { data, body }) => {
    expect(slug).toMatch(/^btl_/);
    const sigma = sigmaOf(body);
    // the front matter must describe the Sigma rule in the body, so edits to one are not forgotten in the other
    const fm = toFrontMatter(sigma, { rel: "x" });
    for (const k of ["title", "summary", "sigma_id", "status", "level", "platform", "logsource", "tactics", "techniques", "author", "date", "falsepositives", "references"]) expect(data[k], k).toEqual(fm[k]);
    expect(data.author).toBe("FLAMINGOFF");
    expect(data.source.name).toBe("Blue Team Library");
    expect(data.source.license).toBe("DRL-1.1");
    expect(data.source.url).toBe(`https://github.com/FLAMINGOFF/blueteam-library/blob/main/src/content/rules/${slug}.md`);
    expect(data.title_zh && data.summary_zh && data.notes_zh && data.notes_en).toBeTruthy();
    // every original rule ships with at least one log it must catch and one look-alike it must ignore
    expect(data.samples?.some(s => s.expect)).toBe(true);
    expect(data.samples?.some(s => !s.expect)).toBe(true);
    expect(exportsFor(sigma.detection).splunk.query).toBeTruthy();
  });

  it("only original rules use the btl_ prefix", () => {
    for (const r of rules.filter(r => r.slug.startsWith("btl_"))) expect(r.data.original, r.slug).toBe(true);
  });
});

describe("sample logs", () => {
  const cases = rules.flatMap(r => (r.data.samples || []).map(s => [`${r.slug}: ${s.name.en}`, r, s]));
  it.each(cases)("%s", (_, { body }, sample) => {
    expect(explain(sigmaOf(body).detection, sample.event).matched).toBe(sample.expect);
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
    if (data.original) expect(data.source.license_url).toBe("https://github.com/SigmaHQ/Detection-Rule-License");
  });
});
