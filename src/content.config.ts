import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders";

const source = z.object({
  name: z.string(),
  url: z.string().url(),
  license: z.string(),
  license_url: z.string().url().optional()
});

const rules = defineCollection({
  loader: glob({ pattern: "**/*.md", base: "./src/content/rules" }),
  schema: z.object({
    title: z.string(),
    title_zh: z.string().optional(),
    summary: z.string(),
    summary_zh: z.string().optional(),
    notes_zh: z.string().optional(),
    notes_en: z.string().optional(),
    featured: z.boolean().optional(),
    sigma_id: z.string().optional(),
    status: z.string(),
    level: z.string(),
    platform: z.string(),
    logsource: z.string(),
    tactics: z.array(z.string()).default([]),
    techniques: z.array(z.string()).default([]),
    author: z.string(),
    date: z.string().optional(),
    modified: z.string().optional(),
    falsepositives: z.array(z.any()).default([]),
    references: z.array(z.string()).default([]),
    format: z.string(),
    source            // 必填：来源、链接、许可证
  })
});

const bi = z.object({ zh: z.string(), en: z.string() });
const incidents = defineCollection({
  loader: glob({ pattern: "**/*.md", base: "./src/content/incidents" }),
  schema: z.object({
    title: bi,
    summary: bi,
    published: z.string(),          // 原报告发布日期
    publisher: z.string(),
    sector: bi,
    actor: z.string().optional(),
    severity: z.enum(["critical", "high", "medium", "low"]),
    tactics: z.array(z.string()).default([]),
    techniques: z.array(z.string()).default([]),
    tags: z.array(z.string()).default([]),
    initial_access: bi,
    detected_by: bi,
    timeline: z.array(z.object({ date: z.string(), zh: z.string(), en: z.string() })),
    root_cause: bi,
    lessons: z.array(bi),
    detection_ideas: z.array(bi).default([]),
    related_rules: z.array(z.string()).default([]),   // 规则 slug
    source: source.extend({ title: z.string() }),
    added: z.string(),              // 本站收录日期
    generated: z.boolean().optional() // 由每日抓取脚本自动生成
  })
});

export const collections = { rules, incidents };
