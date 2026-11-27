import { defineCollection } from "astro:content";
import { glob } from "astro/loaders";
import { ruleSchema, incidentSchema } from "./schemas";

const rules = defineCollection({
  loader: glob({ pattern: "**/*.md", base: "./src/content/rules" }),
  schema: ruleSchema
});

const incidents = defineCollection({
  loader: glob({ pattern: "**/*.md", base: "./src/content/incidents" }),
  schema: incidentSchema
});

export const collections = { rules, incidents };
