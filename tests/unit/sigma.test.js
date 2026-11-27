import { describe, expect, it } from "vitest";
import * as yaml from "js-yaml";
import { asDate, keptFields, splitFrontMatter, toFrontMatter, toMarkdown, TACTIC } from "../../scripts/lib/sigma.mjs";
import { ruleSchema } from "../../src/schemas";
import { TACTICS } from "../../src/i18n";

const RAW = `title: Suspicious Certutil Download
id: 19b08b1c-861d-4e75-a1ef-ea0c1baf202b
status: test
description: |
  Detects certutil downloading a file.
references:
  - https://example.com/a
author: Florian Roth (Nextron Systems)
date: 2019/01/16
modified: 2023-02-15
tags:
  - attack.defense-evasion
  - attack.stealth
  - attack.command-and-control
  - attack.t1105
  - attack.T1027.001
  - cve.2021-44228
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\certutil.exe'
  condition: selection
falsepositives:
  - Unknown
level: high
`;
const rule = yaml.load(RAW);
const rel = "rules/windows/process_creation/proc_creation_win_certutil_download.yml";

describe("toFrontMatter", () => {
  const fm = toFrontMatter(rule, { rel, commit: "abc123" });

  it("maps the basic fields", () => {
    expect(fm).toMatchObject({
      title: "Suspicious Certutil Download",
      summary: "Detects certutil downloading a file.",
      sigma_id: "19b08b1c-861d-4e75-a1ef-ea0c1baf202b",
      status: "test", level: "high", platform: "windows",
      logsource: "windows / process_creation", author: "Florian Roth (Nextron Systems)", format: "Sigma"
    });
  });

  it("normalises dates, including YAML date objects and slashes", () => {
    expect(fm.date).toBe("2019-01-16");
    expect(fm.modified).toBe("2023-02-15");   // js-yaml parses this one into a Date
    expect(asDate(undefined)).toBeUndefined();
  });

  it("maps ATT&CK tags to tactic IDs, merging defense-evasion and stealth", () => {
    expect(fm.tactics).toEqual(["TA0005", "TA0011"]);
    expect(fm.techniques).toEqual(["T1105", "T1027.001"]);
  });

  it("every tactic the importer can emit has a name on the site", () => {
    for (const id of Object.values(TACTIC)) expect(TACTICS[id], id).toBeDefined();
  });

  it("always records the source, a pinned link and the DRL licence", () => {
    expect(fm.source).toEqual({
      name: "SigmaHQ",
      url: `https://github.com/SigmaHQ/sigma/blob/abc123/${rel}`,
      license: "DRL-1.1",
      license_url: "https://github.com/SigmaHQ/Detection-Rule-License"
    });
  });

  it("passes the site's content schema", () => {
    expect(ruleSchema.safeParse(fm).success).toBe(true);
  });

  it("keeps hand-written Chinese fields on re-import", () => {
    const kept = { title_zh: "使用 certutil 下载文件", featured: true };
    expect(toFrontMatter(rule, { rel, kept })).toMatchObject(kept);
  });

  it("falls back to defaults for missing optional fields", () => {
    const m = toFrontMatter({ title: "x", detection: {} }, { rel: "r.yml" });
    expect(m).toMatchObject({ status: "unknown", level: "informational", platform: "other", logsource: "", author: "Unknown", tactics: [], techniques: [] });
    expect("date" in m).toBe(false);
    expect(m.source.url).toContain("/blob/main/");
  });

  it("caps references at 8", () => {
    const m = toFrontMatter({ ...rule, references: Array.from({ length: 12 }, (_, i) => `https://e.com/${i}`) }, { rel });
    expect(m.references).toHaveLength(8);
  });

  it.each([
    ["deprecated", { ...rule, status: "deprecated" }],
    ["unsupported", { ...rule, status: "unsupported" }],
    ["no title", { ...rule, title: undefined }],
    ["no detection", { ...rule, detection: undefined }],
    ["empty document", null]
  ])("skips rules that are %s", (_, r) => {
    expect(toFrontMatter(r, { rel })).toBeNull();
  });
});

describe("Markdown round trip", () => {
  it("writes front matter plus the untouched original rule", () => {
    const fm = toFrontMatter(rule, { rel });
    const md = toMarkdown(fm, RAW);
    const { data, body } = splitFrontMatter(md);
    expect(data).toEqual(fm);
    expect(body).toBe("\n```yaml\n" + RAW.trimEnd() + "\n```\n");
  });

  it("keptFields only returns the hand-maintained keys", () => {
    const md = toMarkdown({ ...toFrontMatter(rule, { rel }), title_zh: "中文", notes_en: "n", featured: true }, RAW);
    expect(keptFields(md)).toEqual({ title_zh: "中文", notes_en: "n", featured: true });
    expect(keptFields("")).toEqual({});
    expect(keptFields("no front matter")).toEqual({});
  });
});
