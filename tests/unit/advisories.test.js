import { describe, expect, it } from "vitest";
import {
  advisoryId, buildRuleIndex, decode, groupKevByDate, htmlToText, kevTemplate, normalizeSummary, parseRss, relatedRules, TACTICS
} from "../../scripts/lib/advisories.mjs";
import { incidentSchema } from "../../src/schemas";
import { TACTICS as SITE_TACTICS } from "../../src/i18n";

const rule = (techniques, extra = "") => `---\ntitle: x\ntechniques: [${techniques.join(", ")}]\n---\n\n\`\`\`yaml\ntags:\n${extra}\n\`\`\`\n`;

describe("text helpers", () => {
  it("decodes entities and CDATA, &amp; last so it is not double-decoded", () => {
    expect(decode("<![CDATA[a &lt;b&gt; &quot;c&quot; &#39;d&#039; e&nbsp;f]]>")).toBe(`a <b> "c" 'd' e f`);
    expect(decode("&amp;lt;")).toBe("&lt;");
  });

  it("htmlToText keeps <main>, drops scripts and navigation, keeps paragraphs", () => {
    const html = `<html><nav>menu</nav><main><h1>Title</h1><script>evil()</script><p>One &amp; two</p><ul><li>a</li><li>b</li></ul></main><footer>f</footer></html>`;
    expect(htmlToText(html)).toBe("Title\nOne & two\na\nb");
  });
});

describe("related rules", () => {
  const idx = buildRuleIndex([
    { slug: "log4j", text: rule(["T1190"], "  - cve.2021-44228") },
    { slug: "ps-sub", text: rule(["T1059.001"]) },
    { slug: "ps-parent", text: rule(["T1059"]) },
    { slug: "ps-both", text: rule(["T1059", "T1059.001"]) },
    ...Array.from({ length: 8 }, (_, i) => ({ slug: `many-${i}`, text: rule(["T1105.002"]) }))
  ]);

  it("matches CVE tags inside the rule body", () => {
    expect(relatedRules(idx, ["CVE-2021-44228"])).toEqual(["log4j"]);
  });

  it("needs a sub-technique, or parent plus sub, to count as related", () => {
    expect(relatedRules(idx, [], ["T1059"])).toEqual([]);
    expect(relatedRules(idx, [], ["T1059.001"])).toEqual(["ps-sub", "ps-both"]);
    expect(relatedRules(idx, [], ["T1059", "T1059.001"])[0]).toBe("ps-both");
  });

  it("puts CVE matches first and caps the list at 6", () => {
    const r = relatedRules(idx, ["CVE-2021-44228"], ["T1105.002"]);
    expect(r[0]).toBe("log4j");
    expect(r).toHaveLength(6);
  });

  it("copes with no input", () => {
    expect(relatedRules(idx)).toEqual([]);
  });
});

describe("CISA feeds", () => {
  it("parses the advisories RSS", () => {
    const rss = `<rss><channel><item><title><![CDATA[#StopRansomware: Foo &amp; Bar]]></title><link>https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a</link><pubDate>Wed, 12 Mar 2025 12:00:00 +0000</pubDate></item>
      <item><title>ICS advisory</title><link>https://www.cisa.gov/news-events/ics-advisories/icsa-25-071-01</link><pubDate>Wed, 12 Mar 2025 12:00:00 +0000</pubDate></item></channel></rss>`;
    const items = parseRss(rss);
    expect(items).toEqual([
      { title: "#StopRansomware: Foo & Bar", link: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a", date: "2025-03-12" },
      { title: "ICS advisory", link: "https://www.cisa.gov/news-events/ics-advisories/icsa-25-071-01", date: "2025-03-12" }
    ]);
    expect(items.map(i => advisoryId(i.link))).toEqual(["aa25-071a", undefined]);
  });

  it("groups KEV entries by date added, oldest first, from the lookback date", () => {
    const kev = { vulnerabilities: [{ cveID: "A", dateAdded: "2026-11-25" }, { cveID: "B", dateAdded: "2026-11-20" }, { cveID: "C", dateAdded: "2026-11-24" }, { cveID: "D", dateAdded: "2026-11-25" }] };
    expect(groupKevByDate(kev, "2026-11-24").map(([d, vs]) => [d, vs.map(v => v.cveID)])).toEqual([["2026-11-24", ["C"]], ["2026-11-25", ["A", "D"]]]);
    expect(groupKevByDate({}, "2026-01-01")).toEqual([]);
  });

  it("cleans up model output", () => {
    const j = normalizeSummary({ techniques: ["t1190", "T1190", "T1059.001", "TA0001", "T12"], tags: ["Ransomware", "zero day", "ransomware", "", ...Array(10).fill(0).map((_, i) => "t" + i)] });
    expect(j.techniques).toEqual(["T1190", "T1059.001"]);
    expect(j.tags).toEqual(["ransomware", "zero-day", "t0", "t1", "t2", "t3", "t4", "t5"]);
  });

  it("uses the same tactic list as the site", () => {
    expect([...TACTICS].sort()).toEqual(Object.keys(SITE_TACTICS).sort());
  });
});

describe("KEV template", () => {
  const v = (cve, extra = {}) => ({ cveID: cve, vendorProject: "Acme", product: "Gateway", vulnerabilityName: "Acme Gateway RCE", dueDate: "2026-12-15", knownRansomwareCampaignUse: "Unknown", ...extra });
  const wrap = (d, date) => ({ ...d, published: date, publisher: "CISA", related_rules: [], added: date,
    source: { name: "CISA", title: "KEV", url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", license: "public domain" } });

  it("summarises one vulnerability in the singular", () => {
    const d = kevTemplate("2026-11-25", [v("CVE-2026-0001")]);
    expect(d.title.en).toBe("CISA adds 1 known exploited vulnerability to KEV (2026-11-25)");
    expect(d.title.zh).toContain("1 个");
    expect(d.severity).toBe("high");
    expect(d.tags).toEqual(["kev", "vulnerability"]);
  });

  it("marks ransomware use as critical and lists every due date once", () => {
    const d = kevTemplate("2026-11-25", [v("CVE-2026-0001", { knownRansomwareCampaignUse: "Known" }), v("CVE-2026-0002"), v("CVE-2026-0003", { dueDate: "2026-12-01" })]);
    expect(d.title.en).toContain("3 known exploited vulnerabilities");
    expect(d.severity).toBe("critical");
    expect(d.tags).toContain("ransomware");
    expect(d.summary.en).toContain("1 of them is known");
    expect(d.timeline.filter(t => t.en.startsWith("Remediation")).map(t => t.date)).toEqual(["2026-12-01", "2026-12-15"]);
  });

  it("produces an incident the site will accept", () => {
    const r = incidentSchema.safeParse(wrap(kevTemplate("2026-11-25", [v("CVE-2026-0001")]), "2026-11-25"));
    expect(r.error?.issues ?? []).toEqual([]);
  });
});
