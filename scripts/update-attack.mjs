#!/usr/bin/env node
// 从 MITRE 官方 CTI 仓库生成精简的 ATT&CK 企业矩阵数据（技术编号 → 名称、所属战术），写到 src/data/attack.json。
// 用法：node scripts/update-attack.mjs [enterprise-attack.json 本地路径]
// ATT&CK® 数据 © The MITRE Corporation，按其使用条款引用并注明出处。
import fs from "node:fs";

const URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json";
const src = process.argv[2];
const bundle = src ? JSON.parse(fs.readFileSync(src, "utf8")) : await (await fetch(URL)).json();
const live = o => !o.revoked && !o.x_mitre_deprecated;
const extId = o => o.external_references?.find(r => r.source_name === "mitre-attack")?.external_id;

const tactics = Object.fromEntries(bundle.objects.filter(o => o.type === "x-mitre-tactic" && live(o)).map(o => [o.x_mitre_shortname, extId(o)]));
const techniques = {};
for (const o of bundle.objects.filter(o => o.type === "attack-pattern" && live(o))) {
  const id = extId(o);
  if (!id) continue;
  techniques[id] = {
    name: o.name,
    tactics: (o.kill_chain_phases || []).filter(k => k.kill_chain_name === "mitre-attack").map(k => tactics[k.phase_name]).filter(Boolean)
  };
}
const sorted = Object.fromEntries(Object.entries(techniques).sort(([a], [b]) => a.localeCompare(b, "en", { numeric: true })));
fs.writeFileSync("src/data/attack.json", JSON.stringify({ source: URL, generated: new Date().toISOString().slice(0, 10), tactics, techniques: sorted }) + "\n");
console.log(`wrote ${Object.keys(sorted).length} techniques, ${Object.keys(tactics).length} tactics`);
