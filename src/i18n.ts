export const LANGS = ["zh", "en"] as const;
export type Lang = (typeof LANGS)[number];
export const langPaths = () => LANGS.map(lang => ({ params: { lang } }));

export const TACTICS: Record<string, { zh: string; en: string }> = {
  TA0043: { zh: "侦察", en: "Reconnaissance" },
  TA0042: { zh: "资源开发", en: "Resource Development" },
  TA0001: { zh: "初始访问", en: "Initial Access" },
  TA0002: { zh: "执行", en: "Execution" },
  TA0003: { zh: "持久化", en: "Persistence" },
  TA0004: { zh: "权限提升", en: "Privilege Escalation" },
  TA0005: { zh: "隐蔽", en: "Stealth" },
  TA0112: { zh: "防御削弱", en: "Defense Impairment" },
  TA0006: { zh: "凭据访问", en: "Credential Access" },
  TA0007: { zh: "发现", en: "Discovery" },
  TA0008: { zh: "横向移动", en: "Lateral Movement" },
  TA0009: { zh: "收集", en: "Collection" },
  TA0011: { zh: "命令与控制", en: "Command and Control" },
  TA0010: { zh: "数据渗出", en: "Exfiltration" },
  TA0040: { zh: "影响", en: "Impact" }
};
export const TACTIC_ORDER = Object.keys(TACTICS);

export const LEVELS: Record<string, { zh: string; en: string; rank: number }> = {
  critical: { zh: "严重", en: "Critical", rank: 0 },
  high: { zh: "高", en: "High", rank: 1 },
  medium: { zh: "中", en: "Medium", rank: 2 },
  low: { zh: "低", en: "Low", rank: 3 },
  informational: { zh: "信息", en: "Info", rank: 4 }
};
export const STATUS: Record<string, { zh: string; en: string }> = {
  stable: { zh: "稳定", en: "Stable" }, test: { zh: "测试", en: "Test" },
  experimental: { zh: "实验", en: "Experimental" }, unknown: { zh: "未知", en: "Unknown" }
};

const D = {
  site: { zh: "蓝队检测与复盘库", en: "Blue Team Detection & Incident Library" },
  tagline: { zh: "汇集公开的检测规则与安全事件报告，按 ATT&CK 组织，附原始来源与许可证。", en: "Public detection rules and incident reports, organized by ATT&CK, with original sources and licenses." },
  home: { zh: "总览", en: "Overview" },
  rules: { zh: "检测规则", en: "Detection Rules" },
  incidents: { zh: "事件复盘", en: "Incident Reviews" },
  matrix: { zh: "ATT&CK 覆盖", en: "ATT&CK Coverage" },
  starred: { zh: "我的收藏", en: "Saved" },
  about: { zh: "来源与许可", en: "Sources & Licenses" },
  search: { zh: "搜索", en: "Search" },
  save: { zh: "收藏", en: "Save" },
  sort: { zh: "排序", en: "Sort" },
  mainNav: { zh: "主导航", en: "Main" },
  quickNav: { zh: "快捷导航", en: "Quick navigation" },
  searchPh: { zh: "搜索规则标题、描述、ATT&CK 编号、事件、攻击者……", en: "Search rules, descriptions, ATT&CK IDs, incidents, actors…" },
  rulesCount: { zh: "条检测规则", en: "detection rules" },
  incidentsCount: { zh: "篇事件复盘", en: "incident reviews" },
  techCount: { zh: "个 ATT&CK 技术", en: "ATT&CK techniques" },
  sourceSynced: { zh: "规则同步自", en: "Rules synced from" },
  latestIncidents: { zh: "最新事件复盘", en: "Latest incident reviews" },
  featured: { zh: "精选规则", en: "Featured rules" },
  recentRules: { zh: "最近更新的规则", en: "Recently updated rules" },
  topTactics: { zh: "规则最多的战术", en: "Tactics with most rules" },
  all: { zh: "全部", en: "All" },
  tactic: { zh: "ATT&CK 战术", en: "ATT&CK tactic" },
  platform: { zh: "平台", en: "Platform" },
  level: { zh: "严重度", en: "Severity" },
  status: { zh: "状态", en: "Status" },
  sector: { zh: "行业", en: "Sector" },
  tags: { zh: "标签", en: "Tags" },
  clear: { zh: "清除筛选", en: "Clear filters" },
  sortNew: { zh: "最近更新", en: "Recently updated" },
  sortSev: { zh: "严重度优先", en: "Severity first" },
  results: { zh: "条结果", en: "results" },
  noResults: { zh: "没有匹配的结果，试试减少筛选条件。", en: "No matches. Try removing some filters." },
  more: { zh: "加载更多", en: "Load more" },
  description: { zh: "说明", en: "Description" },
  detection: { zh: "检测逻辑", en: "Detection logic" },
  copy: { zh: "复制", en: "Copy" },
  copied: { zh: "已复制", en: "Copied" },
  falsepositives: { zh: "已知误报", en: "Known false positives" },
  references: { zh: "参考资料", en: "References" },
  relatedIncidents: { zh: "关联事件", en: "Related incidents" },
  relatedRules: { zh: "相关检测规则", en: "Related detection rules" },
  author: { zh: "作者", en: "Author" },
  logsource: { zh: "日志源", en: "Log source" },
  techniques: { zh: "技术", en: "Techniques" },
  created: { zh: "创建", en: "Created" },
  modified: { zh: "更新", en: "Modified" },
  source: { zh: "来源", en: "Source" },
  license: { zh: "许可证", en: "License" },
  viewOriginal: { zh: "查看原始规则", en: "View original rule" },
  readOriginal: { zh: "阅读原始报告", en: "Read the original report" },
  untranslated: { zh: "原文为英文，暂无中文翻译", en: "" },
  overview: { zh: "概要", en: "Summary" },
  timeline: { zh: "时间线", en: "Timeline" },
  rootCause: { zh: "根因", en: "Root cause" },
  lessons: { zh: "防守方要点", en: "Lessons for defenders" },
  detectionIdeas: { zh: "检测思路", en: "Detection ideas" },
  initialAccess: { zh: "初始访问", en: "Initial access" },
  detectedBy: { zh: "发现方式", en: "How detected" },
  actor: { zh: "攻击者", en: "Threat actor" },
  publisher: { zh: "发布方", en: "Publisher" },
  published: { zh: "原文发布", en: "Published" },
  added: { zh: "本站收录", en: "Added" },
  summaryNote: { zh: "以下为本站根据原始报告撰写的摘要，细节以原文为准。", en: "This is our own summary of the original report. The original is authoritative." },
  generatedNote: { zh: "本篇由每日自动抓取 CISA 公开数据生成，未经人工逐条审校；如有出入请以原文为准。", en: "Generated automatically from public CISA data and not individually reviewed; refer to the original if anything differs." },
  rulesIntro: { zh: "来自 SigmaHQ 等公开项目的检测规则，保留原作者、原始链接与许可证。", en: "Detection rules from public projects such as SigmaHQ, with original authors, links and licenses." },
  incidentsIntro: { zh: "公开安全事件报告的结构化摘要：时间线、根因、防守要点和可用的检测规则。", en: "Structured summaries of public incident reports: timeline, root cause, lessons and usable detection rules." },
  matrixIntro: { zh: "各 ATT&CK 战术下收录的规则数量，点击进入对应列表。", en: "Rule counts per ATT&CK tactic. Click to open the filtered list." },
  starredIntro: { zh: "收藏只保存在当前浏览器中，无需登录。", en: "Saved items are stored in this browser only. No sign-in needed." },
  starredEmpty: { zh: "还没有收藏。点卡片右上角的 ☆ 即可收藏。", en: "Nothing saved yet. Click ☆ on any card to save it." },
  ruleUnit: { zh: "条规则", en: "rules" },
  incUnit: { zh: "篇复盘", en: "reviews" },
  theme: { zh: "主题", en: "Theme" },
  dark: { zh: "深色", en: "Dark" }, system: { zh: "系统", en: "Auto" }, light: { zh: "浅色", en: "Light" },
  footerLicense: { zh: "检测规则版权归原作者，按各自许可证（如 SigmaHQ 规则的 DRL 1.1）转载；事件摘要为本站撰写，原文版权归发布方。", en: "Rules remain the work of their authors and are redistributed under their licenses (e.g. DRL 1.1 for SigmaHQ). Incident summaries are our own; original reports belong to their publishers." },
  contribute: { zh: "通过 GitHub 提交 PR 参与收录", en: "Contribute via GitHub pull request" }
} as const;
export type Key = keyof typeof D;
export const t = (lang: Lang, k: Key) => (D[k] as any)[lang] as string;
export const dict = (lang: Lang) => Object.fromEntries(Object.entries(D).map(([k, v]) => [k, (v as any)[lang]]));
export const tacticName = (lang: Lang, id: string) => TACTICS[id]?.[lang] ?? id;
export const levelName = (lang: Lang, l: string) => LEVELS[l]?.[lang] ?? l;
export const statusName = (lang: Lang, s: string) => STATUS[s]?.[lang] ?? s;
export const otherLang = (lang: Lang): Lang => (lang === "zh" ? "en" : "zh");
export const B = (import.meta.env.BASE_URL || "/").replace(/\/$/, "");
