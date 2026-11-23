// 给规则补充中文标题/摘要并标记精选：node scripts/set-zh.mjs（编辑下方表格）
import fs from "node:fs";
import * as yaml from "js-yaml";
const ZH = {
  proc_access_win_lsass_memdump: ["通过 LSASS 进行凭据转储的可疑活动", "检测以特定调用栈和访问掩码访问 LSASS 进程的行为。Mimikatz、NanoDump、Procdump 乃至任务管理器的转储功能都会表现出这种行为。"],
  aws_cloudtrail_disable_logging: ["AWS CloudTrail 审计日志被停用或删除", "检测停用、删除或更新 CloudTrail 跟踪（Trail）的操作。"],
  proc_creation_win_certutil_download: ["使用 certutil 下载文件", "检测带有可让 certutil 下载文件的特定参数的执行。"],
  proc_creation_win_webshell_susp_process_spawned_from_webserver: ["Web 服务进程派生可疑进程", "检测 Web 服务进程派生出可疑子进程，这可能意味着 WebShell 已被植入或漏洞已被利用。"],
  proc_creation_win_hktl_sliver_c2_execution_pattern: ["Sliver C2 植入程序的执行特征", "检测 Sliver C2 框架植入程序常见的进程活动模式。"],
  proc_creation_win_mshta_susp_child_processes: ["mshta.exe 派生可疑子进程", "检测由 mshta.exe 派生的可疑进程，可能表示恶意 HTA 脚本正在执行。"],
  proc_creation_win_office_susp_child_processes: ["Office 应用派生可疑子进程", "检测从 Microsoft Office 套件（Word、Excel、PowerPoint、Publisher、Visio 等）派生的可疑进程。"],
  proc_creation_win_susp_shadow_copies_deletion: ["删除卷影副本", "检测使用操作系统自带工具删除卷影副本的行为。"]
};
for (const [slug, [t, s]] of Object.entries(ZH)) {
  const f = `src/content/rules/${slug}.md`;
  const txt = fs.readFileSync(f, "utf8");
  const m = txt.match(/^---\n([\s\S]*?)\n---\n/);
  const fm = yaml.load(m[1]); fm.title_zh = t; fm.summary_zh = s; fm.featured = true;
  fs.writeFileSync(f, "---\n" + yaml.dump(fm, { lineWidth: 200 }) + "---\n" + txt.slice(m[0].length));
}
console.log("ok", Object.keys(ZH).length);
