---
title:
  zh: 原创模拟演练：从钓鱼附件到导出 NTDS.dit
  en: "Original tabletop scenario: from a phishing attachment to an NTDS.dit dump"
summary:
  zh: 这是本站原创的虚构演练场景，不对应任何真实事件。财务部一名员工打开钓鱼邮件里的脚本附件，攻击者用系统自带的 curl 拉取载荷、用计划任务持久化、给 Defender 添加排除项，再用 nltest 摸清域结构，最终在域控上从卷影副本复制出 NTDS.dit。场景用来演示本站的 5 条原创规则如何在攻击链的不同阶段各自命中。
  en: An original, fictional exercise that does not describe any real incident. A finance employee opens a script attachment from a phishing email. The attacker pulls a payload with the built-in curl, persists with a scheduled task, adds a Defender exclusion, maps the domain with nltest and finally copies NTDS.dit from a shadow copy on a domain controller. It shows how five of this site's original rules each fire at a different stage of the chain.
published: "2026-11-27"
publisher: Blue Team Library
sector: { zh: 虚构企业（演练）, en: Fictional company (exercise) }
severity: critical
tactics: [TA0001, TA0002, TA0003, TA0005, TA0112, TA0007, TA0006, TA0011]
techniques: [T1566.001, T1105, T1053.005, T1564.012, T1685, T1482, T1003.003]
tags: [original, tabletop, active-directory, windows]
initial_access:
  zh: 钓鱼邮件附件（压缩包里的 .js 脚本），用户双击运行
  en: Phishing attachment (a .js script inside an archive) run by the user
detected_by:
  zh: 演练设计为第 2 步（curl 写入 Public 目录）首次告警；若当时未处理，后续每一步都会再次告警
  en: Designed so the first alert fires at step 2 (curl writing into Public); if ignored, every later step alerts again
timeline:
  - { date: "T+0", zh: "用户在工作站 FIN-WS-07 上运行邮件附件里的 invoice.js", en: "User runs invoice.js from an email attachment on workstation FIN-WS-07" }
  - { date: "T+2m", zh: "脚本调用 curl -o C:\\Users\\Public\\svc.exe 下载载荷（命中：curl 下载到暂存目录）", en: "Script calls curl -o C:\\Users\\Public\\svc.exe to fetch the payload (fires: curl download to staging dir)" }
  - { date: "T+3m", zh: "创建登录时运行 svc.exe 的计划任务（命中：计划任务指向用户可写路径）", en: "Scheduled task created to run svc.exe at logon (fires: scheduled task from user-writable path)" }
  - { date: "T+5m", zh: "用 PowerShell 把 C:\\ProgramData\\cache 加入 Defender 排除项（命中：Defender 排除用户可写路径）", en: "PowerShell adds C:\\ProgramData\\cache as a Defender exclusion (fires: Defender exclusion for user-writable path)" }
  - { date: "T+40m", zh: "运行 nltest /domain_trusts 与 /dclist（命中：nltest 发现域信任）", en: "Runs nltest /domain_trusts and /dclist (fires: nltest domain trust discovery)" }
  - { date: "T+1d", zh: "用窃取的管理员凭据登录域控，创建卷影副本并复制 ntds.dit（命中：复制 NTDS.dit）", en: "Logs on to a DC with stolen admin credentials, creates a shadow copy and copies ntds.dit (fires: NTDS.dit copy)" }
root_cause:
  zh: 演练假设：邮件网关放行了压缩包里的脚本；工作站允许运行 .js 文件；早期告警没有人跟进，攻击者有一天时间拿到域管凭据。
  en: "Exercise assumptions: the mail gateway let a script inside an archive through, workstations run .js files by default, and early alerts were not triaged, giving the attacker a day to obtain domain admin credentials."
lessons:
  - { zh: "把 .js、.vbs、.hta 等脚本的默认打开方式改成记事本，从源头切断这类初始访问", en: "Change the default handler for .js, .vbs and .hta to Notepad to cut off this initial access path" }
  - { zh: "第一条告警出现时就隔离主机；本场景从第 2 步到拿下域控有一天窗口", en: "Isolate the host at the first alert; in this scenario there is a full day between step 2 and the DC compromise" }
  - { zh: "Defender 排除项改动应视为高危事件，并用篡改保护（Tamper Protection）限制", en: "Treat Defender exclusion changes as high severity and restrict them with Tamper Protection" }
  - { zh: "域管账户只在专用的特权访问工作站上使用，不在普通工作站登录", en: "Use domain admin accounts only from dedicated privileged access workstations, never on ordinary endpoints" }
detection_ideas:
  - { zh: "把同一主机 1 小时内的多条原创规则告警合并成一个事件，按攻击链排序，帮助值班人员一眼看出严重性", en: "Group alerts from these rules on the same host within an hour into one case, ordered by kill-chain stage, so the on-call analyst sees the severity at once" }
  - { zh: "补充一条规则：wscript/cscript 从邮件客户端或压缩软件的临时目录启动脚本", en: "Add a rule for wscript/cscript launching scripts from mail client or archive tool temp folders" }
related_rules:
  - btl_win_curl_download_to_staging_dir
  - btl_win_schtasks_create_user_writable_path
  - btl_win_defender_exclusion_user_writable_path
  - btl_win_nltest_domain_trust_discovery
  - btl_win_ntds_dit_copy_builtin_tools
source:
  name: Blue Team Library
  title: 原创模拟演练 / Original tabletop scenario
  url: https://github.com/FLAMINGOFF/blueteam-library/blob/main/src/content/incidents/btl-sim-phish-to-ntds.md
  license: Detection Rule License (DRL) 1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
added: "2026-11-27"
original: true
---
