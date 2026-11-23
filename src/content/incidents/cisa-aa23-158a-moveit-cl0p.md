---
title:
  zh: CL0P 勒索团伙利用 MOVEit Transfer 零日漏洞（CVE-2023-34362）窃取数据
  en: CL0P ransomware gang exploits MOVEit Transfer zero-day (CVE-2023-34362)
summary:
  zh: 美国 CISA 与 FBI 联合通报：CL0P（又称 TA505）自 2023 年 5 月 27 日起利用 MOVEit Transfer 的 SQL 注入零日漏洞，在面向互联网的服务器上植入 LEMURLOOT WebShell，从数据库中窃取文件后勒索受害者。
  en: "Joint CISA/FBI advisory: starting May 27, 2023, CL0P (aka TA505) exploited a SQL injection zero-day in MOVEit Transfer to drop the LEMURLOOT web shell on internet-facing servers, steal data from the database and extort victims."
published: "2023-06-07"
publisher: CISA / FBI
sector: { zh: 多行业（使用 MOVEit Transfer 的组织）, en: Multiple sectors (MOVEit Transfer users) }
actor: CL0P / TA505
severity: critical
tactics: [TA0001, TA0002, TA0003, TA0004, TA0005, TA0007, TA0008, TA0009, TA0011, TA0010]
techniques: [T1190, T1566, T1059.001, T1059.003, T1129, T1505.003, T1546.011, T1068, T1055, T1070, T1574.002, T1018, T1021.002, T1563.002, T1113, T1071, T1105, T1041]
tags: [ransomware, webshell, zero-day, file-transfer]
initial_access:
  zh: 利用面向互联网的 MOVEit Transfer SQL 注入零日漏洞（T1190）
  en: SQL injection zero-day in internet-facing MOVEit Transfer (T1190)
detected_by:
  zh: 通报基于公开信息与 FBI 调查，未描述单个受害者的发现方式
  en: Advisory is based on open sources and FBI investigations; it does not describe how individual victims detected it
timeline:
  - { date: "2019-02", zh: "CL0P 勒索软件出现", en: "CL0P ransomware first appears" }
  - { date: "2023-01", zh: "CL0P 利用 GoAnywhere MFT 零日漏洞（CVE-2023-0669）", en: "CL0P exploits GoAnywhere MFT zero-day (CVE-2023-0669)" }
  - { date: "2023-05-27", zh: "开始利用 MOVEit Transfer 漏洞 CVE-2023-34362", en: "Exploitation of MOVEit Transfer CVE-2023-34362 begins" }
  - { date: "2023-06-02", zh: "CISA 将该漏洞加入已知被利用漏洞（KEV）目录", en: "CISA adds the CVE to the Known Exploited Vulnerabilities catalog" }
  - { date: "2023-06-07", zh: "CISA 与 FBI 发布联合通报", en: "CISA and FBI publish the joint advisory" }
  - { date: "2023-06-16", zh: "通报更新（补充 GoAnywhere 相关 IP）", en: "Advisory updated (GoAnywhere IP lists)" }
root_cause:
  zh: 面向互联网的文件传输应用存在未修补的零日 SQL 注入漏洞；攻击者在提权前就已能直接访问数据库。
  en: An unpatched zero-day SQL injection in an internet-facing file transfer app; the attacker could reach the database directly.
lessons:
  - { zh: 优先修补面向互联网系统上的已知被利用漏洞, en: Patch known-exploited vulnerabilities on internet-facing systems first }
  - { zh: 定期审计域控、服务器与应用中的新增或未知账号，尤其是管理员账号, en: "Audit domain controllers, servers and apps for new or unknown accounts, especially admins" }
  - { zh: 重建 Web 服务器时若保留数据库，需同时清理攻击者创建的应用账号, en: "If you rebuild the web server but keep the database, remove attacker-created app accounts too" }
  - { zh: 限制 RDP 与 PowerShell 使用，启用抗钓鱼 MFA, en: "Restrict RDP and PowerShell use; require phishing-resistant MFA" }
  - { zh: 保留离线、加密、不可篡改的备份, en: "Keep offline, encrypted, immutable backups" }
detection_ideas:
  - { zh: Web 日志中出现带 X-siLock-Comment 请求头的访问，或 human2.aspx 等可疑文件, en: Web logs with the X-siLock-Comment header or files such as human2.aspx }
  - { zh: 应用中新增名为 “Health Check Service” 的管理员账号, en: "New admin accounts named \"Health Check Service\" in the app" }
  - { zh: Web 服务进程派生命令行或脚本解释器, en: Web server processes spawning shells or script interpreters }
related_rules:
  - proc_creation_win_webshell_susp_process_spawned_from_webserver
  - proc_creation_win_webshell_recon_commands_and_processes
source:
  name: CISA
  title: "#StopRansomware: CL0P Ransomware Gang Exploits CVE-2023-34362 MOVEit Vulnerability (AA23-158A)"
  url: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a
  license: 美国政府作品，通常属公有领域；本站提供摘要与链接 / US government work, generally public domain; summary and link
added: "2026-11-23"
---
