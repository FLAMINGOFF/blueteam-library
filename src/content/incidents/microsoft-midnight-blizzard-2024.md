---
title:
  zh: Midnight Blizzard 通过密码喷洒与 OAuth 应用滥用访问微软企业邮箱
  en: Midnight Blizzard accesses Microsoft corporate email via password spray and OAuth app abuse
summary:
  zh: 攻击者对一个未启用 MFA 的遗留测试租户账号进行低频密码喷洒，随后滥用一个对企业环境有高权限的遗留测试 OAuth 应用，创建恶意 OAuth 应用并获取 Exchange Online 的 full_access_as_app 权限，通过 EWS 读取企业邮件。微软于 2024 年 1 月 12 日发现。
  en: The attacker password-sprayed a legacy test tenant account without MFA, then abused a legacy test OAuth app with elevated access, created malicious OAuth apps, obtained the Exchange Online full_access_as_app role and read corporate email over EWS. Microsoft detected it on January 12, 2024.
published: "2024-01-25"
publisher: Microsoft Threat Intelligence
sector: { zh: 科技, en: Technology }
actor: Midnight Blizzard (NOBELIUM / APT29)
severity: high
tactics: [TA0001, TA0003, TA0004, TA0009]
techniques: []
tags: [identity, oauth, cloud, email, password-spray]
initial_access:
  zh: 对未启用 MFA 的遗留测试账号进行密码喷洒，并通过住宅代理隐藏来源
  en: Password spray against a legacy test account without MFA, via residential proxies
detected_by:
  zh: 安全团队分析审计日志中的 EWS 活动
  en: Security team review of EWS activity in audit logs
timeline:
  - { date: "2024-01-12", zh: "微软安全团队发现针对企业系统的攻击并启动响应", en: "Microsoft detects the attack on corporate systems and starts response" }
  - { date: "2024-01-25", zh: "发布面向响应人员的指南", en: "Guidance for responders published" }
  - { date: "2024-02-05", zh: "指南更新（移除一条不通用的查询）", en: "Guidance updated (one query removed)" }
root_cause:
  zh: 遗留测试账号未启用 MFA；遗留测试 OAuth 应用对生产企业环境拥有过高权限。
  en: A legacy test account without MFA, and a legacy test OAuth app with excessive privileges in the corporate environment.
lessons:
  - { zh: 审计所有身份、服务主体与 OAuth 应用的权限，回收 full_access_as_app 等不再需要的授权, en: "Audit privileges of all identities, service principals and OAuth apps; remove unneeded grants such as full_access_as_app" }
  - { zh: 审计 Exchange Online 中 ApplicationImpersonation 角色的持有者, en: Audit holders of the ApplicationImpersonation role in Exchange Online }
  - { zh: 测试租户与遗留账号同样要强制 MFA, en: Enforce MFA on test tenants and legacy accounts too }
  - { zh: 住宅代理导致 IP 变化快，仅靠 IOC 不够，应依赖行为与身份风险信号, en: "Residential proxies rotate IPs quickly, so rely on behavior and identity risk signals, not IOCs alone" }
detection_ideas:
  - { zh: OAuth 应用被授予 full_access_as_app 权限, en: OAuth app granted full_access_as_app }
  - { zh: 新增具有高权限的服务主体或用户, en: New service principal or user with elevated permissions }
  - { zh: 仅应用权限的应用大量访问邮件、EWS 调用量突增, en: App-only permission app accessing many mailboxes; spike in EWS calls }
  - { zh: 密码喷洒类登录风险告警, en: Password-spray sign-in risk alerts }
related_rules: []
source:
  name: Microsoft Security Blog
  title: "Midnight Blizzard: Guidance for responders on nation-state attack"
  url: https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/
  license: 原文版权归原作者所有，本站仅提供摘要与链接 / Original © its authors; summary and link only
added: "2026-11-23"
---
