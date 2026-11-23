---
title:
  zh: Cloudflare 2023 感恩节安全事件：未轮换的第三方泄露凭据被利用
  en: "Cloudflare Thanksgiving 2023 incident: unrotated credentials from a third-party breach"
summary:
  zh: 攻击者利用 2023 年 10 月 Okta 事件中泄露、但 Cloudflare 未轮换的一个服务令牌和几个服务账号，进入其自建的 Atlassian 服务器（Jira、Confluence、Bitbucket），植入 Sliver C2 并下载了部分代码仓库。官方称客户数据与系统未受影响。
  en: An attacker used a service token and service accounts leaked in the October 2023 Okta breach, which Cloudflare had not rotated, to access its self-hosted Atlassian server (Jira, Confluence, Bitbucket), install the Sliver C2 framework and download some code repositories. Cloudflare reports no customer data or systems were affected.
published: "2024-02-01"
publisher: Cloudflare
sector: { zh: 互联网基础设施, en: Internet infrastructure }
actor: 未具名，官方评估可能为国家级行为者 / Unnamed, assessed as likely nation-state
severity: high
tactics: [TA0001, TA0003, TA0006, TA0009, TA0010, TA0011]
techniques: []
tags: [supply-chain, credentials, atlassian, sliver]
initial_access:
  zh: 第三方（Okta）事件中泄露、未轮换的服务令牌与服务账号凭据
  en: Service token and service account credentials leaked in a third-party (Okta) breach and never rotated
detected_by:
  zh: 服务账号被加入管理员组后触发的自动告警
  en: Automated alert after a service account was added to an admin group
timeline:
  - { date: "2023-10-18", zh: "Okta 事件发生，Cloudflare 部分凭据外泄", en: "Okta compromise; some Cloudflare credentials exposed" }
  - { date: "2023-11-14", zh: "攻击者开始侦察，访问一个与主网络隔离的 AWS 环境", en: "Reconnaissance begins; attacker reaches a segmented AWS environment" }
  - { date: "2023-11-15", zh: "使用泄露的令牌和服务账号登录 Jira 与 Confluence", en: "Leaked token and service account used to access Jira and Confluence" }
  - { date: "2023-11-16", zh: "创建伪装成普通员工的账号以维持访问", en: "Attacker creates an employee-looking account for persistence" }
  - { date: "2023-11-22", zh: "通过 Jira 的 ScriptRunner 插件植入 Sliver C2", en: "Sliver C2 installed via the ScriptRunner for Jira plugin" }
  - { date: "2023-11-23", zh: "服务账号被加入管理员组，自动告警触发；当天停用相关账号并宣布事件", en: "Service account added to admin group triggers alert; accounts disabled and incident declared the same day" }
  - { date: "2023-11-24", zh: "最后一次观察到攻击活动，Sliver 被清除", en: "Last observed activity; Sliver removed" }
root_cause:
  zh: 第三方事件后未轮换被认为“没有在用”的服务令牌和服务账号凭据。
  en: Service token and service account credentials believed to be unused were not rotated after the third-party breach.
lessons:
  - { zh: 上游/第三方出事后，轮换所有可能泄露的凭据，包括服务令牌和服务账号, en: "After an upstream or third-party breach, rotate every possibly exposed credential, including service tokens and service accounts" }
  - { zh: 用零信任与网络分段限制单点凭据泄露的影响范围, en: Use Zero Trust and segmentation to limit the blast radius of a single leaked credential }
  - { zh: 把测试/预发布等非生产环境与生产网络隔离, en: Isolate test and staging systems from the production network }
detection_ideas:
  - { zh: 监控服务账号的权限组变更（本次正是靠这一条告警发现）, en: "Alert on group-membership changes for service accounts (this is what caught the attacker)" }
  - { zh: 关注 Wiki 中对 secret、token、remote access 等敏感词的集中搜索, en: "Watch for bursts of wiki searches for terms such as secret, token, remote access" }
  - { zh: 短时间内通过 git archive 批量下载代码仓库, en: Bulk repository downloads via git archive in a short window }
  - { zh: 协作平台插件（如 ScriptRunner）被用来执行代码或落地文件, en: Collaboration-platform plugins (e.g. ScriptRunner) used to run code or drop files }
related_rules:
  - proc_creation_win_hktl_sliver_c2_execution_pattern
source:
  name: Cloudflare Blog
  title: Thanksgiving 2023 security incident
  url: https://blog.cloudflare.com/thanksgiving-2023-security-incident
  license: 原文版权归原作者所有，本站仅提供摘要与链接 / Original © its authors; summary and link only
added: "2026-11-23"
---
