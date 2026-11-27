---
title:
  zh: 原创模拟演练：Web 应用 RCE、根凭证泄露与公开的 S3 存储桶
  en: "Original tabletop scenario: web app RCE, leaked root credentials and a public S3 bucket"
summary:
  zh: 这是本站原创的虚构演练场景，不对应任何真实事件。攻击者利用 EC2 上一个 Node.js 应用的远程代码执行漏洞弹回 Shell，在部署目录里找到误放的根用户访问密钥，用它新建一把根密钥做持久化，再把存放客户导出数据的 S3 存储桶设为公开。场景串起本站的 3 条原创规则，分别覆盖主机和云控制面。
  en: An original, fictional exercise that does not describe any real incident. An attacker exploits remote code execution in a Node.js app on EC2, gets a reverse shell, finds root access keys left in the deploy folder, creates a second root key for persistence and makes the bucket holding customer exports public. It links three of this site's original rules across the host and the cloud control plane.
published: "2026-11-27"
publisher: Blue Team Library
sector: { zh: 虚构 SaaS 公司（演练）, en: Fictional SaaS company (exercise) }
severity: critical
tactics: [TA0001, TA0002, TA0006, TA0003, TA0009]
techniques: [T1190, T1059.004, T1552.001, T1098.001, T1530]
tags: [original, tabletop, aws, linux]
initial_access:
  zh: 面向公网的 Node.js 应用存在远程代码执行漏洞
  en: Remote code execution in an internet-facing Node.js application
detected_by:
  zh: 演练设计为反弹 Shell 时首次告警（主机 EDR）；云侧两条规则在 CloudTrail 中各自告警
  en: Designed so the first alert fires on the reverse shell (host EDR); the two cloud rules alert separately in CloudTrail
timeline:
  - { date: "T+0", zh: "攻击者向 /api/render 发送恶意模板，触发远程代码执行", en: "Attacker sends a malicious template to /api/render and gets code execution" }
  - { date: "T+1m", zh: "node 进程派生 bash -i >& /dev/tcp/…（命中：bash /dev/tcp 反弹 Shell）", en: "The node process spawns bash -i >& /dev/tcp/… (fires: bash /dev/tcp reverse shell)" }
  - { date: "T+10m", zh: "在 /srv/app/.env.bak 里找到根用户的访问密钥", en: "Finds root user access keys in /srv/app/.env.bak" }
  - { date: "T+25m", zh: "用根密钥调用 CreateAccessKey 新建第二把根密钥（命中：为根用户创建访问密钥）", en: "Uses the root key to call CreateAccessKey for a second root key (fires: root access key created)" }
  - { date: "T+40m", zh: "对 corp-exports 存储桶执行 PutBucketAcl public-read（命中：S3 ACL 授予公开访问）", en: "Runs PutBucketAcl public-read on the corp-exports bucket (fires: S3 ACL grants public access)" }
root_cause:
  zh: 演练假设：模板渲染接口未做沙箱；根用户存在长期访问密钥且被写进了部署备份文件；账户未开启 S3 Block Public Access。
  en: "Exercise assumptions: the template endpoint was not sandboxed, the root user had long-lived access keys that ended up in a deploy backup file, and the account did not enable S3 Block Public Access."
lessons:
  - { zh: "删除根用户的所有访问密钥，并给根用户开启硬件 MFA", en: "Delete all root user access keys and protect root with hardware MFA" }
  - { zh: "在账户级别开启 S3 Block Public Access，公开内容改用 CloudFront", en: "Enable S3 Block Public Access at account level and serve public content through CloudFront" }
  - { zh: "应用用 EC2 实例角色获取临时凭证，不在磁盘上保存任何长期密钥", en: "Give the app an EC2 instance role for temporary credentials and keep no long-lived keys on disk" }
  - { zh: "限制 Web 服务进程派生 Shell（如 seccomp、AppArmor 或容器只读文件系统）", en: "Stop web service processes from spawning shells (seccomp, AppArmor or a read-only container filesystem)" }
detection_ideas:
  - { zh: "把主机告警里的实例 ID 与 CloudTrail 中来自该实例公网 IP 的 API 调用关联", en: "Correlate the instance ID from the host alert with CloudTrail calls coming from that instance's public IP" }
  - { zh: "补充一条规则：根用户的任何 API 调用（ConsoleLogin 以外）都告警", en: "Add a rule that alerts on any root user API call other than ConsoleLogin" }
related_rules:
  - btl_lnx_shell_dev_tcp_reverse_shell
  - btl_aws_root_access_key_created
  - btl_aws_s3_acl_grants_public_access
source:
  name: Blue Team Library
  title: 原创模拟演练 / Original tabletop scenario
  url: https://github.com/FLAMINGOFF/blueteam-library/blob/main/src/content/incidents/btl-sim-cloud-rce-to-public-s3.md
  license: 原创 / Original
added: "2026-11-27"
original: true
---
