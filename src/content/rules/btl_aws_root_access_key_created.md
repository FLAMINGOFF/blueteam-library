---
title: Access Key Created For The AWS Root User
summary: |-
  Detects a successful CreateAccessKey call made by the root user of an AWS account.
  AWS recommends that the root user has no access keys at all, so a new one is either a serious policy violation or an attacker creating long-lived persistence after taking over the root account.
sigma_id: d456fc38-27a8-4d06-b8ea-6c1a099c5cd3
status: experimental
level: high
platform: aws
logsource: aws / cloudtrail
tactics:
  - TA0003
  - TA0004
techniques:
  - T1098.001
author: FLAMINGOFF
date: '2026-11-27'
falsepositives:
  - None expected; every hit should be reviewed
references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html
  - https://attack.mitre.org/techniques/T1098/001/
source:
  name: Blue Team Library
  url: https://github.com/FLAMINGOFF/blueteam-library/blob/main/src/content/rules/btl_aws_root_access_key_created.md
  license: Original
format: Sigma
original: true
title_zh: 为 AWS 根用户创建访问密钥
summary_zh: 检测 AWS 账户根用户成功调用 CreateAccessKey。AWS 建议根用户完全不要有访问密钥，所以出现新密钥要么是严重的违规操作，要么是攻击者接管根账户后在建立长期持久化。
notes_zh: 响应时先用 IAM 凭证报告确认密钥是否仍存在，再检查同一会话前后的 ConsoleLogin、MFA 变更和新建用户等事件。
notes_en: When responding, confirm with the IAM credential report whether the key still exists, then review ConsoleLogin, MFA changes and new users around the same session.
samples:
  - name:
      zh: 根用户新建访问密钥
      en: Root creates an access key
    expect: true
    event:
      eventSource: iam.amazonaws.com
      eventName: CreateAccessKey
      awsRegion: us-east-1
      sourceIPAddress: 198.51.100.200
      userIdentity:
        type: Root
        arn: arn:aws:iam::111122223333:root
        accountId: '111122223333'
      responseElements:
        accessKey:
          accessKeyId: AKIAEXAMPLEROOTKEY01
          status: Active
  - name:
      zh: 普通 IAM 用户轮换自己的密钥
      en: An IAM user rotating their own key
    expect: false
    event:
      eventSource: iam.amazonaws.com
      eventName: CreateAccessKey
      userIdentity:
        type: IAMUser
        arn: arn:aws:iam::111122223333:user/ci-bot
  - name:
      zh: 根用户尝试但被 SCP 拒绝
      en: Root attempt denied by an SCP
    expect: false
    event:
      eventSource: iam.amazonaws.com
      eventName: CreateAccessKey
      errorCode: AccessDenied
      userIdentity:
        type: Root
        arn: arn:aws:iam::111122223333:root
---

```yaml
title: Access Key Created For The AWS Root User
id: d456fc38-27a8-4d06-b8ea-6c1a099c5cd3
status: experimental
description: |
  Detects a successful CreateAccessKey call made by the root user of an AWS account.
  AWS recommends that the root user has no access keys at all, so a new one is either a serious policy violation or an attacker creating long-lived persistence after taking over the root account.
references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html
  - https://attack.mitre.org/techniques/T1098/001/
author: FLAMINGOFF
date: 2026-11-27
tags:
  - attack.persistence
  - attack.privilege-escalation
  - attack.t1098.001
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName: 'CreateAccessKey'
    userIdentity.type: 'Root'
  filter_main_failed:
    errorCode|exists: true
  condition: selection and not filter_main_failed
falsepositives:
  - None expected; every hit should be reviewed
level: high
```
