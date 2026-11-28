---
title: Domain Trust And Domain Controller Discovery Via Nltest
summary: |-
  Detects nltest.exe enumerating domain trusts or domain controllers.
  Ransomware affiliates and intrusion sets run these commands early to map the forest before moving laterally.
sigma_id: 6d8a3a49-795f-414c-9500-7a3ca40701f2
status: experimental
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1482
author: FLAMINGOFF
date: '2026-11-27'
falsepositives:
  - Domain administrators troubleshooting trusts or DC location
references:
  - https://attack.mitre.org/techniques/T1482/
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11)
source:
  name: Blue Team Library
  url: https://github.com/FLAMINGOFF/blueteam-library/blob/main/src/content/rules/btl_win_nltest_domain_trust_discovery.md
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
original: true
title_zh: 使用 nltest 发现域信任关系与域控制器
summary_zh: 检测 nltest.exe 枚举域信任关系或域控制器。勒索软件团伙和入侵者常在早期运行这些命令，摸清林结构后再横向移动。
notes_zh: 管理员也会用 nltest 排障，单独告警价值中等。建议与同一主机短时间内的其他发现类命令（net group、whoami /groups、AdFind）一起看。
notes_en: Admins use nltest for troubleshooting, so on its own this is medium value. Look at it alongside other discovery commands on the same host in a short window (net group, whoami /groups, AdFind).
samples:
  - name:
      zh: 枚举所有信任
      en: Enumerate all trusts
    expect: true
    event:
      EventID: 1
      Image: C:\Windows\System32\nltest.exe
      OriginalFileName: nltestrk.exe
      CommandLine: nltest /domain_trusts /all_trusts
      ParentImage: C:\Windows\System32\cmd.exe
  - name:
      zh: 列出域控制器
      en: List domain controllers
    expect: true
    event:
      EventID: 1
      Image: C:\Windows\System32\nltest.exe
      CommandLine: nltest.exe /dclist:corp.example.com
  - name:
      zh: 查询安全通道状态（排障）
      en: Secure channel check (troubleshooting)
    expect: false
    event:
      EventID: 1
      Image: C:\Windows\System32\nltest.exe
      CommandLine: nltest /sc_query:corp.example.com
---

```yaml
title: Domain Trust And Domain Controller Discovery Via Nltest
id: 6d8a3a49-795f-414c-9500-7a3ca40701f2
status: experimental
description: |
  Detects nltest.exe enumerating domain trusts or domain controllers.
  Ransomware affiliates and intrusion sets run these commands early to map the forest before moving laterally.
references:
  - https://attack.mitre.org/techniques/T1482/
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935(v=ws.11)
author: FLAMINGOFF
date: 2026-11-27
tags:
  - attack.discovery
  - attack.t1482
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith: '\nltest.exe'
    - OriginalFileName: 'nltestrk.exe'
  selection_args:
    CommandLine|contains|windash:
      - ' /domain_trusts'
      - ' /all_trusts'
      - ' /trusted_domains'
      - ' /dclist:'
      - ' /dsgetdc:'
  condition: all of selection_*
falsepositives:
  - Domain administrators troubleshooting trusts or DC location
level: medium
```
