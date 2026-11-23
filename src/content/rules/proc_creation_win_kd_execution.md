---
title: Windows Kernel Debugger Execution
summary: Detects execution of the Windows Kernel Debugger "kd.exe".
sigma_id: 27ee9438-90dc-4bef-904b-d3ef927f5e7e
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-05-15'
modified: '2024-04-24'
falsepositives:
  - Rare occasions of legitimate cases where kernel debugging is necessary in production. Investigation is required
references:
  - Internal Research
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_kd_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Windows Kernel Debugger Execution
id: 27ee9438-90dc-4bef-904b-d3ef927f5e7e
status: test
description: Detects execution of the Windows Kernel Debugger "kd.exe".
references:
    - Internal Research
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-15
modified: 2024-04-24
tags:
    - attack.privilege-escalation
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\kd.exe'
        - OriginalFileName: 'kd.exe'
    condition: selection
falsepositives:
    - Rare occasions of legitimate cases where kernel debugging is necessary in production. Investigation is required
level: medium
```
