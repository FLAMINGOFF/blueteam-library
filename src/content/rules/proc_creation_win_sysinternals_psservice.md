---
title: Sysinternals PsService Execution
summary: Detects usage of Sysinternals PsService which can be abused for service reconnaissance and tampering
sigma_id: 3371f518-5fe3-4cf6-a14b-2a0ae3fd8a4f
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0007
  - TA0003
techniques:
  - T1543.003
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-06-16'
modified: '2026-06-29'
falsepositives:
  - Legitimate use of PsService by an administrator
references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/psservice
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sysinternals_psservice.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Sysinternals PsService Execution
id: 3371f518-5fe3-4cf6-a14b-2a0ae3fd8a4f
status: test
description: Detects usage of Sysinternals PsService which can be abused for service reconnaissance and tampering
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/psservice
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-16
modified: 2026-06-29
tags:
    - attack.privilege-escalation
    - attack.discovery
    - attack.persistence
    - attack.t1543.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - OriginalFileName: 'psservice.exe'
        - Image|endswith:
              - '\PsService.exe'
              - '\PsService64.exe'
              - '\PsService64a.exe'
    condition: selection
falsepositives:
    - Legitimate use of PsService by an administrator
level: medium
```
