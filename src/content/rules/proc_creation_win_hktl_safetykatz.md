---
title: HackTool - SafetyKatz Execution
summary: Detects the execution of the hacktool SafetyKatz via PE information and default Image name
sigma_id: b1876533-4ed5-4a83-90f3-b8645840a413
status: test
level: critical
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1003.001
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-10-20'
modified: '2023-02-04'
falsepositives:
  - Unlikely
references:
  - https://github.com/GhostPack/SafetyKatz
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_safetykatz.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - SafetyKatz Execution
id: b1876533-4ed5-4a83-90f3-b8645840a413
status: test
description: Detects the execution of the hacktool SafetyKatz via PE information and default Image name
references:
    - https://github.com/GhostPack/SafetyKatz
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-20
modified: 2023-02-04
tags:
    - attack.credential-access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\SafetyKatz.exe'
        - OriginalFileName: 'SafetyKatz.exe'
        - Description: 'SafetyKatz'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```
