---
title: HackTool - SharpChisel Execution
summary: Detects usage of the Sharp Chisel via the commandline arguments
sigma_id: cf93e05e-d798-4d9e-b522-b0248dc61eaf
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1090.001
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-05'
modified: '2023-02-13'
falsepositives:
  - Unlikely
references:
  - https://github.com/shantanu561993/SharpChisel
  - https://www.sentinelone.com/labs/wading-through-muddy-waters-recent-activity-of-an-iranian-state-sponsored-threat-actor/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_sharp_chisel.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - SharpChisel Execution
id: cf93e05e-d798-4d9e-b522-b0248dc61eaf
related:
    - id: 8b0e12da-d3c3-49db-bb4f-256703f380e5
      type: similar
status: test
description: Detects usage of the Sharp Chisel via the commandline arguments
references:
    - https://github.com/shantanu561993/SharpChisel
    - https://www.sentinelone.com/labs/wading-through-muddy-waters-recent-activity-of-an-iranian-state-sponsored-threat-actor/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-05
modified: 2023-02-13
tags:
    - attack.command-and-control
    - attack.t1090.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\SharpChisel.exe'
        - Product: 'SharpChisel'
    # See rule 8b0e12da-d3c3-49db-bb4f-256703f380e5 for Chisel.exe coverage
    condition: selection
falsepositives:
    - Unlikely
level: high
```
