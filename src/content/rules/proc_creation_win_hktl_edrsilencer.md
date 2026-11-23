---
title: HackTool - EDRSilencer Execution
summary: >-
  Detects the execution of EDRSilencer, a tool that leverages Windows Filtering Platform (WFP) to block Endpoint Detection and Response (EDR) agents from reporting security events to the server based
  on PE metadata information.
sigma_id: eb2d07d4-49cb-4523-801a-da002df36602
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0112
techniques:
  - T1685
author: '@gott_cyber'
date: '2024-01-02'
falsepositives:
  - Unlikely
references:
  - https://github.com/netero1010/EDRSilencer
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_edrsilencer.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - EDRSilencer Execution
id: eb2d07d4-49cb-4523-801a-da002df36602
status: test
description: |
    Detects the execution of EDRSilencer, a tool that leverages Windows Filtering Platform (WFP) to block Endpoint Detection and Response (EDR) agents from reporting security events to the server based on PE metadata information.
references:
    - https://github.com/netero1010/EDRSilencer
author: '@gott_cyber'
date: 2024-01-02
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\EDRSilencer.exe'
        - OriginalFileName: 'EDRSilencer.exe'
        - Description|contains: 'EDRSilencer'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
