---
title: HackTool - LittleCorporal Generated Maldoc Injection
summary: Detects the process injection of a LittleCorporal generated Maldoc.
sigma_id: 7bdde3bf-2a42-4c39-aa31-a92b3e17afac
status: test
level: high
platform: windows
logsource: windows / process_access
tactics:
  - TA0002
  - TA0004
techniques:
  - T1204.002
  - T1055.003
author: Christian Burkard (Nextron Systems)
date: '2021-08-09'
modified: '2023-11-28'
falsepositives:
  - Unknown
references:
  - https://github.com/connormcgarr/LittleCorporal
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_access/proc_access_win_hktl_littlecorporal_generated_maldoc.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - LittleCorporal Generated Maldoc Injection
id: 7bdde3bf-2a42-4c39-aa31-a92b3e17afac
status: test
description: Detects the process injection of a LittleCorporal generated Maldoc.
references:
    - https://github.com/connormcgarr/LittleCorporal
author: Christian Burkard (Nextron Systems)
date: 2021-08-09
modified: 2023-11-28
tags:
    - attack.execution
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1204.002
    - attack.t1055.003
logsource:
    category: process_access
    product: windows
detection:
    selection:
        SourceImage|endswith: '\winword.exe'
        CallTrace|contains|all:
            - ':\Windows\Microsoft.NET\Framework64\v2.'
            - 'UNKNOWN'
    condition: selection
falsepositives:
    - Unknown
level: high
```
