---
title: HackTool - DInjector PowerShell Cradle Execution
summary: Detects the use of the Dinject PowerShell cradle based on the specific flags
sigma_id: d78b5d61-187d-44b6-bf02-93486a80de5a
status: test
level: critical
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0005
techniques:
  - T1055
author: Florian Roth (Nextron Systems)
date: '2021-12-07'
modified: '2023-02-04'
falsepositives:
  - Unlikely
references:
  - https://web.archive.org/web/20211001064856/https://github.com/snovvcrash/DInjector
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_dinjector.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - DInjector PowerShell Cradle Execution
id: d78b5d61-187d-44b6-bf02-93486a80de5a
status: test
description: Detects the use of the Dinject PowerShell cradle based on the specific flags
references:
    - https://web.archive.org/web/20211001064856/https://github.com/snovvcrash/DInjector # Original got deleted. This is a fork
author: Florian Roth (Nextron Systems)
date: 2021-12-07
modified: 2023-02-04
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - ' /am51'
            - ' /password'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```
