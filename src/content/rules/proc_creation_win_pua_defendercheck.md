---
title: PUA - DefenderCheck Execution
summary: >-
  Detects the use of DefenderCheck, a tool to evaluate the signatures used in Microsoft Defender. It can be used to figure out the strings / byte chains used in Microsoft Defender to detect a tool and
  thus used for AV evasion.
sigma_id: f0ca6c24-3225-47d5-b1f5-352bf07ecfa7
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1027.005
author: Florian Roth (Nextron Systems)
date: '2022-08-30'
modified: '2023-02-04'
falsepositives:
  - Unlikely
references:
  - https://github.com/matterpreter/DefenderCheck
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_pua_defendercheck.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PUA - DefenderCheck Execution
id: f0ca6c24-3225-47d5-b1f5-352bf07ecfa7
status: test
description: Detects the use of DefenderCheck, a tool to evaluate the signatures used in Microsoft Defender. It can be used to figure out the strings / byte chains used in Microsoft Defender to detect a tool and thus used for AV evasion.
references:
    - https://github.com/matterpreter/DefenderCheck
author: Florian Roth (Nextron Systems)
date: 2022-08-30
modified: 2023-02-04
tags:
    - attack.stealth
    - attack.t1027.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\DefenderCheck.exe'
        - Description: 'DefenderCheck'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
