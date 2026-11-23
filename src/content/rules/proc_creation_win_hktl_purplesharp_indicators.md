---
title: HackTool - PurpleSharp Execution
summary: Detects the execution of the PurpleSharp adversary simulation tool
sigma_id: ff23ffbc-3378-435e-992f-0624dcf93ab4
status: test
level: critical
platform: windows
logsource: windows / process_creation
tactics:
  - TA0042
techniques:
  - T1587
author: Florian Roth (Nextron Systems)
date: '2021-06-18'
modified: '2023-02-05'
falsepositives:
  - Unlikely
references:
  - https://github.com/mvelazc0/PurpleSharp
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_purplesharp_indicators.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - PurpleSharp Execution
id: ff23ffbc-3378-435e-992f-0624dcf93ab4
status: test
description: Detects the execution of the PurpleSharp adversary simulation tool
references:
    - https://github.com/mvelazc0/PurpleSharp
author: Florian Roth (Nextron Systems)
date: 2021-06-18
modified: 2023-02-05
tags:
    - attack.t1587
    - attack.resource-development
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|contains: '\purplesharp'
        - OriginalFileName: 'PurpleSharp.exe'
    selection_cli:
        CommandLine|contains:
            - 'xyz123456.exe'
            - 'PurpleSharp'
    condition: 1 of selection_*
falsepositives:
    - Unlikely
level: critical
```
