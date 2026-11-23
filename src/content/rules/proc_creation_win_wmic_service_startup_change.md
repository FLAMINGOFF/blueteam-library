---
title: Service Startup Type Change Via Wmic.EXE
summary: Detects changes to service startup type to 'disabled' or 'manual' using the WMIC command-line utility.
sigma_id: c0514f28-fdae-42df-b886-06e2b2bc5b37
status: experimental
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0112
techniques:
  - T1047
  - T1685
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: '2026-04-27'
falsepositives:
  - Legitimate administrative changes to service startup types using WMIC, investigate accordingly.
references:
  - https://blog.talosintelligence.com/uncovering-qilin-attack-methods-exposed-through-multiple-cases/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_wmic_service_startup_change.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Service Startup Type Change Via Wmic.EXE
id: c0514f28-fdae-42df-b886-06e2b2bc5b37
status: experimental
description: |
    Detects changes to service startup type to 'disabled' or 'manual' using the WMIC command-line utility.
references:
    - https://blog.talosintelligence.com/uncovering-qilin-attack-methods-exposed-through-multiple-cases/
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2026-04-27
tags:
    - attack.execution
    - attack.defense-impairment
    - attack.t1047
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\WMIC.exe'
        - OriginalFileName: 'wmic.exe'
    selection_cli:
        CommandLine|contains|all:
            - ' service '
            - 'ChangeStartMode'
        CommandLine|contains:
            - 'Manual'
            - 'Disabled'
    condition: all of selection_*
falsepositives:
    - Legitimate administrative changes to service startup types using WMIC, investigate accordingly.
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_wmic_service_startup_change/info.yml
```
