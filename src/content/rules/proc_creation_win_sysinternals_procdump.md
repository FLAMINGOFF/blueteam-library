---
title: Procdump Execution
summary: Detects usage of the SysInternals Procdump utility
sigma_id: 2e65275c-8288-4ab4-aeb7-6274f58b6b20
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1036
  - T1003.001
author: Florian Roth (Nextron Systems)
date: '2021-08-16'
modified: '2026-06-29'
falsepositives:
  - Legitimate use of procdump by a developer or administrator
references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sysinternals_procdump.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Procdump Execution
id: 2e65275c-8288-4ab4-aeb7-6274f58b6b20
status: test
description: Detects usage of the SysInternals Procdump utility
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/procdump
author: Florian Roth (Nextron Systems)
date: 2021-08-16
modified: 2026-06-29
tags:
    - attack.stealth
    - attack.t1036
    - attack.t1003.001
    - attack.credential-access
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\procdump.exe'
            - '\procdump64.exe'
            - '\procdump64a.exe'
    condition: selection
falsepositives:
    - Legitimate use of procdump by a developer or administrator
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_sysinternals_procdump/info.yml
```
