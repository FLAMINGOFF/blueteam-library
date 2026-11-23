---
title: PUA - Crassus Execution
summary: Detects Crassus, a Windows privilege escalation discovery tool, based on PE metadata characteristics.
sigma_id: 2c32b543-1058-4808-91c6-5b31b8bed6c5
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
  - TA0043
techniques:
  - T1590.001
author: pH-T (Nextron Systems)
date: '2023-04-17'
falsepositives:
  - Unlikely
references:
  - https://github.com/vu-ls/Crassus
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_pua_crassus.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PUA - Crassus Execution
id: 2c32b543-1058-4808-91c6-5b31b8bed6c5
status: test
description: Detects Crassus, a Windows privilege escalation discovery tool, based on PE metadata characteristics.
references:
    - https://github.com/vu-ls/Crassus
author: pH-T (Nextron Systems)
date: 2023-04-17
tags:
    - attack.discovery
    - attack.reconnaissance
    - attack.t1590.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\Crassus.exe'
        - OriginalFileName: 'Crassus.exe'
        - Description|contains: 'Crassus'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
