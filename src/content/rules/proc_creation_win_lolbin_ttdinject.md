---
title: Use of TTDInject.exe
summary: Detects the executiob of TTDInject.exe, which is used by Windows 10 v1809 and newer to debug time travel (underlying call of tttracer.exe)
sigma_id: b27077d6-23e6-45d2-81a0-e2b356eea5fd
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1127
author: frack113
date: '2022-05-16'
falsepositives:
  - Legitimate use
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Ttdinject/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_ttdinject.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Use of TTDInject.exe
id: b27077d6-23e6-45d2-81a0-e2b356eea5fd
status: test
description: Detects the executiob of TTDInject.exe, which is used by Windows 10 v1809 and newer to debug time travel (underlying call of tttracer.exe)
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Ttdinject/
author: frack113
date: 2022-05-16
tags:
    - attack.execution
    - attack.stealth
    - attack.t1127
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        - Image|endswith: 'ttdinject.exe'
        - OriginalFileName: 'TTDInject.EXE'
    condition: selection
falsepositives:
    - Legitimate use
level: medium
```
