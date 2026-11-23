---
title: PowerShell Get-Process LSASS
summary: Detects a "Get-Process" cmdlet and it's aliases on lsass process, which is in almost all cases a sign of malicious activity
sigma_id: b2815d0d-7481-4bf0-9b6c-a4c48a94b349
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1552.004
author: Florian Roth (Nextron Systems)
date: '2021-04-23'
modified: '2023-01-05'
falsepositives:
  - Unknown
references:
  - https://web.archive.org/web/20220205033028/https://twitter.com/PythonResponder/status/1385064506049630211
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_getprocess_lsass.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PowerShell Get-Process LSASS
id: b2815d0d-7481-4bf0-9b6c-a4c48a94b349
status: test
description: Detects a "Get-Process" cmdlet and it's aliases on lsass process, which is in almost all cases a sign of malicious activity
references:
    - https://web.archive.org/web/20220205033028/https://twitter.com/PythonResponder/status/1385064506049630211
author: Florian Roth (Nextron Systems)
date: 2021-04-23
modified: 2023-01-05
tags:
    - attack.credential-access
    - attack.t1552.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            # You can add more permutation as you see fit
            - 'Get-Process lsas'
            - 'ps lsas'
            - 'gps lsas'
    condition: selection
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_powershell_getprocess_lsass/info.yml
```
