---
title: PowerShell SAM Copy
summary: Detects suspicious PowerShell scripts accessing SAM hives
sigma_id: 1af57a4b-460a-4738-9034-db68b880c665
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1003.002
author: Florian Roth (Nextron Systems)
date: '2021-07-29'
modified: '2023-01-06'
falsepositives:
  - Some rare backup scenarios
  - PowerShell scripts fixing HiveNightmare / SeriousSAM ACLs
references:
  - https://twitter.com/splinter_code/status/1420546784250769408
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_sam_access.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PowerShell SAM Copy
id: 1af57a4b-460a-4738-9034-db68b880c665
status: test
description: Detects suspicious PowerShell scripts accessing SAM hives
references:
    - https://twitter.com/splinter_code/status/1420546784250769408
author: Florian Roth (Nextron Systems)
date: 2021-07-29
modified: 2023-01-06
tags:
    - attack.credential-access
    - attack.t1003.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        CommandLine|contains|all:
            - '\HarddiskVolumeShadowCopy'
            - 'System32\config\sam'
    selection_2:
        CommandLine|contains:
            - 'Copy-Item'
            - 'cp $_.'
            - 'cpi $_.'
            - 'copy $_.'
            - '.File]::Copy('
    condition: all of selection*
falsepositives:
    - Some rare backup scenarios
    - PowerShell scripts fixing HiveNightmare / SeriousSAM ACLs
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_powershell_sam_access/info.yml
```
