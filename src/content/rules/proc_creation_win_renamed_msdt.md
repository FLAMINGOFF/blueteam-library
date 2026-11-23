---
title: Renamed Msdt.EXE Execution
summary: Detects the execution of a renamed "Msdt.exe" binary
sigma_id: bd1c6866-65fc-44b2-be51-5588fcff82b9
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1036.003
author: pH-T (Nextron Systems)
date: '2022-06-03'
modified: '2023-02-03'
falsepositives:
  - Unlikely
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Msdt/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_msdt.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed Msdt.EXE Execution
id: bd1c6866-65fc-44b2-be51-5588fcff82b9
status: test
description: Detects the execution of a renamed "Msdt.exe" binary
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Msdt/
author: pH-T (Nextron Systems)
date: 2022-06-03
modified: 2023-02-03
tags:
    - attack.stealth
    - attack.t1036.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'msdt.exe'
    filter:
        Image|endswith: '\msdt.exe'
    condition: selection and not filter
falsepositives:
    - Unlikely
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_renamed_msdt/info.yml
```
