---
title: LSASS Process Reconnaissance Via Findstr.EXE
summary: Detects findstring commands that include the keyword lsass, which indicates recon actviity for the LSASS process PID
sigma_id: fe63010f-8823-4864-a96b-a7b4a0f7b929
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1552.006
author: Florian Roth (Nextron Systems)
date: '2022-08-12'
modified: '2024-06-04'
falsepositives:
  - Unknown
references:
  - https://blog.talosintelligence.com/recent-cyber-attack/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_findstr_lsass.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: LSASS Process Reconnaissance Via Findstr.EXE
id: fe63010f-8823-4864-a96b-a7b4a0f7b929
status: test
description: Detects findstring commands that include the keyword lsass, which indicates recon actviity for the LSASS process PID
references:
    - https://blog.talosintelligence.com/recent-cyber-attack/
author: Florian Roth (Nextron Systems)
date: 2022-08-12
modified: 2024-06-04
tags:
    - attack.credential-access
    - attack.t1552.006
logsource:
    category: process_creation
    product: windows
detection:
    selection_findstr_img:
        - Image|endswith:
              - '\find.exe'
              - '\findstr.exe'
        - OriginalFileName:
              - 'FIND.EXE'
              - 'FINDSTR.EXE'
    selection_findstr_cli:
        CommandLine|contains: 'lsass'
    selection_special:
        CommandLine|contains|windash:
            - ' /i "lsass'
            - ' /i lsass.exe'
            - 'findstr "lsass'
            - 'findstr lsass'
            - 'findstr.exe "lsass'
            - 'findstr.exe lsass'
    condition: all of selection_findstr_* or selection_special
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_findstr_lsass/info.yml
```
