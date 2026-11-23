---
title: File Download And Execution Via IEExec.EXE
summary: Detects execution of the IEExec utility to download and execute files
sigma_id: 9801abb8-e297-4dbf-9fbd-57dde0e830ad
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1105
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-05-16'
modified: '2023-11-09'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Ieexec/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_ieexec_download.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: File Download And Execution Via IEExec.EXE
id: 9801abb8-e297-4dbf-9fbd-57dde0e830ad
status: test
description: Detects execution of the IEExec utility to download and execute files
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Ieexec/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-05-16
modified: 2023-11-09
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\IEExec.exe'
        - OriginalFileName: 'IEExec.exe'
    selection_cli:
        CommandLine|contains:
            - 'http://'
            - 'https://'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
