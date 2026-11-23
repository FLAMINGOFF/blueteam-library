---
title: Service StartupType Change Via Sc.EXE
summary: Detect the use of "sc.exe" to change the startup type of a service to "disabled" or "demand"
sigma_id: 85c312b7-f44d-4a51-a024-d671c40b49fc
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0112
techniques:
  - T1685
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-08-01'
modified: '2023-03-04'
falsepositives:
  - False positives may occur with troubleshooting scripts
references:
  - https://www.virustotal.com/gui/file/38283b775552da8981452941ea74191aa0d203edd3f61fb2dee7b0aea3514955
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sc_disable_service.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Service StartupType Change Via Sc.EXE
id: 85c312b7-f44d-4a51-a024-d671c40b49fc
status: test
description: Detect the use of "sc.exe" to change the startup type of a service to "disabled" or "demand"
references:
    - https://www.virustotal.com/gui/file/38283b775552da8981452941ea74191aa0d203edd3f61fb2dee7b0aea3514955
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-01
modified: 2023-03-04
tags:
    - attack.execution
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\sc.exe'
        - OriginalFileName: 'sc.exe'
    selection_cli:
        CommandLine|contains|all:
            - ' config '
            - 'start'
        CommandLine|contains:
            - 'disabled'
            - 'demand'
    condition: all of selection_*
falsepositives:
    - False positives may occur with troubleshooting scripts
level: medium
```
