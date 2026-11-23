---
title: Service Started/Stopped Via Wmic.EXE
summary: Detects usage of wmic to start or stop a service
sigma_id: 0b7163dc-7eee-4960-af17-c0cd517f92da
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1047
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-06-20'
modified: '2023-02-14'
falsepositives:
  - Unknown
references:
  - https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_wmic_service_manipulation.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Service Started/Stopped Via Wmic.EXE
id: 0b7163dc-7eee-4960-af17-c0cd517f92da
status: test
description: Detects usage of wmic to start or stop a service
references:
    - https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-20
modified: 2023-02-14
tags:
    - attack.execution
    - attack.t1047
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - OriginalFileName: 'wmic.exe'
        - Image|endswith: '\WMIC.exe'
    selection_cli:
        CommandLine|contains|all:
            - ' service '
            - ' call '
        CommandLine|contains:
            - 'stopservice'
            - 'startservice'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_wmic_service_manipulation/info.yml
```
