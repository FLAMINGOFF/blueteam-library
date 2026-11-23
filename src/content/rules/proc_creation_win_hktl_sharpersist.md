---
title: HackTool - SharPersist Execution
summary: Detects the execution of the hacktool SharPersist - used to deploy various different kinds of persistence mechanisms
sigma_id: 26488ad0-f9fd-4536-876f-52fea846a2e4
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0002
  - TA0003
techniques:
  - T1053
author: Florian Roth (Nextron Systems)
date: '2022-09-15'
modified: '2023-02-04'
falsepositives:
  - Unknown
references:
  - https://www.mandiant.com/resources/blog/sharpersist-windows-persistence-toolkit
  - https://github.com/mandiant/SharPersist
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_sharpersist.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - SharPersist Execution
id: 26488ad0-f9fd-4536-876f-52fea846a2e4
status: test
description: Detects the execution of the hacktool SharPersist - used to deploy various different kinds of persistence mechanisms
references:
    - https://www.mandiant.com/resources/blog/sharpersist-windows-persistence-toolkit
    - https://github.com/mandiant/SharPersist
author: Florian Roth (Nextron Systems)
date: 2022-09-15
modified: 2023-02-04
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.t1053
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\SharPersist.exe'
        - Product: 'SharPersist'
    selection_cli_1:
        CommandLine|contains:
            - ' -t schtask -c '
            - ' -t startupfolder -c '
    selection_cli_2:
        CommandLine|contains|all:
            - ' -t reg -c '
            - ' -m add'
    selection_cli_3:
        CommandLine|contains|all:
            - ' -t service -c '
            - ' -m add'
    selection_cli_4:
        CommandLine|contains|all:
            - ' -t schtask -c '
            - ' -m add'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high
```
