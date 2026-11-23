---
title: HackTool - SharpMove Tool Execution
summary: Detects the execution of SharpMove, a .NET utility performing multiple tasks such as "Task Creation", "SCM" query, VBScript execution using WMI via its PE metadata and command line options.
sigma_id: 055fb54c-a8f4-4aee-bd44-f74cf30a0d9d
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0008
techniques:
  - T1021.002
author: Luca Di Bartolomeo (CrimpSec)
date: '2024-01-29'
falsepositives:
  - Unknown
references:
  - https://github.com/0xthirteen/SharpMove/
  - https://pentestlab.blog/tag/sharpmove/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_sharpmove.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - SharpMove Tool Execution
id: 055fb54c-a8f4-4aee-bd44-f74cf30a0d9d
status: test
description: |
    Detects the execution of SharpMove, a .NET utility performing multiple tasks such as "Task Creation", "SCM" query, VBScript execution using WMI via its PE metadata and command line options.
references:
    - https://github.com/0xthirteen/SharpMove/
    - https://pentestlab.blog/tag/sharpmove/
author: Luca Di Bartolomeo (CrimpSec)
date: 2024-01-29
tags:
    - attack.lateral-movement
    - attack.t1021.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\SharpMove.exe'
        - OriginalFileName: SharpMove.exe
    selection_cli_computer:
        # In its current implementation the "computername" flag is required in all actions
        CommandLine|contains: 'computername='
    selection_cli_actions:
        CommandLine|contains:
            - 'action=create'
            - 'action=dcom'
            - 'action=executevbs'
            - 'action=hijackdcom'
            - 'action=modschtask'
            - 'action=modsvc'
            - 'action=query'
            - 'action=scm'
            - 'action=startservice'
            - 'action=taskscheduler'
    condition: selection_img or all of selection_cli_*
falsepositives:
    - Unknown
level: high
```
