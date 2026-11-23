---
title: Suspicious Schtasks Schedule Types
summary: Detects scheduled task creations or modification on a suspicious schedule type
sigma_id: 24c8392b-aa3c-46b7-a545-43f71657fe98
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
  - TA0002
techniques:
  - T1053.005
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-09'
falsepositives:
  - Legitimate processes that run at logon. Filter according to your environment
references:
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-change
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create
  - http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_schtasks_schedule_type.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Schtasks Schedule Types
id: 24c8392b-aa3c-46b7-a545-43f71657fe98
related:
    - id: 7a02e22e-b885-4404-b38b-1ddc7e65258a
      type: similar
status: test
description: Detects scheduled task creations or modification on a suspicious schedule type
references:
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-change
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create
    - http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-09
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.t1053.005
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\schtasks.exe'
        - OriginalFileName: 'schtasks.exe'
    selection_time:
        CommandLine|contains:
            - ' ONLOGON '
            - ' ONSTART '
            - ' ONCE '
            - ' ONIDLE '
    filter_privs:
        CommandLine|contains:
            - 'NT AUT' # This covers the usual NT AUTHORITY\SYSTEM
            - ' SYSTEM' # SYSTEM is a valid value for schtasks hence it gets it's own value with space
            - 'HIGHEST'
    condition: all of selection_* and not 1 of filter_*
falsepositives:
    - Legitimate processes that run at logon. Filter according to your environment
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_schtasks_schedule_type/info.yml
```
