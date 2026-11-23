---
title: Suspicious Schtasks Schedule Type With High Privileges
summary: Detects scheduled task creations or modification to be run with high privileges on a suspicious schedule type
sigma_id: 7a02e22e-b885-4404-b38b-1ddc7e65258a
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
  - TA0002
techniques:
  - T1053.005
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-08-31'
falsepositives:
  - Some installers were seen using this method of creation unfortunately. Filter them in your environment
references:
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-change
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_schtasks_schedule_type_system.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Schtasks Schedule Type With High Privileges
id: 7a02e22e-b885-4404-b38b-1ddc7e65258a
related:
    - id: 24c8392b-aa3c-46b7-a545-43f71657fe98
      type: similar
status: test
description: Detects scheduled task creations or modification to be run with high privileges on a suspicious schedule type
references:
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-change
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-31
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
    selection_privs:
        CommandLine|contains:
            - 'NT AUT' # This covers the usual NT AUTHORITY\SYSTEM
            - ' SYSTEM' # SYSTEM is a valid value for schtasks hence it gets it's own value with space
            - 'HIGHEST'
    condition: all of selection_*
falsepositives:
    - Some installers were seen using this method of creation unfortunately. Filter them in your environment
level: medium
```
