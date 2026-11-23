---
title: Delete All Scheduled Tasks
summary: Detects the usage of schtasks with the delete flag and the asterisk symbol to delete all tasks from the schedule of the local computer, including tasks scheduled by other users.
sigma_id: 220457c1-1c9f-4c2e-afe6-9598926222c1
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0040
techniques:
  - T1489
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-09'
falsepositives:
  - Unlikely
references:
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-delete
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_schtasks_delete_all.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Delete All Scheduled Tasks
id: 220457c1-1c9f-4c2e-afe6-9598926222c1
status: test
description: Detects the usage of schtasks with the delete flag and the asterisk symbol to delete all tasks from the schedule of the local computer, including tasks scheduled by other users.
references:
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-delete
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-09
tags:
    - attack.impact
    - attack.t1489
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all:
            - ' /delete '
            - '/tn \*'
            - ' /f'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
