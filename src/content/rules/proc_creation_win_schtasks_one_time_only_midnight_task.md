---
title: Uncommon One Time Only Scheduled Task At 00:00
summary: Detects scheduled task creation events that include suspicious actions, and is run once at 00:00
sigma_id: 970823b7-273b-460a-8afc-3a6811998529
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0003
  - TA0004
techniques:
  - T1053.005
author: pH-T (Nextron Systems)
date: '2022-07-15'
modified: '2023-02-03'
falsepositives:
  - Software installation
references:
  - https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-blackbyte
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_schtasks_one_time_only_midnight_task.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Uncommon One Time Only Scheduled Task At 00:00
id: 970823b7-273b-460a-8afc-3a6811998529
status: test
description: Detects scheduled task creation events that include suspicious actions, and is run once at 00:00
references:
    - https://www.trendmicro.com/vinfo/us/security/news/ransomware-spotlight/ransomware-spotlight-blackbyte
author: pH-T (Nextron Systems)
date: 2022-07-15
modified: 2023-02-03
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege-escalation
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|contains: '\schtasks.exe'
        - OriginalFileName: 'schtasks.exe'
    selection_cli:
        CommandLine|contains:
            - 'wscript'
            - 'vbscript'
            - 'cscript'
            - 'wmic '
            - 'wmic.exe'
            - 'regsvr32.exe'
            - 'powershell'
            - '\AppData\'
    selection_time:
        CommandLine|contains|all:
            - 'once'
            - '00:00'
    condition: all of selection_*
falsepositives:
    - Software installation
level: high
```
