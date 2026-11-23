---
title: Suspicious Windows Trace ETW Session Tamper Via Logman.EXE
summary: Detects the execution of "logman" utility in order to disable or delete Windows trace sessions
sigma_id: cd1f961e-0b96-436b-b7c6-38da4583ec00
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1685
  - T1685.005
author: Florian Roth (Nextron Systems)
date: '2021-02-11'
modified: '2023-02-21'
falsepositives:
  - Legitimate deactivation by administrative staff
  - Installer tools that disable services, e.g. before log collection agent installation
references:
  - https://twitter.com/0gtweet/status/1359039665232306183?s=21
  - https://ss64.com/nt/logman.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_logman_disable_eventlog.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Windows Trace ETW Session Tamper Via Logman.EXE
id: cd1f961e-0b96-436b-b7c6-38da4583ec00
status: test
description: Detects the execution of "logman" utility in order to disable or delete Windows trace sessions
references:
    - https://twitter.com/0gtweet/status/1359039665232306183?s=21
    - https://ss64.com/nt/logman.html
author: Florian Roth (Nextron Systems)
date: 2021-02-11
modified: 2023-02-21
tags:
    - attack.defense-impairment
    - attack.t1685
    - attack.t1685.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\logman.exe'
        - OriginalFileName: 'Logman.exe'
    selection_action:
        CommandLine|contains:
            - 'stop '
            - 'delete '
    selection_service:
        CommandLine|contains:
            - 'Circular Kernel Context Logger'
            - 'EventLog-' # Cover multiple traces starting with EventLog-*
            - 'SYSMON TRACE'
            - 'SysmonDnsEtwSession'
    condition: all of selection*
falsepositives:
    - Legitimate deactivation by administrative staff
    - Installer tools that disable services, e.g. before log collection agent installation
level: high
```
