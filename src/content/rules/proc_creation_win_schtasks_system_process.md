---
title: Scheduled Task Creation Masquerading as System Processes
summary: Detects the creation of scheduled tasks that involve system processes, which may indicate malicious actors masquerading as or abusing these processes to execute payloads or maintain persistence.
sigma_id: 9f8573c9-22b4-40e3-89c1-72bc2b8d49ab
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0002
  - TA0003
techniques:
  - T1053.005
  - T1036.004
  - T1036.005
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: '2025-02-05'
falsepositives:
  - Legitimate system administration tasks scheduling trusted system processes.
references:
  - https://tria.ge/241015-l98snsyeje/behavioral2
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_schtasks_system_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Scheduled Task Creation Masquerading as System Processes
id: 9f8573c9-22b4-40e3-89c1-72bc2b8d49ab
status: experimental
description: Detects the creation of scheduled tasks that involve system processes, which may indicate malicious actors masquerading as or abusing these processes to execute payloads or maintain persistence.
references:
    - https://tria.ge/241015-l98snsyeje/behavioral2
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-02-05
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.stealth
    - attack.t1053.005
    - attack.t1036.004
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\schtasks.exe'
        - OriginalFileName: 'schtasks.exe'
    selection_cli:
        CommandLine|contains|windash: ' /create '
        CommandLine|contains:
            - ' audiodg'
            - ' conhost'
            - ' dwm.exe'
            - ' explorer'
            - ' lsass'
            - ' lsm'
            - ' mmc'
            - ' msiexec'
            - ' regsvr32'
            - ' rundll32'
            - ' services'
            - ' spoolsv'
            - ' svchost'
            - ' taskeng'
            - ' taskhost'
            - ' wininit'
            - ' winlogon'
    condition: all of selection_*
falsepositives:
    - Legitimate system administration tasks scheduling trusted system processes.
level: high
```
