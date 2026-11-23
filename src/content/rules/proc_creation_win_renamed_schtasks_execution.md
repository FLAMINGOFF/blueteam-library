---
title: Renamed Schtasks Execution
summary: |-
  Detects the execution of renamed schtasks.exe binary, which is a legitimate Windows utility used for scheduling tasks.
  One of the very common persistence techniques is schedule malicious tasks using schtasks.exe.
  Since, it is heavily abused, it is also heavily monitored by security products. To evade detection, threat actors may rename the schtasks.exe binary to schedule their malicious tasks.
sigma_id: f91e51c9-f344-4b32-969b-0b6f6b8537d4
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0003
  - TA0004
techniques:
  - T1036.003
  - T1053.005
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: '2025-11-27'
modified: '2026-10-02'
falsepositives:
  - Unlikely
references:
  - https://x.com/JangPr0/status/1932034543026065833
  - https://ss64.com/nt/schtasks.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_schtasks_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed Schtasks Execution
id: f91e51c9-f344-4b32-969b-0b6f6b8537d4
status: experimental
description: |
    Detects the execution of renamed schtasks.exe binary, which is a legitimate Windows utility used for scheduling tasks.
    One of the very common persistence techniques is schedule malicious tasks using schtasks.exe.
    Since, it is heavily abused, it is also heavily monitored by security products. To evade detection, threat actors may rename the schtasks.exe binary to schedule their malicious tasks.
references:
    - https://x.com/JangPr0/status/1932034543026065833
    - https://ss64.com/nt/schtasks.html
author: Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-11-27
modified: 2026-10-02
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1036.003
    - attack.t1053.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd_operation:
        CommandLine|contains|windash:
            - ' /create '
            - ' /delete '
            - ' /query '
            - ' /change '
            - ' /run '
            - ' /end '
    selection_cmd_flags:
        CommandLine|contains|windash:
            - ' /tn '
            - ' /tr '
            - ' /sc '
            - ' /st '
            - ' /ru '
            - ' /fo '
    selection_pe:
        OriginalFileName: 'schtasks.exe'
    filter_main_cmd:
        CommandLine|contains: 'schtasks'
    filter_main_img:
        Image|endswith: '\schtasks.exe'
    filter_optional_cmd_openfiles:
        CommandLine|contains|all:
            - 'openfiles'
            - ' /query '
            - ' /fo'
    condition: (all of selection_cmd_* and not filter_main_cmd and not filter_optional_cmd_openfiles) or (selection_pe and not filter_main_img)
falsepositives:
    - Unlikely
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_renamed_schtasks_execution/info.yml
```
