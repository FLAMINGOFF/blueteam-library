---
title: Potential Persistence Via Microsoft Compatibility Appraiser
summary: |-
  Detects manual execution of the "Microsoft Compatibility Appraiser" task via schtasks.
  In order to trigger persistence stored in the "\AppCompatFlags\TelemetryController" registry key.
sigma_id: f548a603-c9f2-4c89-b511-b089f7e94549
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0002
  - TA0003
techniques:
  - T1053.005
author: Sreeman
date: '2020-09-29'
modified: '2023-02-10'
falsepositives:
  - Unknown
references:
  - https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_schtasks_persistence_windows_telemetry.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Persistence Via Microsoft Compatibility Appraiser
id: f548a603-c9f2-4c89-b511-b089f7e94549
related:
    - id: 73a883d0-0348-4be4-a8d8-51031c2564f8
      type: derived
status: test
description: |
    Detects manual execution of the "Microsoft Compatibility Appraiser" task via schtasks.
    In order to trigger persistence stored in the "\AppCompatFlags\TelemetryController" registry key.
references:
    - https://www.trustedsec.com/blog/abusing-windows-telemetry-for-persistence/
author: Sreeman
date: 2020-09-29
modified: 2023-02-10
tags:
    - attack.privilege-escalation
    - attack.execution
    - attack.persistence
    - attack.t1053.005
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\schtasks.exe'
        - OriginalFileName: 'schtasks.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'run '
            - '\Application Experience\Microsoft Compatibility Appraiser'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
