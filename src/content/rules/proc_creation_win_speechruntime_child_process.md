---
title: Suspicious Speech Runtime Binary Child Process
summary: |-
  Detects suspicious Speech Runtime Binary Execution by monitoring its child processes.
  Child processes spawned by SpeechRuntime.exe could indicate an attempt for lateral movement via COM & DCOM hijacking.
sigma_id: 78f10490-f2f4-4d19-a75b-4e0683bf3b8d
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0008
  - TA0005
techniques:
  - T1021.003
  - T1218
author: andrewdanis
date: '2025-10-23'
falsepositives:
  - Unlikely.
references:
  - https://github.com/rtecCyberSec/SpeechRuntimeMove
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_speechruntime_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Speech Runtime Binary Child Process
id: 78f10490-f2f4-4d19-a75b-4e0683bf3b8d
status: experimental
description: |
    Detects suspicious Speech Runtime Binary Execution by monitoring its child processes.
    Child processes spawned by SpeechRuntime.exe could indicate an attempt for lateral movement via COM & DCOM hijacking.
references:
    - https://github.com/rtecCyberSec/SpeechRuntimeMove
author: andrewdanis
date: 2025-10-23
logsource:
    category: process_creation
    product: windows
tags:
    - attack.lateral-movement
    - attack.stealth
    - attack.t1021.003
    - attack.t1218
detection:
    selection:
        ParentImage|endswith: '\SpeechRuntime.exe'
    condition: selection
falsepositives:
    - Unlikely.
level: high
```
