---
title: HackTool - SILENTTRINITY Stager Execution
summary: Detects SILENTTRINITY stager use via PE metadata
sigma_id: 03552375-cc2c-4883-bbe4-7958d5a980be
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1071
author: Aleksey Potapov, oscd.community
date: '2019-10-22'
modified: '2023-02-13'
falsepositives:
  - Unlikely
references:
  - https://github.com/byt3bl33d3r/SILENTTRINITY
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_silenttrinity_stager.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - SILENTTRINITY Stager Execution
id: 03552375-cc2c-4883-bbe4-7958d5a980be
related:
    - id: 75c505b1-711d-4f68-a357-8c3fe37dbf2d # DLL Load
      type: derived
status: test
description: Detects SILENTTRINITY stager use via PE metadata
references:
    - https://github.com/byt3bl33d3r/SILENTTRINITY
author: Aleksey Potapov, oscd.community
date: 2019-10-22
modified: 2023-02-13
tags:
    - attack.command-and-control
    - attack.t1071
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Description|contains: 'st2stager'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
