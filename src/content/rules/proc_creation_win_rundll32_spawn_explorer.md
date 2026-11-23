---
title: RunDLL32 Spawning Explorer
summary: Detects RunDLL32.exe spawning explorer.exe as child, which is very uncommon, often observes Gamarue spawning the explorer.exe process in an unusual way
sigma_id: caa06de8-fdef-4c91-826a-7f9e163eef4b
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218.011
author: elhoim, CD_ROM_
date: '2022-04-27'
modified: '2022-05-25'
falsepositives:
  - Unknown
references:
  - https://redcanary.com/blog/intelligence-insights-november-2021/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_rundll32_spawn_explorer.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: RunDLL32 Spawning Explorer
id: caa06de8-fdef-4c91-826a-7f9e163eef4b
status: test
description: Detects RunDLL32.exe spawning explorer.exe as child, which is very uncommon, often observes Gamarue spawning the explorer.exe process in an unusual way
references:
    - https://redcanary.com/blog/intelligence-insights-november-2021/
author: elhoim, CD_ROM_
date: 2022-04-27
modified: 2022-05-25
tags:
    - attack.stealth
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\rundll32.exe'
        Image|endswith: '\explorer.exe'
    filter:
        ParentCommandLine|contains: '\shell32.dll,Control_RunDLL'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
