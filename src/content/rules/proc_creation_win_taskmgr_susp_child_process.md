---
title: New Process Created Via Taskmgr.EXE
summary: Detects the creation of a process via the Windows task manager. This might be an attempt to bypass UAC
sigma_id: 3d7679bd-0c00-440c-97b0-3f204273e6c7
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1036
author: Florian Roth (Nextron Systems)
date: '2018-03-13'
modified: '2024-01-18'
falsepositives:
  - Administrative activity
references:
  - https://twitter.com/ReneFreingruber/status/1172244989335810049
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_taskmgr_susp_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: New Process Created Via Taskmgr.EXE
id: 3d7679bd-0c00-440c-97b0-3f204273e6c7
status: test
description: Detects the creation of a process via the Windows task manager. This might be an attempt to bypass UAC
references:
    - https://twitter.com/ReneFreingruber/status/1172244989335810049
author: Florian Roth (Nextron Systems)
date: 2018-03-13
modified: 2024-01-18
tags:
    - attack.stealth
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\taskmgr.exe'
    filter_main_generic:
        Image|endswith:
            - ':\Windows\System32\mmc.exe'
            - ':\Windows\System32\resmon.exe'
            - ':\Windows\System32\Taskmgr.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Administrative activity
level: low
```
