---
title: Uncommon Child Process Spawned From XBootMgrSleep.EXE
summary: |-
  Detects a process other than XBootMgr.exe spawned by XBootMgrSleep.exe.
  XBootMgrSleep.exe is a Microsoft-signed Windows Performance Toolkit binary that can execute an arbitrary executable after a delay.
sigma_id: 74697c29-1b30-4e1f-a517-33574061821d
status: experimental
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1202
author: Diablo Research
date: '2026-09-27'
falsepositives:
  - Custom Windows Performance Toolkit automation that intentionally launches another executable through XBootMgrSleep.exe
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/XBootMgrSleep/
  - https://learn.microsoft.com/en-us/previous-versions/windows/desktop/xperf/reference
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_xbootmgrsleep_uncommon_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Uncommon Child Process Spawned From XBootMgrSleep.EXE
id: 74697c29-1b30-4e1f-a517-33574061821d
status: experimental
description: |
    Detects a process other than XBootMgr.exe spawned by XBootMgrSleep.exe.
    XBootMgrSleep.exe is a Microsoft-signed Windows Performance Toolkit binary that can execute an arbitrary executable after a delay.
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/XBootMgrSleep/
    - https://learn.microsoft.com/en-us/previous-versions/windows/desktop/xperf/reference
author: Diablo Research
date: 2026-09-27
tags:
    - attack.stealth
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\xbootmgrsleep.exe'
    filter_main_xbootmgr:
        Image: 'C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\xbootmgr.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Custom Windows Performance Toolkit automation that intentionally launches another executable through XBootMgrSleep.exe
level: medium
```
