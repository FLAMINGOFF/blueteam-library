---
title: Suspicious Workstation Locking via Rundll32
summary: Detects a suspicious call to the user32.dll function that locks the user workstation
sigma_id: 3b5b0213-0460-4e3f-8937-3abf98ff7dcc
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques: []
author: frack113
date: '2022-06-04'
modified: '2023-02-09'
falsepositives:
  - Scripts or links on the user desktop used to lock the workstation instead of Windows+L or the menu option
references:
  - https://app.any.run/tasks/2aef9c63-f944-4763-b3ef-81eee209d128/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_rundll32_user32_dll.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Workstation Locking via Rundll32
id: 3b5b0213-0460-4e3f-8937-3abf98ff7dcc
status: test
description: Detects a suspicious call to the user32.dll function that locks the user workstation
references:
    - https://app.any.run/tasks/2aef9c63-f944-4763-b3ef-81eee209d128/
author: frack113
date: 2022-06-04
modified: 2023-02-09
tags:
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection_call_img:
        - Image|endswith: '\rundll32.exe'
        - OriginalFileName: 'RUNDLL32.EXE'
    selection_call_parent:
        ParentImage|endswith: '\cmd.exe'
    selection_call_cli:
        CommandLine|contains: 'user32.dll,'
    selection_function:
        CommandLine|contains: 'LockWorkStation'
    condition: all of selection_*
falsepositives:
    - Scripts or links on the user desktop used to lock the workstation instead of Windows+L or the menu option
level: medium
```
