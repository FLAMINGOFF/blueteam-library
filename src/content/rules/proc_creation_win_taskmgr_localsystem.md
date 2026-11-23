---
title: Taskmgr as LOCAL_SYSTEM
summary: Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM
sigma_id: 9fff585c-c33e-4a86-b3cd-39312079a65f
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1036
author: Florian Roth (Nextron Systems)
date: '2018-03-18'
modified: '2022-05-27'
falsepositives:
  - Unknown
references:
  - Internal Research
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_taskmgr_localsystem.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Taskmgr as LOCAL_SYSTEM
id: 9fff585c-c33e-4a86-b3cd-39312079a65f
status: test
description: Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM
references:
    - Internal Research
author: Florian Roth (Nextron Systems)
date: 2018-03-18
modified: 2022-05-27
tags:
    - attack.stealth
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
        Image|endswith: '\taskmgr.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
