---
title: Renamed MegaSync Execution
summary: Detects the execution of a renamed MegaSync.exe as seen used by ransomware families like Nefilim, Sodinokibi, Pysa, and Conti.
sigma_id: 643bdcac-8b82-49f4-9fd9-25a90b929f3b
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218
author: Sittikorn S
date: '2021-06-22'
modified: '2023-02-03'
falsepositives:
  - Software that illegally integrates MegaSync in a renamed form
  - Administrators that have renamed MegaSync
references:
  - https://redcanary.com/blog/rclone-mega-extortion/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_megasync.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed MegaSync Execution
id: 643bdcac-8b82-49f4-9fd9-25a90b929f3b
status: test
description: Detects the execution of a renamed MegaSync.exe as seen used by ransomware families like Nefilim, Sodinokibi, Pysa, and Conti.
references:
    - https://redcanary.com/blog/rclone-mega-extortion/
author: Sittikorn S
date: 2021-06-22
modified: 2023-02-03
tags:
    - attack.stealth
    - attack.t1218
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        OriginalFileName: 'megasync.exe'
    filter:
        Image|endswith: '\megasync.exe'
    condition: selection and not filter
falsepositives:
    - Software that illegally integrates MegaSync in a renamed form
    - Administrators that have renamed MegaSync
level: high
```
