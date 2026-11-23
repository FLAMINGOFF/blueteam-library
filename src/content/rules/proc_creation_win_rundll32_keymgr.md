---
title: Suspicious Key Manager Access
summary: Detects the invocation of the Stored User Names and Passwords dialogue (Key Manager)
sigma_id: a4694263-59a8-4608-a3a0-6f8d3a51664c
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1555.004
author: Florian Roth (Nextron Systems)
date: '2022-04-21'
modified: '2023-02-09'
falsepositives:
  - Administrative activity
references:
  - https://twitter.com/NinjaParanoid/status/1516442028963659777
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_rundll32_keymgr.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Key Manager Access
id: a4694263-59a8-4608-a3a0-6f8d3a51664c
status: test
description: Detects the invocation of the Stored User Names and Passwords dialogue (Key Manager)
references:
    - https://twitter.com/NinjaParanoid/status/1516442028963659777
author: Florian Roth (Nextron Systems)
date: 2022-04-21
modified: 2023-02-09
tags:
    - attack.credential-access
    - attack.t1555.004
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\rundll32.exe'
        - OriginalFileName: 'RUNDLL32.EXE'
    selection_cli:
        CommandLine|contains|all:
            - 'keymgr'
            - 'KRShowKeyMgr'
    condition: all of selection_*
falsepositives:
    - Administrative activity
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_rundll32_keymgr/info.yml
```
