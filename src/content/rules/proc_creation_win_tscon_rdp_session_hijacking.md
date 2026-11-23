---
title: Potential RDP Session Hijacking Activity
summary: Detects potential RDP Session Hijacking activity on Windows systems
sigma_id: 224f140f-3553-4cd1-af78-13d81bf9f7cc
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: '@juju4'
date: '2022-12-27'
modified: '2024-12-01'
falsepositives:
  - Administrative activity
references:
  - https://twitter.com/Moti_B/status/909449115477659651
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_tscon_rdp_session_hijacking.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential RDP Session Hijacking Activity
id: 224f140f-3553-4cd1-af78-13d81bf9f7cc
status: test
description: Detects potential RDP Session Hijacking activity on Windows systems
references:
    - https://twitter.com/Moti_B/status/909449115477659651
author: '@juju4'
date: 2022-12-27
modified: 2024-12-01
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\tscon.exe'
        - OriginalFileName: 'tscon.exe'
    selection_integrity:
        IntegrityLevel:
            - 'System'
            - 'S-1-16-16384'
    condition: all of selection_*
falsepositives:
    - Administrative activity
level: medium
```
