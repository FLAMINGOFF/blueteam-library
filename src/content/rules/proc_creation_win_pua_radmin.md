---
title: PUA - Radmin Viewer Utility Execution
summary: Detects the execution of Radmin which can be abused by an adversary to remotely control Windows machines
sigma_id: 5817e76f-4804-41e6-8f1d-5fa0b3ecae2d
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0008
techniques:
  - T1072
author: frack113
date: '2022-01-22'
modified: '2023-12-11'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1072/T1072.md
  - https://www.radmin.fr/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_pua_radmin.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PUA - Radmin Viewer Utility Execution
id: 5817e76f-4804-41e6-8f1d-5fa0b3ecae2d
status: test
description: Detects the execution of Radmin which can be abused by an adversary to remotely control Windows machines
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1072/T1072.md
    - https://www.radmin.fr/
author: frack113
date: 2022-01-22
modified: 2023-12-11
tags:
    - attack.execution
    - attack.lateral-movement
    - attack.t1072
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Description: 'Radmin Viewer'
        - Product: 'Radmin Viewer'
        - OriginalFileName: 'Radmin.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
