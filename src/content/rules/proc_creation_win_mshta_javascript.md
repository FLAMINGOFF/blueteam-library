---
title: Suspicious JavaScript Execution Via Mshta.EXE
summary: Detects execution of javascript code using "mshta.exe".
sigma_id: 67f113fa-e23d-4271-befa-30113b3e08b1
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218.005
author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
date: '2019-10-24'
modified: '2023-02-07'
falsepositives:
  - Unknown
references:
  - https://eqllib.readthedocs.io/en/latest/analytics/6bc283c4-21f2-4aed-a05c-a9a3ffa95dd4.html
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.005/T1218.005.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_mshta_javascript.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious JavaScript Execution Via Mshta.EXE
id: 67f113fa-e23d-4271-befa-30113b3e08b1
status: test
description: Detects execution of javascript code using "mshta.exe".
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/6bc283c4-21f2-4aed-a05c-a9a3ffa95dd4.html
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1218.005/T1218.005.md
author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
date: 2019-10-24
modified: 2023-02-07
tags:
    - attack.stealth
    - attack.t1218.005
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\mshta.exe'
        - OriginalFileName: 'MSHTA.EXE'
    selection_cli:
        CommandLine|contains: 'javascript'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_mshta_javascript/info.yml
```
