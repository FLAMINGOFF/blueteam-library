---
title: Code Execution via Pcwutl.dll
summary: Detects launch of executable by calling the LaunchApplication function from pcwutl.dll library.
sigma_id: 9386d78a-7207-4048-9c9f-a93a7c2d1c05
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218.011
author: Julia Fomina, oscd.community
date: '2020-10-05'
modified: '2023-02-09'
falsepositives:
  - Use of Program Compatibility Troubleshooter Helper
references:
  - https://lolbas-project.github.io/lolbas/Libraries/Pcwutl/
  - https://twitter.com/harr0ey/status/989617817849876488
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_pcwutl.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Code Execution via Pcwutl.dll
id: 9386d78a-7207-4048-9c9f-a93a7c2d1c05
status: test
description: Detects launch of executable by calling the LaunchApplication function from pcwutl.dll library.
references:
    - https://lolbas-project.github.io/lolbas/Libraries/Pcwutl/
    - https://twitter.com/harr0ey/status/989617817849876488
author: Julia Fomina, oscd.community
date: 2020-10-05
modified: 2023-02-09
tags:
    - attack.stealth
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\rundll32.exe'
        - OriginalFileName: 'RUNDLL32.EXE'
    selection_cli:
        CommandLine|contains|all:
            - 'pcwutl'
            - 'LaunchApplication'
    condition: all of selection_*
falsepositives:
    - Use of Program Compatibility Troubleshooter Helper
level: medium
```
