---
title: CobaltStrike Load by Rundll32
summary: Rundll32 can be use by Cobalt Strike with StartW function to load DLLs from the command line.
sigma_id: ae9c6a7c-9521-42a6-915e-5aaa8689d529
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218.011
author: Wojciech Lesicki
date: '2021-06-01'
modified: '2022-09-16'
falsepositives:
  - Unknown
references:
  - https://www.cobaltstrike.com/help-windows-executable
  - https://redcanary.com/threat-detection-report/
  - https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_cobaltstrike_load_by_rundll32.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: CobaltStrike Load by Rundll32
id: ae9c6a7c-9521-42a6-915e-5aaa8689d529
status: test
description: Rundll32 can be use by Cobalt Strike with StartW function to load DLLs from the command line.
references:
    - https://www.cobaltstrike.com/help-windows-executable
    - https://redcanary.com/threat-detection-report/
    - https://thedfirreport.com/2020/10/18/ryuk-in-5-hours/
author: Wojciech Lesicki
date: 2021-06-01
modified: 2022-09-16
tags:
    - attack.stealth
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_rundll:
        - Image|endswith: '\rundll32.exe'
        - OriginalFileName: RUNDLL32.EXE
        - CommandLine|contains:
              - 'rundll32.exe'
              - 'rundll32 '
    selection_params:
        CommandLine|contains: '.dll'
        CommandLine|endswith:
            - ' StartW'
            - ',StartW'
    condition: all of selection*
falsepositives:
    - Unknown
level: high
```
