---
title: Suspicious Control Panel DLL Load
summary: Detects suspicious Rundll32 execution from control.exe as used by Equation Group and Exploit Kits
sigma_id: d7eb979b-c2b5-4a6f-a3a7-c87ce6763819
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218.011
author: Florian Roth (Nextron Systems)
date: '2017-04-15'
modified: '2023-02-09'
falsepositives:
  - Unknown
references:
  - https://twitter.com/rikvduijn/status/853251879320662017
  - https://twitter.com/felixw3000/status/853354851128025088
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_rundll32_susp_control_dll_load.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Control Panel DLL Load
id: d7eb979b-c2b5-4a6f-a3a7-c87ce6763819
status: test
description: Detects suspicious Rundll32 execution from control.exe as used by Equation Group and Exploit Kits
references:
    - https://twitter.com/rikvduijn/status/853251879320662017
    - https://twitter.com/felixw3000/status/853354851128025088
author: Florian Roth (Nextron Systems)
date: 2017-04-15
modified: 2023-02-09
tags:
    - attack.stealth
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\System32\control.exe'
    selection_img:
        - Image|endswith: '\rundll32.exe'
        - OriginalFileName: 'RUNDLL32.EXE'
    filter:
        CommandLine|contains: 'Shell32.dll'
    condition: all of selection_* and not filter
falsepositives:
    - Unknown
level: high
```
