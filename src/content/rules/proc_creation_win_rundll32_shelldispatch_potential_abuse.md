---
title: Potential ShellDispatch.DLL Functionality Abuse
summary: Detects potential "ShellDispatch.dll" functionality abuse to execute arbitrary binaries via "ShellExecute"
sigma_id: 82343930-652f-43f5-ab70-2ee9fdd6d5e9
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques: []
author: X__Junior (Nextron Systems)
date: '2023-06-20'
falsepositives:
  - Unlikely
references:
  - https://www.hexacorn.com/blog/2023/06/07/this-lolbin-doesnt-exist/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_rundll32_shelldispatch_potential_abuse.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential ShellDispatch.DLL Functionality Abuse
id: 82343930-652f-43f5-ab70-2ee9fdd6d5e9
status: test
description: Detects potential "ShellDispatch.dll" functionality abuse to execute arbitrary binaries via "ShellExecute"
references:
    - https://www.hexacorn.com/blog/2023/06/07/this-lolbin-doesnt-exist/
author: X__Junior (Nextron Systems)
date: 2023-06-20
tags:
    - attack.execution
    - attack.stealth
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\rundll32.exe'
        - OriginalFileName: 'RUNDLL32.EXE'
    selection_cli:
        CommandLine|contains: 'RunDll_ShellExecuteW'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: medium
```
