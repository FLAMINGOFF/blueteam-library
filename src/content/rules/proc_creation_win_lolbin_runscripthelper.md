---
title: Suspicious Runscripthelper.exe
summary: Detects execution of powershell scripts via Runscripthelper.exe
sigma_id: eca49c87-8a75-4f13-9c73-a5a29e845f03
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059
  - T1202
author: Victor Sergeev, oscd.community
date: '2020-10-09'
modified: '2022-07-11'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Runscripthelper/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_runscripthelper.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Runscripthelper.exe
id: eca49c87-8a75-4f13-9c73-a5a29e845f03
status: test
description: Detects execution of powershell scripts via Runscripthelper.exe
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Runscripthelper/
author: Victor Sergeev, oscd.community
date: 2020-10-09
modified: 2022-07-11
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\Runscripthelper.exe'
        CommandLine|contains: 'surfacecheck'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
