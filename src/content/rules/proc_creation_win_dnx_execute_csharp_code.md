---
title: Potential Application Whitelisting Bypass via Dnx.EXE
summary: |-
  Detects the execution of Dnx.EXE. The Dnx utility allows for the execution of C# code.
  Attackers might abuse this in order to bypass application whitelisting.
sigma_id: 81ebd28b-9607-4478-bf06-974ed9d53ed7
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218
  - T1027.004
author: Beyu Denis, oscd.community
date: '2019-10-26'
modified: '2024-04-24'
falsepositives:
  - Legitimate use of dnx.exe by legitimate user
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Csi/
  - https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_dnx_execute_csharp_code.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Application Whitelisting Bypass via Dnx.EXE
id: 81ebd28b-9607-4478-bf06-974ed9d53ed7
status: test
description: |
    Detects the execution of Dnx.EXE. The Dnx utility allows for the execution of C# code.
    Attackers might abuse this in order to bypass application whitelisting.
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Csi/
    - https://enigma0x3.net/2016/11/17/bypassing-application-whitelisting-by-using-dnx-exe/
author: Beyu Denis, oscd.community
date: 2019-10-26
modified: 2024-04-24
tags:
    - attack.stealth
    - attack.t1218
    - attack.t1027.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\dnx.exe'
    condition: selection
falsepositives:
    - Legitimate use of dnx.exe by legitimate user
level: medium
```
