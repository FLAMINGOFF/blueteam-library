---
title: PUA - CleanWipe Execution
summary: Detects the use of CleanWipe a tool usually used to delete Symantec antivirus.
sigma_id: f44800ac-38ec-471f-936e-3fa7d9c53100
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0112
techniques:
  - T1685
author: Nasreddine Bencherchali (Nextron Systems)
date: '2021-12-18'
modified: '2023-02-14'
falsepositives:
  - Legitimate administrative use (Should be investigated either way)
references:
  - https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Other/CleanWipe
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_pua_cleanwipe.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PUA - CleanWipe Execution
id: f44800ac-38ec-471f-936e-3fa7d9c53100
status: test
description: Detects the use of CleanWipe a tool usually used to delete Symantec antivirus.
references:
    - https://github.com/3CORESec/MAL-CL/tree/master/Descriptors/Other/CleanWipe
author: Nasreddine Bencherchali (Nextron Systems)
date: 2021-12-18
modified: 2023-02-14
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image|endswith: '\SepRemovalToolNative_x64.exe'
    selection2:
        Image|endswith: '\CATClean.exe'
        CommandLine|contains: '--uninstall'
    selection3:
        Image|endswith: '\NetInstaller.exe'
        CommandLine|contains: '-r'
    selection4:
        Image|endswith: '\WFPUnins.exe'
        CommandLine|contains|all:
            - '/uninstall'
            - '/enterprise'
    condition: 1 of selection*
falsepositives:
    - Legitimate administrative use (Should be investigated either way)
level: high
```
