---
title: Potential Process Injection Via Msra.EXE
summary: >-
  Detects potential process injection via Microsoft Remote Asssistance (Msra.exe) by looking at suspicious child processes spawned from the aforementioned process. It has been a target used by many
  threat actors and used for discovery and persistence tactics
sigma_id: 744a188b-0415-4792-896f-11ddb0588dbc
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0005
techniques:
  - T1055
author: Alexander McDonald
date: '2022-06-24'
modified: '2023-02-03'
falsepositives:
  - Legitimate use of Msra.exe
references:
  - https://www.microsoft.com/security/blog/2021/12/09/a-closer-look-at-qakbots-latest-building-blocks-and-how-to-knock-them-down/
  - https://www.fortinet.com/content/dam/fortinet/assets/analyst-reports/ar-qakbot.pdf
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_msra_process_injection.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Process Injection Via Msra.EXE
id: 744a188b-0415-4792-896f-11ddb0588dbc
status: test
description: Detects potential process injection via Microsoft Remote Asssistance (Msra.exe) by looking at suspicious child processes spawned from the aforementioned process. It has been a target used by many threat actors and used for discovery and persistence tactics
references:
    - https://www.microsoft.com/security/blog/2021/12/09/a-closer-look-at-qakbots-latest-building-blocks-and-how-to-knock-them-down/
    - https://www.fortinet.com/content/dam/fortinet/assets/analyst-reports/ar-qakbot.pdf
author: Alexander McDonald
date: 2022-06-24
modified: 2023-02-03
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\msra.exe'
        ParentCommandLine|endswith: 'msra.exe'
        Image|endswith:
            - '\arp.exe'
            - '\cmd.exe'
            - '\net.exe'
            - '\netstat.exe'
            - '\nslookup.exe'
            - '\route.exe'
            - '\schtasks.exe'
            - '\whoami.exe'
    condition: selection
falsepositives:
    - Legitimate use of Msra.exe
level: high
```
