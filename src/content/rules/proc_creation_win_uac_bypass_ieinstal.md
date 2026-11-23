---
title: UAC Bypass Using IEInstal - Process
summary: Detects the pattern of UAC Bypass using IEInstal.exe (UACMe 64)
sigma_id: 80fc36aa-945e-4181-89f2-2f907ab6775d
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
techniques:
  - T1548.002
author: Christian Burkard (Nextron Systems)
date: '2021-08-30'
modified: '2024-12-01'
falsepositives:
  - Unknown
references:
  - https://github.com/hfiref0x/UACME
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_uac_bypass_ieinstal.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: UAC Bypass Using IEInstal - Process
id: 80fc36aa-945e-4181-89f2-2f907ab6775d
status: test
description: Detects the pattern of UAC Bypass using IEInstal.exe (UACMe 64)
references:
    - https://github.com/hfiref0x/UACME
author: Christian Burkard (Nextron Systems)
date: 2021-08-30
modified: 2024-12-01
tags:
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        IntegrityLevel:
            - 'High'
            - 'System'
            - 'S-1-16-16384' # System
            - 'S-1-16-12288' # High
        ParentImage|endswith: '\ieinstal.exe'
        Image|contains: '\AppData\Local\Temp\'
        Image|endswith: 'consent.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
