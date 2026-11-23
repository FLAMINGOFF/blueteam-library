---
title: UAC Bypass Using PkgMgr and DISM
summary: Detects the pattern of UAC Bypass using pkgmgr.exe and dism.exe (UACMe 23)
sigma_id: a743ceba-c771-4d75-97eb-8a90f7f4844c
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
techniques:
  - T1548.002
author: Christian Burkard (Nextron Systems)
date: '2021-08-23'
modified: '2024-12-01'
falsepositives:
  - Unknown
references:
  - https://github.com/hfiref0x/UACME
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_uac_bypass_pkgmgr_dism.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: UAC Bypass Using PkgMgr and DISM
id: a743ceba-c771-4d75-97eb-8a90f7f4844c
status: test
description: Detects the pattern of UAC Bypass using pkgmgr.exe and dism.exe (UACMe 23)
references:
    - https://github.com/hfiref0x/UACME
author: Christian Burkard (Nextron Systems)
date: 2021-08-23
modified: 2024-12-01
tags:
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\pkgmgr.exe'
        Image|endswith: '\dism.exe'
        IntegrityLevel:
            - 'High'
            - 'System'
            - 'S-1-16-16384' # System
            - 'S-1-16-12288' # High
    condition: selection
falsepositives:
    - Unknown
level: high
```
