---
title: UAC Bypass Using WOW64 Logger DLL Hijack
summary: Detects the pattern of UAC Bypass using a WoW64 logger DLL hijack (UACMe 30)
sigma_id: 4f6c43e2-f989-4ea5-bcd8-843b49a0317c
status: test
level: high
platform: windows
logsource: windows / process_access
tactics:
  - TA0004
techniques:
  - T1548.002
author: Christian Burkard (Nextron Systems)
date: '2021-08-23'
modified: '2022-10-09'
falsepositives:
  - Unknown
references:
  - https://github.com/hfiref0x/UACME
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_access/proc_access_win_uac_bypass_wow64_logger.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: UAC Bypass Using WOW64 Logger DLL Hijack
id: 4f6c43e2-f989-4ea5-bcd8-843b49a0317c
status: test
description: Detects the pattern of UAC Bypass using a WoW64 logger DLL hijack (UACMe 30)
references:
    - https://github.com/hfiref0x/UACME
author: Christian Burkard (Nextron Systems)
date: 2021-08-23
modified: 2022-10-09
tags:
    - attack.privilege-escalation
    - attack.t1548.002
logsource:
    category: process_access
    product: windows
detection:
    selection:
        SourceImage|contains: ':\Windows\SysWOW64\'
        GrantedAccess: '0x1fffff'
        CallTrace|startswith: 'UNKNOWN(0000000000000000)|UNKNOWN(0000000000000000)|'
    condition: selection
falsepositives:
    - Unknown
level: high
```
