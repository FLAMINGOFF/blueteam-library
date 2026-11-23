---
title: Uncommon Process Access Rights For Target Image
summary: Detects process access request to uncommon target images with a "PROCESS_ALL_ACCESS" access mask.
sigma_id: a24e5861-c6ca-4fde-a93c-ba9256feddf0
status: test
level: low
platform: windows
logsource: windows / process_access
tactics:
  - TA0004
techniques:
  - T1055.011
author: Nasreddine Bencherchali (Nextron Systems), frack113
date: '2024-05-27'
falsepositives:
  - Unknown
references:
  - https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_access/proc_access_win_susp_all_access_uncommon_target.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Uncommon Process Access Rights For Target Image
id: a24e5861-c6ca-4fde-a93c-ba9256feddf0
status: test
description: |
    Detects process access request to uncommon target images with a "PROCESS_ALL_ACCESS" access mask.
references:
    - https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
author: Nasreddine Bencherchali (Nextron Systems), frack113
date: 2024-05-27
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1055.011
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith:
            # Note: Add additional uncommon targets to increase coverage.
            - '\calc.exe'
            - '\calculator.exe'
            - '\mspaint.exe'
            - '\notepad.exe'
            - '\ping.exe'
            - '\wordpad.exe'
            - '\write.exe'
        GrantedAccess: '0x1FFFFF' # PROCESS_ALL_ACCESS - All possible access rights for a process object.
    condition: selection
falsepositives:
    - Unknown
# Note: please upgrade to a higher level after an initial test/tuning.
level: low
```
