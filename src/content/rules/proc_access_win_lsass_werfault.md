---
title: Credential Dumping Attempt Via WerFault
summary: >-
  Detects process LSASS memory dump using Mimikatz, NanoDump, Invoke-Mimikatz, Procdump or Taskmgr based on the CallTrace pointing to ntdll.dll, dbghelp.dll or dbgcore.dll for win10, server2016 and
  up.
sigma_id: e5b33f7d-eb93-48b6-9851-09e1e610b6d7
status: test
level: high
platform: windows
logsource: windows / process_access
tactics:
  - TA0006
techniques:
  - T1003.001
author: Florian Roth (Nextron Systems)
date: '2022-06-27'
modified: '2023-11-29'
falsepositives:
  - Actual failures in lsass.exe that trigger a crash dump (unlikely)
  - Unknown cases in which WerFault accesses lsass.exe
references:
  - https://github.com/helpsystems/nanodump/commit/578116faea3d278d53d70ea932e2bbfe42569507
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_access/proc_access_win_lsass_werfault.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Credential Dumping Attempt Via WerFault
id: e5b33f7d-eb93-48b6-9851-09e1e610b6d7
status: test
description: Detects process LSASS memory dump using Mimikatz, NanoDump, Invoke-Mimikatz, Procdump or Taskmgr based on the CallTrace pointing to ntdll.dll, dbghelp.dll or dbgcore.dll for win10, server2016 and up.
references:
    - https://github.com/helpsystems/nanodump/commit/578116faea3d278d53d70ea932e2bbfe42569507
author: Florian Roth (Nextron Systems)
date: 2022-06-27
modified: 2023-11-29
tags:
    - attack.credential-access
    - attack.t1003.001
    - attack.s0002
logsource:
    category: process_access
    product: windows
detection:
    selection:
        SourceImage|endswith: '\WerFault.exe'
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess: '0x1FFFFF'
    condition: selection
falsepositives:
    - Actual failures in lsass.exe that trigger a crash dump (unlikely)
    - Unknown cases in which WerFault accesses lsass.exe
level: high
```
