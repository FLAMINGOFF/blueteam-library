---
title: Using SettingSyncHost.exe as LOLBin
summary: Detects using SettingSyncHost.exe to run hijacked binary
sigma_id: b2ddd389-f676-4ac4-845a-e00781a48e5f
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
  - TA0002
  - TA0005
techniques:
  - T1574.008
author: Anton Kutepov, oscd.community
date: '2020-02-05'
modified: '2021-11-27'
falsepositives:
  - Unknown
references:
  - https://www.hexacorn.com/blog/2020/02/02/settingsynchost-exe-as-a-lolbin
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_settingsynchost.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Using SettingSyncHost.exe as LOLBin
id: b2ddd389-f676-4ac4-845a-e00781a48e5f
status: test
description: Detects using SettingSyncHost.exe to run hijacked binary
references:
    - https://www.hexacorn.com/blog/2020/02/02/settingsynchost-exe-as-a-lolbin
author: Anton Kutepov, oscd.community
date: 2020-02-05
modified: 2021-11-27
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.stealth
    - attack.t1574.008
logsource:
    category: process_creation
    product: windows
detection:
    system_utility:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
    parent_is_settingsynchost:
        ParentCommandLine|contains|all:
            - 'cmd.exe /c'
            - 'RoamDiag.cmd'
            - '-outputpath'
    condition: not system_utility and parent_is_settingsynchost
falsepositives:
    - Unknown
level: high
```
