---
title: Remote LSASS Process Access Through Windows Remote Management
summary: Detects remote access to the LSASS process via WinRM. This could be a sign of credential dumping from tools like mimikatz.
sigma_id: aa35a627-33fb-4d04-a165-d33b4afca3e8
status: stable
level: high
platform: windows
logsource: windows / process_access
tactics:
  - TA0006
  - TA0002
  - TA0008
techniques:
  - T1003.001
  - T1059.001
  - T1021.006
author: Patryk Prauze - ING Tech
date: '2019-05-20'
modified: '2023-11-29'
falsepositives:
  - Unlikely
references:
  - https://pentestlab.blog/2018/05/15/lateral-movement-winrm/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_access/proc_access_win_lsass_remote_access_trough_winrm.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remote LSASS Process Access Through Windows Remote Management
id: aa35a627-33fb-4d04-a165-d33b4afca3e8
status: stable
description: Detects remote access to the LSASS process via WinRM. This could be a sign of credential dumping from tools like mimikatz.
references:
    - https://pentestlab.blog/2018/05/15/lateral-movement-winrm/
author: Patryk Prauze - ING Tech
date: 2019-05-20
modified: 2023-11-29
tags:
    - attack.credential-access
    - attack.execution
    - attack.t1003.001
    - attack.t1059.001
    - attack.lateral-movement
    - attack.t1021.006
    - attack.s0002
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\lsass.exe'
        SourceImage|endswith: ':\Windows\system32\wsmprovhost.exe'
    filter_main_access:
        GrantedAccess: '0x80000000'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unlikely
level: high
```
