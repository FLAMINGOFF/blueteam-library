---
title: Potential Script Proxy Execution Via CL_Mutexverifiers.ps1
summary: Detects the use of the Microsoft signed script "CL_mutexverifiers" to proxy the execution of additional PowerShell script commands
sigma_id: 1e0e1a81-e79b-44bc-935b-ddb9c8006b3d
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1216
author: Nasreddine Bencherchali (Nextron Systems), oscd.community, Natalia Shornikova, frack113
date: '2022-05-21'
modified: '2023-08-17'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Scripts/CL_mutexverifiers/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_cl_mutexverifiers.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Script Proxy Execution Via CL_Mutexverifiers.ps1
id: 1e0e1a81-e79b-44bc-935b-ddb9c8006b3d
status: test
description: Detects the use of the Microsoft signed script "CL_mutexverifiers" to proxy the execution of additional PowerShell script commands
references:
    - https://lolbas-project.github.io/lolbas/Scripts/CL_mutexverifiers/
author: Nasreddine Bencherchali (Nextron Systems), oscd.community, Natalia Shornikova, frack113
date: 2022-05-21
modified: 2023-08-17
tags:
    - attack.stealth
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    selection_pwsh:
        ParentImage|endswith:
            # Note: to avoid potential FPs we assume the script was launched from powershell. But in theory it can be launched by any Powershell like process
            - '\powershell.exe'
            - '\pwsh.exe'
        Image|endswith: '\powershell.exe'
        CommandLine|contains: ' -nologo -windowstyle minimized -file '
    selection_temp:
        # Note: Since the function uses "env:temp" the value will change depending on the context of exec
        CommandLine|contains:
            - '\AppData\Local\Temp\'
            - '\Windows\Temp\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
