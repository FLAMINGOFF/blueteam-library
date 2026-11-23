---
title: HackTool - Empire PowerShell UAC Bypass
summary: Detects some Empire PowerShell UAC bypass methods
sigma_id: 3268b746-88d8-4cd3-bffc-30077d02c787
status: stable
level: critical
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
techniques:
  - T1548.002
author: Ecco
date: '2019-08-30'
modified: '2023-02-21'
falsepositives:
  - Unknown
references:
  - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64
  - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-FodHelperBypass.ps1#L64
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_empire_powershell_uac_bypass.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - Empire PowerShell UAC Bypass
id: 3268b746-88d8-4cd3-bffc-30077d02c787
status: stable
description: Detects some Empire PowerShell UAC bypass methods
references:
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-FodHelperBypass.ps1#L64
author: Ecco
date: 2019-08-30
modified: 2023-02-21
tags:
    - attack.privilege-escalation
    - attack.t1548.002
    - car.2019-04-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - ' -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\Microsoft\Windows Update).Update)'
            - ' -NoP -NonI -c $x=$((gp HKCU:Software\Microsoft\Windows Update).Update);'
    condition: selection
falsepositives:
    - Unknown
level: critical
```
