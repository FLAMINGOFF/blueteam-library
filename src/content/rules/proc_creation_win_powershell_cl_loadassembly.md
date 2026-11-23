---
title: Assembly Loading Via CL_LoadAssembly.ps1
summary: Detects calls to "LoadAssemblyFromPath" or "LoadAssemblyFromNS" that are part of the "CL_LoadAssembly.ps1" script. This can be abused to load different assemblies and bypass App locker controls.
sigma_id: c57872c7-614f-4d7f-a40d-b78c8df2d30d
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1216
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: '2022-05-21'
modified: '2023-08-17'
falsepositives:
  - Unknown
references:
  - https://bohops.com/2018/01/07/executing-commands-and-bypassing-applocker-with-powershell-diagnostic-scripts/
  - https://lolbas-project.github.io/lolbas/Scripts/CL_LoadAssembly/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_cl_loadassembly.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Assembly Loading Via CL_LoadAssembly.ps1
id: c57872c7-614f-4d7f-a40d-b78c8df2d30d
status: test
description: Detects calls to "LoadAssemblyFromPath" or "LoadAssemblyFromNS" that are part of the "CL_LoadAssembly.ps1" script. This can be abused to load different assemblies and bypass App locker controls.
references:
    - https://bohops.com/2018/01/07/executing-commands-and-bypassing-applocker-with-powershell-diagnostic-scripts/
    - https://lolbas-project.github.io/lolbas/Scripts/CL_LoadAssembly/
author: frack113, Nasreddine Bencherchali (Nextron Systems)
date: 2022-05-21
modified: 2023-08-17
tags:
    - attack.stealth
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        # Note: As this function is usually called from within powershell, classical process creation even would not catch it. This will only catch inline calls via "-Command" or "-ScriptBlock" flags for example.
        CommandLine|contains:
            - 'LoadAssemblyFromPath '
            - 'LoadAssemblyFromNS '
    condition: selection
falsepositives:
    - Unknown
level: medium
```
