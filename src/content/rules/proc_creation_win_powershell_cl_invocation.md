---
title: Potential Process Execution Proxy Via CL_Invocation.ps1
summary: Detects calls to "SyncInvoke" that is part of the "CL_Invocation.ps1" script to proxy execution using "System.Diagnostics.Process"
sigma_id: a0459f02-ac51-4c09-b511-b8c9203fc429
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1216
author: Nasreddine Bencherchali (Nextron Systems), oscd.community, Natalia Shornikova
date: '2020-10-14'
modified: '2023-08-17'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Scripts/Cl_invocation/
  - https://twitter.com/bohops/status/948061991012327424
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_cl_invocation.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Process Execution Proxy Via CL_Invocation.ps1
id: a0459f02-ac51-4c09-b511-b8c9203fc429
status: test
description: Detects calls to "SyncInvoke" that is part of the "CL_Invocation.ps1" script to proxy execution using "System.Diagnostics.Process"
references:
    - https://lolbas-project.github.io/lolbas/Scripts/Cl_invocation/
    - https://twitter.com/bohops/status/948061991012327424
author: Nasreddine Bencherchali (Nextron Systems), oscd.community, Natalia Shornikova
date: 2020-10-14
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
        CommandLine|contains: 'SyncInvoke '
    condition: selection
falsepositives:
    - Unknown
level: medium
```
