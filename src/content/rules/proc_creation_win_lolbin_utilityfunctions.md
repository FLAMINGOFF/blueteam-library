---
title: UtilityFunctions.ps1 Proxy Dll
summary: Detects the use of a Microsoft signed script executing a managed DLL with PowerShell.
sigma_id: 0403d67d-6227-4ea8-8145-4e72db7da120
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1216
author: frack113
date: '2022-05-28'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Scripts/UtilityFunctions/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_utilityfunctions.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: UtilityFunctions.ps1 Proxy Dll
id: 0403d67d-6227-4ea8-8145-4e72db7da120
status: test
description: Detects the use of a Microsoft signed script executing a managed DLL with PowerShell.
references:
    - https://lolbas-project.github.io/lolbas/Scripts/UtilityFunctions/
author: frack113
date: 2022-05-28
tags:
    - attack.stealth
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'UtilityFunctions.ps1'
            - 'RegSnapin '
    condition: selection
falsepositives:
    - Unknown
level: medium
```
