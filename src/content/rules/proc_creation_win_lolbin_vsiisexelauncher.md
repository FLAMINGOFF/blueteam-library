---
title: Use of VSIISExeLauncher.exe
summary: The "VSIISExeLauncher.exe" binary part of the Visual Studio/VS Code can be used to execute arbitrary binaries
sigma_id: 18749301-f1c5-4efc-a4c3-276ff1f5b6f8
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1127
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-06-09'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/VSIISExeLauncher/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_vsiisexelauncher.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Use of VSIISExeLauncher.exe
id: 18749301-f1c5-4efc-a4c3-276ff1f5b6f8
status: test
description: The "VSIISExeLauncher.exe" binary part of the Visual Studio/VS Code can be used to execute arbitrary binaries
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/VSIISExeLauncher/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-09
tags:
    - attack.execution
    - attack.stealth
    - attack.t1127
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\VSIISExeLauncher.exe'
        - OriginalFileName: 'VSIISExeLauncher.exe'
    selection_cli:
        CommandLine|contains:
            - ' -p '
            - ' -a '
    condition: all of selection*
falsepositives:
    - Unknown
level: medium
```
