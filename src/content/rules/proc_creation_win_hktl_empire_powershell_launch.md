---
title: HackTool - Empire PowerShell Launch Parameters
summary: Detects suspicious powershell command line parameters used in Empire
sigma_id: 79f4ede3-402e-41c8-bc3e-ebbf5f162581
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.001
author: Florian Roth (Nextron Systems)
date: '2019-04-20'
modified: '2023-02-21'
falsepositives:
  - Other tools that incidentally use the same command line parameters
references:
  - https://github.com/EmpireProject/Empire/blob/c2ba61ca8d2031dad0cfc1d5770ba723e8b710db/lib/common/helpers.py#L165
  - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/deaduser.py#L191
  - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/resolver.py#L178
  - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_empire_powershell_launch.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - Empire PowerShell Launch Parameters
id: 79f4ede3-402e-41c8-bc3e-ebbf5f162581
status: test
description: Detects suspicious powershell command line parameters used in Empire
references:
    - https://github.com/EmpireProject/Empire/blob/c2ba61ca8d2031dad0cfc1d5770ba723e8b710db/lib/common/helpers.py#L165
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/deaduser.py#L191
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/resolver.py#L178
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64
author: Florian Roth (Nextron Systems)
date: 2019-04-20
modified: 2023-02-21
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - ' -NoP -sta -NonI -W Hidden -Enc '
            - ' -noP -sta -w 1 -enc '
            - ' -NoP -NonI -W Hidden -enc '
            - ' -noP -sta -w 1 -enc'
            - ' -enc  SQB'
            - ' -nop -exec bypass -EncodedCommand '
    condition: selection
falsepositives:
    - Other tools that incidentally use the same command line parameters
level: high
```
