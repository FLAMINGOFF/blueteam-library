---
title: PrintBrm ZIP Creation of Extraction
summary: Detects the execution of the LOLBIN PrintBrm.exe, which can be used to create or extract ZIP files. PrintBrm.exe should not be run on a normal workstation.
sigma_id: cafeeba3-01da-4ab4-b6c4-a31b1d9730c7
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
  - TA0005
techniques:
  - T1105
  - T1564.004
author: frack113
date: '2022-05-02'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/PrintBrm/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_printbrm.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PrintBrm ZIP Creation of Extraction
id: cafeeba3-01da-4ab4-b6c4-a31b1d9730c7
status: test
description: Detects the execution of the LOLBIN PrintBrm.exe, which can be used to create or extract ZIP files. PrintBrm.exe should not be run on a normal workstation.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/PrintBrm/
author: frack113
date: 2022-05-02
tags:
    - attack.command-and-control
    - attack.stealth
    - attack.t1105
    - attack.t1564.004
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\PrintBrm.exe'
        CommandLine|contains|all:
            - ' -f'
            - '.zip'
    condition: selection
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_lolbin_printbrm/info.yml
```
