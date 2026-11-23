---
title: MMC Spawning Windows Shell
summary: Detects a Windows command line executable started from MMC
sigma_id: 05a2ab7e-ce11-4b63-86db-ab32e763e11d
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0008
techniques:
  - T1021.003
author: Karneades, Swisscom CSIRT
date: '2019-08-05'
modified: '2022-07-14'
falsepositives: []
references:
  - https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_mmc_susp_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: MMC Spawning Windows Shell
id: 05a2ab7e-ce11-4b63-86db-ab32e763e11d
status: test
description: Detects a Windows command line executable started from MMC
references:
    - https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
author: Karneades, Swisscom CSIRT
date: 2019-08-05
modified: 2022-07-14
tags:
    - attack.lateral-movement
    - attack.t1021.003
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        ParentImage|endswith: '\mmc.exe'
    selection2:
        - Image|endswith:
              - '\cmd.exe'
              - '\powershell.exe'
              - '\pwsh.exe'
              - '\wscript.exe'
              - '\cscript.exe'
              - '\sh.exe'
              - '\bash.exe'
              - '\reg.exe'
              - '\regsvr32.exe'
        - Image|contains: '\BITSADMIN'
    condition: all of selection*
level: high
```
