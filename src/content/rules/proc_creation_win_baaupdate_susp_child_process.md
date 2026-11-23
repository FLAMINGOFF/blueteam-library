---
title: Suspicious BitLocker Access Agent Update Utility Execution
summary: |-
  Detects the execution of the BitLocker Access Agent Update Utility (baaupdate.exe) which is not a common parent process for other processes.
  Suspicious child processes spawned by baaupdate.exe could indicate an attempt at lateral movement via BitLocker DCOM & COM Hijacking.
sigma_id: 9f38c1db-e2ae-40bf-81d0-5b68f73fb512
status: experimental
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
  - TA0008
techniques:
  - T1218
  - T1021.003
author: andrewdanis, Swachchhanda Shrawan Poudel (Nextron Systems)
date: '2025-10-18'
falsepositives:
  - Unknown
references:
  - https://github.com/rtecCyberSec/BitlockMove
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_baaupdate_susp_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious BitLocker Access Agent Update Utility Execution
id: 9f38c1db-e2ae-40bf-81d0-5b68f73fb512
related:
    - id: 6e8fe0a8-ba0b-4a93-8f9e-82657e7a5984 # BaaUpdate.exe Suspicious DLL Load
      type: similar
status: experimental
description: |
    Detects the execution of the BitLocker Access Agent Update Utility (baaupdate.exe) which is not a common parent process for other processes.
    Suspicious child processes spawned by baaupdate.exe could indicate an attempt at lateral movement via BitLocker DCOM & COM Hijacking.
references:
    - https://github.com/rtecCyberSec/BitlockMove
author: andrewdanis, Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2025-10-18
tags:
    - attack.stealth
    - attack.t1218
    - attack.lateral-movement
    - attack.t1021.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\baaupdate.exe'
        Image|endswith:
            - '\bitsadmin.exe'
            - '\cmd.exe'
            - '\cscript.exe'
            - '\mshta.exe'
            - '\powershell_ise.exe'
            - '\powershell.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\schtasks.exe'
            - '\wmic.exe'
            - '\wscript.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
