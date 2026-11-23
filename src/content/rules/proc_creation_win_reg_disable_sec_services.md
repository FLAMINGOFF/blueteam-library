---
title: Security Service Disabled Via Reg.EXE
summary: Detects execution of "reg.exe" to disable security services such as Windows Defender.
sigma_id: 5e95028c-5229-4214-afae-d653d573d0ec
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1685
author: Florian Roth (Nextron Systems), John Lambert (idea), elhoim
date: '2021-07-14'
modified: '2023-06-05'
falsepositives:
  - Unlikely
references:
  - https://twitter.com/JohnLaTwC/status/1415295021041979392
  - https://github.com/gordonbay/Windows-On-Reins/blob/e587ac7a0407847865926d575e3c46f68cf7c68d/wor.ps1
  - https://vms.drweb.fr/virus/?i=24144899
  - https://web.archive.org/web/20221222070510/https://bidouillesecurity.com/disable-windows-defender-in-powershell/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_reg_disable_sec_services.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Security Service Disabled Via Reg.EXE
id: 5e95028c-5229-4214-afae-d653d573d0ec
status: test
description: Detects execution of "reg.exe" to disable security services such as Windows Defender.
references:
    - https://twitter.com/JohnLaTwC/status/1415295021041979392
    - https://github.com/gordonbay/Windows-On-Reins/blob/e587ac7a0407847865926d575e3c46f68cf7c68d/wor.ps1
    - https://vms.drweb.fr/virus/?i=24144899
    - https://web.archive.org/web/20221222070510/https://bidouillesecurity.com/disable-windows-defender-in-powershell/
author: Florian Roth (Nextron Systems), John Lambert (idea), elhoim
date: 2021-07-14
modified: 2023-06-05
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection_reg_add:
        CommandLine|contains|all:
            - 'reg'
            - 'add'
    selection_cli_reg_start:
        CommandLine|contains|all:
            - 'd 4'
            - 'v Start'
        CommandLine|contains:
            - '\AppIDSvc'
            - '\MsMpSvc'
            - '\NisSrv'
            - '\SecurityHealthService'
            - '\Sense'
            - '\UsoSvc'
            - '\WdBoot'
            - '\WdFilter'
            - '\WdNisDrv'
            - '\WdNisSvc'
            - '\WinDefend'
            - '\wscsvc'
            - '\wuauserv'
    condition: all of selection_*
falsepositives:
    - Unlikely
level: high
```
