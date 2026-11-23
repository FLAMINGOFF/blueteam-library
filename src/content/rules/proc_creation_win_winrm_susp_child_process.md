---
title: Suspicious Processes Spawned by WinRM
summary: Detects suspicious processes including shells spawnd from WinRM host process
sigma_id: 5cc2cda8-f261-4d88-a2de-e9e193c86716
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0001
  - TA0003
  - TA0004
techniques:
  - T1190
author: Andreas Hunkeler (@Karneades), Markus Neis
date: '2021-05-20'
modified: '2022-07-14'
falsepositives:
  - Legitimate WinRM usage
references:
  - Internal Research
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_winrm_susp_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Processes Spawned by WinRM
id: 5cc2cda8-f261-4d88-a2de-e9e193c86716
status: test
description: Detects suspicious processes including shells spawnd from WinRM host process
author: Andreas Hunkeler (@Karneades), Markus Neis
references:
    - Internal Research
date: 2021-05-20
modified: 2022-07-14
tags:
    - attack.t1190
    - attack.initial-access
    - attack.persistence
    - attack.privilege-escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\wsmprovhost.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\sh.exe'
            - '\bash.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wsl.exe'
            - '\schtasks.exe'
            - '\certutil.exe'
            - '\whoami.exe'
            - '\bitsadmin.exe'
    condition: selection
falsepositives:
    - Legitimate WinRM usage
level: high
```
