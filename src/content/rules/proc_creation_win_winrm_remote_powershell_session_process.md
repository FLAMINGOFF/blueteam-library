---
title: Remote PowerShell Session Host Process (WinRM)
summary: Detects remote PowerShell sections by monitoring for wsmprovhost (WinRM host process) as a parent or child process (sign of an active PowerShell remote session).
sigma_id: 734f8d9b-42b8-41b2-bcf5-abaf49d5a3c8
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0008
techniques:
  - T1059.001
  - T1021.006
author: Roberto Rodriguez @Cyb3rWard0g
date: '2019-09-12'
modified: '2022-10-09'
falsepositives:
  - Legitimate usage of remote Powershell, e.g. for monitoring purposes.
references:
  - https://threathunterplaybook.com/hunts/windows/190511-RemotePwshExecution/notebook.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_winrm_remote_powershell_session_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remote PowerShell Session Host Process (WinRM)
id: 734f8d9b-42b8-41b2-bcf5-abaf49d5a3c8
status: test
description: Detects remote PowerShell sections by monitoring for wsmprovhost (WinRM host process) as a parent or child process (sign of an active PowerShell remote session).
references:
    - https://threathunterplaybook.com/hunts/windows/190511-RemotePwshExecution/notebook.html
author: Roberto Rodriguez @Cyb3rWard0g
date: 2019-09-12
modified: 2022-10-09
tags:
    - attack.execution
    - attack.lateral-movement
    - attack.t1059.001
    - attack.t1021.006
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\wsmprovhost.exe'
        - ParentImage|endswith: '\wsmprovhost.exe'
    condition: selection
falsepositives:
    - Legitimate usage of remote Powershell, e.g. for monitoring purposes.
level: medium
```
