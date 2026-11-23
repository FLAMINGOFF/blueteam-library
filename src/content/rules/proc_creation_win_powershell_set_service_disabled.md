---
title: Service StartupType Change Via PowerShell Set-Service
summary: Detects the use of the PowerShell "Set-Service" cmdlet to change the startup type of a service to "disabled" or "manual"
sigma_id: 62b20d44-1546-4e61-afce-8e175eb9473c
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0112
techniques:
  - T1685
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-03-04'
falsepositives:
  - False positives may occur with troubleshooting scripts
references:
  - https://www.virustotal.com/gui/file/38283b775552da8981452941ea74191aa0d203edd3f61fb2dee7b0aea3514955
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_set_service_disabled.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Service StartupType Change Via PowerShell Set-Service
id: 62b20d44-1546-4e61-afce-8e175eb9473c
status: test
description: Detects the use of the PowerShell "Set-Service" cmdlet to change the startup type of a service to "disabled" or "manual"
references:
    - https://www.virustotal.com/gui/file/38283b775552da8981452941ea74191aa0d203edd3f61fb2dee7b0aea3514955
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-03-04
tags:
    - attack.execution
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\powershell.exe'
        - OriginalFileName: 'PowerShell.EXE'
    selection_cli:
        CommandLine|contains|all:
            - 'Set-Service'
            - '-StartupType'
        CommandLine|contains:
            - 'Disabled'
            - 'Manual'
    condition: all of selection_*
falsepositives:
    - False positives may occur with troubleshooting scripts
level: medium
```
