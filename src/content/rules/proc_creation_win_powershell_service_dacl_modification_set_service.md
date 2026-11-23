---
title: Suspicious Service DACL Modification Via Set-Service Cmdlet
summary: >-
  Detects suspicious DACL modifications via the "Set-Service" cmdlet using the "SecurityDescriptorSddl" flag (Only available with PowerShell 7) that can be used to hide services or make them
  unstopable
sigma_id: a95b9b42-1308-4735-a1af-abb1c5e6f5ac
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
techniques:
  - T1543.003
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-10-18'
falsepositives:
  - Unknown
references:
  - https://www.sans.org/blog/red-team-tactics-hiding-windows-services/
  - https://learn.microsoft.com/pt-br/windows/win32/secauthz/sid-strings
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_service_dacl_modification_set_service.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Service DACL Modification Via Set-Service Cmdlet
id: a95b9b42-1308-4735-a1af-abb1c5e6f5ac
related:
    - id: 99cf1e02-00fb-4c0d-8375-563f978dfd37
      type: derived
status: test
description: Detects suspicious DACL modifications via the "Set-Service" cmdlet using the "SecurityDescriptorSddl" flag (Only available with PowerShell 7) that can be used to hide services or make them unstopable
references:
    - https://www.sans.org/blog/red-team-tactics-hiding-windows-services/
    - https://learn.microsoft.com/pt-br/windows/win32/secauthz/sid-strings
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-18
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1543.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\pwsh.exe'
        - OriginalFileName: 'pwsh.dll'
    selection_sddl_flag:
        CommandLine|contains:
            - '-SecurityDescriptorSddl '
            - '-sd '
    selection_set_service:
        CommandLine|contains|all:
            - 'Set-Service '
            - 'D;;'
        CommandLine|contains:
            - ';;;IU'
            - ';;;SU'
            - ';;;BA'
            - ';;;SY'
            - ';;;WD'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
