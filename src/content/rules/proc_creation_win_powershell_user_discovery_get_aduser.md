---
title: User Discovery And Export Via Get-ADUser Cmdlet
summary: Detects usage of the Get-ADUser cmdlet to collect user information and output it to a file
sigma_id: 1114e048-b69c-4f41-bc20-657245ae6e3f
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1033
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-09'
modified: '2022-11-17'
falsepositives:
  - Legitimate admin scripts may use the same technique, it's better to exclude specific computers or users who execute these commands or scripts often
references:
  - http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
  - https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_user_discovery_get_aduser.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: User Discovery And Export Via Get-ADUser Cmdlet
id: 1114e048-b69c-4f41-bc20-657245ae6e3f
related:
    - id: c2993223-6da8-4b1a-88ee-668b8bf315e9
      type: similar
status: test
description: Detects usage of the Get-ADUser cmdlet to collect user information and output it to a file
references:
    - http://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
    - https://www.microsoft.com/en-us/security/blog/2022/10/18/defenders-beware-a-case-for-post-ransomware-investigations/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-09
modified: 2022-11-17
tags:
    - attack.discovery
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\powershell.exe'
              - '\pwsh.exe'
        - OriginalFileName:
              - 'PowerShell.EXE'
              - 'pwsh.dll'
    selection_cli:
        CommandLine|contains|all:
            - 'Get-ADUser '
            - ' -Filter \*'
        CommandLine|contains:
            - ' > '
            - ' | Select '
            - 'Out-File'
            - 'Set-Content'
            - 'Add-Content'
    condition: all of selection_*
falsepositives:
    - Legitimate admin scripts may use the same technique, it's better to exclude specific computers or users who execute these commands or scripts often
level: medium
```
