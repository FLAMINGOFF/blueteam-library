---
title: AADInternals PowerShell Cmdlets Execution - ProccessCreation
summary: Detects ADDInternals Cmdlet execution. A tool for administering Azure AD and Office 365. Which can be abused by threat actors to attack Azure AD or Office 365.
sigma_id: c86500e9-a645-4680-98d7-f882c70c1ea3
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0043
  - TA0007
  - TA0006
  - TA0040
techniques: []
author: Austin Songer (@austinsonger), Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
date: '2022-12-23'
modified: '2025-02-06'
falsepositives:
  - Legitimate use of the library for administrative activity
references:
  - https://o365blog.com/aadinternals/
  - https://github.com/Gerenios/AADInternals
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_aadinternals_cmdlets_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: AADInternals PowerShell Cmdlets Execution - ProccessCreation
id: c86500e9-a645-4680-98d7-f882c70c1ea3
related:
    - id: 91e69562-2426-42ce-a647-711b8152ced6
      type: similar
status: test
description: Detects ADDInternals Cmdlet execution. A tool for administering Azure AD and Office 365. Which can be abused by threat actors to attack Azure AD or Office 365.
references:
    - https://o365blog.com/aadinternals/
    - https://github.com/Gerenios/AADInternals
author: Austin Songer (@austinsonger), Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)
date: 2022-12-23
modified: 2025-02-06
tags:
    - attack.execution
    - attack.reconnaissance
    - attack.discovery
    - attack.credential-access
    - attack.impact
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith:
              - '\powershell.exe'
              - '\powershell_ise.exe'
              - '\pwsh.exe'
        - OriginalFileName:
              - 'PowerShell.Exe'
              - 'pwsh.dll'
    selection_cli:
        CommandLine|contains:
            # Since most of the cmdlets use a unique enough string which is "-AADInt" we only used that portion. For a complete list please check the references linked above
            - 'Add-AADInt'
            - 'ConvertTo-AADInt'
            - 'Disable-AADInt'
            - 'Enable-AADInt'
            - 'Export-AADInt'
            - 'Find-AADInt'
            - 'Get-AADInt'
            - 'Grant-AADInt'
            - 'Initialize-AADInt'
            - 'Install-AADInt'
            - 'Invoke-AADInt'
            - 'Join-AADInt'
            - 'New-AADInt'
            - 'Open-AADInt'
            - 'Read-AADInt'
            - 'Register-AADInt'
            - 'Remove-AADInt'
            - 'Reset-AADInt'
            - 'Resolve-AADInt'
            - 'Restore-AADInt'
            - 'Save-AADInt'
            - 'Search-AADInt'
            - 'Send-AADInt'
            - 'Set-AADInt'
            - 'Start-AADInt'
            - 'Unprotect-AADInt'
            - 'Update-AADInt'
    condition: all of selection_*
falsepositives:
    - Legitimate use of the library for administrative activity
level: high
```
