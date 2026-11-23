---
title: Execute Code with Pester.bat as Parent
summary: Detects code execution via Pester.bat (Pester - Powershell Modulte for testing)
sigma_id: 18988e1b-9087-4f8a-82fe-0414dce49878
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.001
  - T1216
author: frack113, Nasreddine Bencherchali
date: '2022-08-20'
falsepositives:
  - Legitimate use of Pester for writing tests for Powershell scripts and modules
references:
  - https://twitter.com/Oddvarmoe/status/993383596244258816
  - https://twitter.com/_st0pp3r_/status/1560072680887525378
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_pester.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Execute Code with Pester.bat as Parent
id: 18988e1b-9087-4f8a-82fe-0414dce49878
related:
    - id: 59e938ff-0d6d-4dc3-b13f-36cc28734d4e
      type: similar
status: test
description: Detects code execution via Pester.bat (Pester - Powershell Modulte for testing)
references:
    - https://twitter.com/Oddvarmoe/status/993383596244258816
    - https://twitter.com/_st0pp3r_/status/1560072680887525378
author: frack113, Nasreddine Bencherchali
date: 2022-08-20
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059.001
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    selection_module:
        ParentImage|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        ParentCommandLine|contains: '\WindowsPowerShell\Modules\Pester\'
    selection_cli:
        ParentCommandLine|contains:
            - '{ Invoke-Pester -EnableExit ;'
            - '{ Get-Help "'
    condition: all of selection_*
falsepositives:
    - Legitimate use of Pester for writing tests for Powershell scripts and modules
level: medium
```
