---
title: Import PowerShell Modules From Suspicious Directories - ProcCreation
summary: Detects powershell scripts that import modules from suspicious directories
sigma_id: c31364f7-8be6-4b77-8483-dd2b5a7b69a3
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.001
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-01-10'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.002/T1003.002.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_import_module_susp_dirs.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Import PowerShell Modules From Suspicious Directories - ProcCreation
id: c31364f7-8be6-4b77-8483-dd2b5a7b69a3
related:
    - id: 21f9162c-5f5d-4b01-89a8-b705bd7d10ab
      type: similar
status: test
description: Detects powershell scripts that import modules from suspicious directories
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1003.002/T1003.002.md
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-01-10
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'Import-Module "$Env:Temp\'
            - Import-Module '$Env:Temp\
            - 'Import-Module $Env:Temp\'
            - 'Import-Module "$Env:Appdata\'
            - Import-Module '$Env:Appdata\
            - 'Import-Module $Env:Appdata\'
            - 'Import-Module C:\Users\Public\'
            # Import-Module alias is "ipmo"
            - 'ipmo "$Env:Temp\'
            - ipmo '$Env:Temp\
            - 'ipmo $Env:Temp\'
            - 'ipmo "$Env:Appdata\'
            - ipmo '$Env:Appdata\
            - 'ipmo $Env:Appdata\'
            - 'ipmo C:\Users\Public\'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
