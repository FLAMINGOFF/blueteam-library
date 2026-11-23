---
title: Suspicious PowerShell IEX Execution Patterns
summary: Detects suspicious ways to run Invoke-Execution using IEX alias
sigma_id: 09576804-7a05-458e-a817-eb718ca91f54
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.001
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: '2022-03-24'
modified: '2022-11-28'
falsepositives:
  - Legitimate scripts that use IEX
references:
  - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.2
  - https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_iex_patterns.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious PowerShell IEX Execution Patterns
id: 09576804-7a05-458e-a817-eb718ca91f54
status: test
description: Detects suspicious ways to run Invoke-Execution using IEX alias
references:
    - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-expression?view=powershell-7.2
    - https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708
author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
date: 2022-03-24
modified: 2022-11-28
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection_combined_1:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - ' | iex;'
            - ' | iex '
            - ' | iex}'
            - ' | IEX ;'
            - ' | IEX -Error'
            - ' | IEX (new'
            - ');IEX '
    selection_combined_2:
        CommandLine|contains:
            - '::FromBase64String'
            - '.GetString([System.Convert]::'
    selection_standalone:
        CommandLine|contains:
            - ')|iex;$'
            - ');iex($'
            - ');iex $'
            - ' | IEX | '
            - ' | iex\"'
    condition: all of selection_combined_* or selection_standalone
falsepositives:
    - Legitimate scripts that use IEX
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_powershell_iex_patterns/info.yml
```
