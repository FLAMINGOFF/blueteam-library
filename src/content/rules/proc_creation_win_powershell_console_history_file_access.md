---
title: Potential PowerShell Console History Access Attempt via History File
summary: |-
  Detects potential access attempts to the PowerShell console history directly via history file (ConsoleHost_history.txt).
  This can give access to plaintext passwords used in PowerShell commands or used for general reconnaissance.
sigma_id: f4ff7323-b5fc-4323-8b52-6b9408e15788
status: experimental
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1552.001
author: Luc Génaux
date: '2025-04-03'
falsepositives:
  - Legitimate access of the console history file is possible
references:
  - https://0xdf.gitlab.io/2018/11/08/powershell-history-file.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_console_history_file_access.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential PowerShell Console History Access Attempt via History File
id: f4ff7323-b5fc-4323-8b52-6b9408e15788
status: experimental
description: |
    Detects potential access attempts to the PowerShell console history directly via history file (ConsoleHost_history.txt).
    This can give access to plaintext passwords used in PowerShell commands or used for general reconnaissance.
references:
    - https://0xdf.gitlab.io/2018/11/08/powershell-history-file.html
author: Luc Génaux
date: 2025-04-03
tags:
    - attack.credential-access
    - attack.t1552.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'ConsoleHost_history.txt'
            - '(Get-PSReadLineOption).HistorySavePath'
    condition: selection
falsepositives:
    - Legitimate access of the console history file is possible
level: medium
```
