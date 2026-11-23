---
title: Powershell Inline Execution From A File
summary: Detects inline execution of PowerShell code from a file
sigma_id: ee218c12-627a-4d27-9e30-d6fb2fe22ed2
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.001
author: frack113
date: '2022-12-25'
falsepositives:
  - Unknown
references:
  - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=50
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_powershell_exec_data_file.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Powershell Inline Execution From A File
id: ee218c12-627a-4d27-9e30-d6fb2fe22ed2
status: test
description: Detects inline execution of PowerShell code from a file
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=50
author: frack113
date: 2022-12-25
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: process_creation
detection:
    selection_exec:
        CommandLine|contains:
            - 'iex '
            - 'Invoke-Expression '
            - 'Invoke-Command '
            - 'icm '
    selection_read:
        CommandLine|contains:
            - 'cat '
            - 'get-content '
            - 'type '
    selection_raw:
        CommandLine|contains: ' -raw'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_powershell_exec_data_file/info.yml
```
