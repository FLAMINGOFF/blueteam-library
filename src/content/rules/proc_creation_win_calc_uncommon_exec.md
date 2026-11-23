---
title: Suspicious Calculator Usage
summary: Detects suspicious use of 'calc.exe' with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion.
sigma_id: 737e618a-a410-49b5-bec3-9e55ff7fbc15
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1036
author: Florian Roth (Nextron Systems)
date: '2019-02-09'
modified: '2023-11-09'
falsepositives:
  - Unknown
references:
  - https://twitter.com/ItsReallyNick/status/1094080242686312448
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_calc_uncommon_exec.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Calculator Usage
id: 737e618a-a410-49b5-bec3-9e55ff7fbc15
status: test
description: |
    Detects suspicious use of 'calc.exe' with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion.
references:
    - https://twitter.com/ItsReallyNick/status/1094080242686312448
author: Florian Roth (Nextron Systems)
date: 2019-02-09
modified: 2023-11-09
tags:
    - attack.stealth
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        CommandLine|contains: '\calc.exe '
    selection_2:
        Image|endswith: '\calc.exe'
    filter_main_known_locations:
        Image|contains:
            - ':\Windows\System32\'
            - ':\Windows\SysWOW64\'
            - ':\Windows\WinSxS\'
    condition: selection_1 or ( selection_2 and not filter_main_known_locations )
falsepositives:
    - Unknown
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_calc_uncommon_exec/info.yml
```
