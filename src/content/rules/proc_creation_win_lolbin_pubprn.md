---
title: Pubprn.vbs Proxy Execution
summary: Detects the use of the 'Pubprn.vbs' Microsoft signed script to execute commands.
sigma_id: 1fb76ab8-fa60-4b01-bddd-71e89bf555da
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1216.001
author: frack113
date: '2022-05-28'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Scripts/Pubprn/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_pubprn.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Pubprn.vbs Proxy Execution
id: 1fb76ab8-fa60-4b01-bddd-71e89bf555da
status: test
description: Detects the use of the 'Pubprn.vbs' Microsoft signed script to execute commands.
references:
    - https://lolbas-project.github.io/lolbas/Scripts/Pubprn/
author: frack113
date: 2022-05-28
tags:
    - attack.stealth
    - attack.t1216.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\pubprn.vbs'
            - 'script:'
    condition: selection
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_lolbin_pubprn/info.yml
```
