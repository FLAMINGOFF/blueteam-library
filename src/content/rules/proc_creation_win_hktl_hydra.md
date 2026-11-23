---
title: HackTool - Hydra Password Bruteforce Execution
summary: Detects command line parameters used by Hydra password guessing hack tool
sigma_id: aaafa146-074c-11eb-adc1-0242ac120002
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1110
  - T1110.001
author: Vasiliy Burov
date: '2020-10-05'
modified: '2023-02-04'
falsepositives:
  - Software that uses the caret encased keywords PASS and USER in its command line
references:
  - https://github.com/vanhauser-thc/thc-hydra
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_hydra.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - Hydra Password Bruteforce Execution
id: aaafa146-074c-11eb-adc1-0242ac120002
status: test
description: Detects command line parameters used by Hydra password guessing hack tool
references:
    - https://github.com/vanhauser-thc/thc-hydra
author: Vasiliy Burov
date: 2020-10-05
modified: 2023-02-04
tags:
    - attack.credential-access
    - attack.t1110
    - attack.t1110.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '-u '
            - '-p '
        CommandLine|contains:
            - '^USER^'
            - '^PASS^'
    condition: selection
falsepositives:
    - Software that uses the caret encased keywords PASS and USER in its command line
level: high
```
