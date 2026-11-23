---
title: HackTool - ADCSPwn Execution
summary: Detects command line parameters used by ADCSPwn, a tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
sigma_id: cd8c163e-a19b-402e-bdd5-419ff5859f12
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0009
  - TA0006
techniques:
  - T1557.001
author: Florian Roth (Nextron Systems)
date: '2021-07-31'
modified: '2023-02-04'
falsepositives:
  - Unlikely
references:
  - https://github.com/bats3c/ADCSPwn
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_adcspwn.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - ADCSPwn Execution
id: cd8c163e-a19b-402e-bdd5-419ff5859f12
status: test
description: Detects command line parameters used by ADCSPwn, a tool to escalate privileges in an active directory network by coercing authenticate from machine accounts and relaying to the certificate service
references:
    - https://github.com/bats3c/ADCSPwn
author: Florian Roth (Nextron Systems)
date: 2021-07-31
modified: 2023-02-04
tags:
    - attack.collection
    - attack.credential-access
    - attack.t1557.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - ' --adcs '
            - ' --port '
    condition: selection
falsepositives:
    - Unlikely
level: high
```
