---
title: Potential Persistence Attempt Via Existing Service Tampering
summary: Detects the modification of an existing service in order to execute an arbitrary payload when the service is started or killed as a potential method for persistence.
sigma_id: 38879043-7e1e-47a9-8d46-6bec88e201df
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
  - TA0002
  - TA0005
techniques:
  - T1543.003
  - T1574.011
author: Sreeman
date: '2020-09-29'
modified: '2023-02-04'
falsepositives:
  - Unknown
references:
  - https://pentestlab.blog/2020/01/22/persistence-modify-existing-service/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sc_service_tamper_for_persistence.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Persistence Attempt Via Existing Service Tampering
id: 38879043-7e1e-47a9-8d46-6bec88e201df
status: test
description: Detects the modification of an existing service in order to execute an arbitrary payload when the service is started or killed as a potential method for persistence.
references:
    - https://pentestlab.blog/2020/01/22/persistence-modify-existing-service/
author: Sreeman
date: 2020-09-29
modified: 2023-02-04
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.stealth
    - attack.t1543.003
    - attack.t1574.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_sc:
        - CommandLine|contains|all:
              - 'sc '
              - 'config '
              - 'binpath='
        - CommandLine|contains|all:
              - 'sc '
              - 'failure'
              - 'command='
    selection_reg_img:
        - CommandLine|contains|all:
              - 'reg '
              - 'add '
              - 'FailureCommand'
        - CommandLine|contains|all:
              - 'reg '
              - 'add '
              - 'ImagePath'
    selection_reg_ext:
        CommandLine|contains:
            - '.sh'
            - '.exe'
            - '.dll'
            - '.bin$'
            - '.bat'
            - '.cmd'
            - '.js'
            - '.msh$'
            - '.reg$'
            - '.scr'
            - '.ps'
            - '.vb'
            - '.jar'
            - '.pl'
    condition: selection_sc or all of selection_reg_*
falsepositives:
    - Unknown
level: medium
```
