---
title: HackTool - KrbRelayUp Execution
summary: Detects KrbRelayUp used to perform a universal no-fix local privilege escalation in Windows domain environments where LDAP signing is not enforced
sigma_id: 12827a56-61a4-476a-a9cb-f3068f191073
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
  - TA0008
techniques:
  - T1558.003
  - T1550.003
author: Florian Roth (Nextron Systems)
date: '2022-04-26'
modified: '2023-02-04'
falsepositives:
  - Unlikely
references:
  - https://github.com/Dec0ne/KrbRelayUp
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_krbrelayup.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - KrbRelayUp Execution
id: 12827a56-61a4-476a-a9cb-f3068f191073
status: test
description: Detects KrbRelayUp used to perform a universal no-fix local privilege escalation in Windows domain environments where LDAP signing is not enforced
references:
    - https://github.com/Dec0ne/KrbRelayUp
author: Florian Roth (Nextron Systems)
date: 2022-04-26
modified: 2023-02-04
tags:
    - attack.credential-access
    - attack.t1558.003
    - attack.lateral-movement
    - attack.t1550.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\KrbRelayUp.exe'
        - OriginalFileName: 'KrbRelayUp.exe' # In case the file has been renamed after compilation
    selection_cli_1:
        CommandLine|contains|all:
            - ' relay '
            - ' -Domain '
            - ' -ComputerName '
    selection_cli_2:
        CommandLine|contains|all:
            - ' krbscm '
            - ' -sc '
    selection_cli_3:
        CommandLine|contains|all:
            - ' spawn '
            - ' -d '
            - ' -cn '
            - ' -cp '
    condition: 1 of selection_*
falsepositives:
    - Unlikely
level: high
```
