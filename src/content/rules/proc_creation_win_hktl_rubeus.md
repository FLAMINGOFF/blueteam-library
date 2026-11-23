---
title: HackTool - Rubeus Execution
summary: Detects the execution of the hacktool Rubeus via PE information of command line parameters
sigma_id: 7ec2c172-dceb-4c10-92c9-87c1881b7e18
status: stable
level: critical
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
  - TA0008
techniques:
  - T1003
  - T1558.003
  - T1550.003
author: Florian Roth (Nextron Systems)
date: '2018-12-19'
modified: '2023-04-20'
falsepositives:
  - Unlikely
references:
  - https://blog.harmj0y.net/redteaming/from-kekeo-to-rubeus
  - https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html
  - https://github.com/GhostPack/Rubeus
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_rubeus.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - Rubeus Execution
id: 7ec2c172-dceb-4c10-92c9-87c1881b7e18
related:
    - id: 7ec2c172-dceb-4c10-92c9-87c1881b7e18
      type: similar
status: stable
description: Detects the execution of the hacktool Rubeus via PE information of command line parameters
references:
    - https://blog.harmj0y.net/redteaming/from-kekeo-to-rubeus
    - https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html
    - https://github.com/GhostPack/Rubeus
author: Florian Roth (Nextron Systems)
date: 2018-12-19
modified: 2023-04-20
tags:
    - attack.credential-access
    - attack.t1003
    - attack.t1558.003
    - attack.lateral-movement
    - attack.t1550.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\Rubeus.exe'
        - OriginalFileName: 'Rubeus.exe'
        - Description: 'Rubeus'
        - CommandLine|contains:
              - 'asreproast '
              - 'dump /service:krbtgt '
              - 'dump /luid:0x'
              - 'kerberoast '
              - 'createnetonly /program:'
              - 'ptt /ticket:'
              - '/impersonateuser:'
              - 'renew /ticket:'
              - 'asktgt /user:'
              - 'harvest /interval:'
              - 's4u /user:'
              - 's4u /ticket:'
              - 'hash /password:'
              - 'golden /aes256:'
              - 'silver /user:'
    condition: selection
falsepositives:
    - Unlikely
level: critical
```
