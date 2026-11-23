---
title: Port Forwarding Activity Via SSH.EXE
summary: Detects port forwarding activity via SSH.exe
sigma_id: 327f48c1-a6db-4eb8-875a-f6981f1b0183
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
  - TA0008
techniques:
  - T1572
  - T1021.001
  - T1021.004
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-10-12'
modified: '2024-03-05'
falsepositives:
  - Administrative activity using a remote port forwarding to a local port
references:
  - https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_ssh_port_forward.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Port Forwarding Activity Via SSH.EXE
id: 327f48c1-a6db-4eb8-875a-f6981f1b0183
status: test
description: Detects port forwarding activity via SSH.exe
references:
    - https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-10-12
modified: 2024-03-05
tags:
    - attack.command-and-control
    - attack.lateral-movement
    - attack.t1572
    - attack.t1021.001
    - attack.t1021.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\ssh.exe'
        CommandLine|contains|windash: ' -R '
    condition: selection
falsepositives:
    - Administrative activity using a remote port forwarding to a local port
level: medium
```
