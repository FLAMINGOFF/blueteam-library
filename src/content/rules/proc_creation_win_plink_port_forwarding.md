---
title: Suspicious Plink Port Forwarding
summary: Detects suspicious Plink tunnel port forwarding to a local port
sigma_id: 48a61b29-389f-4032-b317-b30de6b95314
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
  - TA0008
techniques:
  - T1572
  - T1021.001
author: Florian Roth (Nextron Systems)
date: '2021-01-19'
modified: '2022-10-09'
falsepositives:
  - Administrative activity using a remote port forwarding to a local port
references:
  - https://www.real-sec.com/2019/04/bypassing-network-restrictions-through-rdp-tunneling/
  - https://medium.com/@informationsecurity/remote-ssh-tunneling-with-plink-exe-7831072b3d7d
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_plink_port_forwarding.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Plink Port Forwarding
id: 48a61b29-389f-4032-b317-b30de6b95314
status: test
description: Detects suspicious Plink tunnel port forwarding to a local port
references:
    - https://www.real-sec.com/2019/04/bypassing-network-restrictions-through-rdp-tunneling/
    - https://medium.com/@informationsecurity/remote-ssh-tunneling-with-plink-exe-7831072b3d7d
author: Florian Roth (Nextron Systems)
date: 2021-01-19
modified: 2022-10-09
tags:
    - attack.command-and-control
    - attack.t1572
    - attack.lateral-movement
    - attack.t1021.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Description: 'Command-line SSH, Telnet, and Rlogin client'
        CommandLine|contains: ' -R '
    condition: selection
falsepositives:
    - Administrative activity using a remote port forwarding to a local port
level: high
```
