---
title: RDP Port Forwarding Rule Added Via Netsh.EXE
summary: Detects the execution of netsh to configure a port forwarding of port 3389 (RDP) rule
sigma_id: 782d6f3e-4c5d-4b8c-92a3-1d05fed72e63
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0008
  - TA0011
techniques:
  - T1090
author: Florian Roth (Nextron Systems), oscd.community
date: '2019-01-29'
modified: '2023-02-13'
falsepositives:
  - Legitimate administration activity
references:
  - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_netsh_port_forwarding_3389.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: RDP Port Forwarding Rule Added Via Netsh.EXE
id: 782d6f3e-4c5d-4b8c-92a3-1d05fed72e63
status: test
description: Detects the execution of netsh to configure a port forwarding of port 3389 (RDP) rule
references:
    - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
author: Florian Roth (Nextron Systems), oscd.community
date: 2019-01-29
modified: 2023-02-13
tags:
    - attack.lateral-movement
    - attack.command-and-control
    - attack.t1090
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\netsh.exe'
        - OriginalFileName: 'netsh.exe'
    selection_cli:
        CommandLine|contains|all:
            - ' i'
            - ' p'
            - '=3389'
            - ' c'
    condition: all of selection_*
falsepositives:
    - Legitimate administration activity
level: high
```
