---
title: RDP Connection Allowed Via Netsh.EXE
summary: Detects usage of the netsh command to open and allow connections to port 3389 (RDP). As seen used by Sarwent Malware
sigma_id: 01aeb693-138d-49d2-9403-c4f52d7d3d62
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1686.003
author: Sander Wiebing
date: '2020-05-23'
modified: '2023-12-11'
falsepositives:
  - Legitimate administration activity
references:
  - https://labs.sentinelone.com/sarwent-malware-updates-command-detonation/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_netsh_fw_allow_rdp.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: RDP Connection Allowed Via Netsh.EXE
id: 01aeb693-138d-49d2-9403-c4f52d7d3d62
status: test
description: Detects usage of the netsh command to open and allow connections to port 3389 (RDP). As seen used by Sarwent Malware
references:
    - https://labs.sentinelone.com/sarwent-malware-updates-command-detonation/
author: Sander Wiebing
date: 2020-05-23
modified: 2023-12-11
tags:
    - attack.defense-impairment
    - attack.t1686.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\netsh.exe'
        - OriginalFileName: 'netsh.exe'
    selection_cli:
        # Example:
        #   Old: netsh firewall add portopening TCP 3389 "Open Port 3389"
        #   New: netsh advfirewall firewall add rule name= "Open Port 3389" dir=in action=allow protocol=TCP localport=3389
        CommandLine|contains|all:
            - 'firewall '
            - 'add '
            - 'tcp '
            - '3389'
        CommandLine|contains:
            - 'portopening'
            - 'allow'
    condition: all of selection_*
falsepositives:
    - Legitimate administration activity
level: high
```
