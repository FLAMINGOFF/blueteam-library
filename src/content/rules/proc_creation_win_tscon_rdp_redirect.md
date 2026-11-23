---
title: Suspicious RDP Redirect Using TSCON
summary: Detects a suspicious RDP session redirect using tscon.exe
sigma_id: f72aa3e8-49f9-4c7d-bd74-f8ab84ff9bbb
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0008
techniques:
  - T1563.002
  - T1021.001
author: Florian Roth (Nextron Systems)
date: '2018-03-17'
modified: '2023-05-16'
falsepositives:
  - Unknown
references:
  - http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
  - https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6
  - https://www.hackingarticles.in/rdp-session-hijacking-with-tscon/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_tscon_rdp_redirect.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious RDP Redirect Using TSCON
id: f72aa3e8-49f9-4c7d-bd74-f8ab84ff9bbb
status: test
description: Detects a suspicious RDP session redirect using tscon.exe
references:
    - http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
    - https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6
    - https://www.hackingarticles.in/rdp-session-hijacking-with-tscon/
author: Florian Roth (Nextron Systems)
date: 2018-03-17
modified: 2023-05-16
tags:
    - attack.lateral-movement
    - attack.t1563.002
    - attack.t1021.001
    - car.2013-07-002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: ' /dest:rdp-tcp#'
    condition: selection
falsepositives:
    - Unknown
level: high
```
