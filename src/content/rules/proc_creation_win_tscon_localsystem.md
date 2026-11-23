---
title: Suspicious TSCON Start as SYSTEM
summary: Detects a tscon.exe start as LOCAL SYSTEM
sigma_id: 9847f263-4a81-424f-970c-875dab15b79b
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1219.002
author: Florian Roth (Nextron Systems)
date: '2018-03-17'
modified: '2022-05-27'
falsepositives:
  - Unknown
references:
  - http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
  - https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6
  - https://www.ired.team/offensive-security/lateral-movement/t1076-rdp-hijacking-for-lateral-movement
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_tscon_localsystem.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious TSCON Start as SYSTEM
id: 9847f263-4a81-424f-970c-875dab15b79b
status: test
description: Detects a tscon.exe start as LOCAL SYSTEM
references:
    - http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
    - https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6
    - https://www.ired.team/offensive-security/lateral-movement/t1076-rdp-hijacking-for-lateral-movement
author: Florian Roth (Nextron Systems)
date: 2018-03-17
modified: 2022-05-27
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
        Image|endswith: '\tscon.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
