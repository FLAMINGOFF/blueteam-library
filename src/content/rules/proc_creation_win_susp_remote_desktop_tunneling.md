---
title: Potential Remote Desktop Tunneling
summary: >-
  Detects potential use of an SSH utility to establish RDP over a reverse SSH Tunnel. This can be used by attackers to enable routing of network packets that would otherwise not reach their intended
  destination.
sigma_id: 8a3038e8-9c9d-46f8-b184-66234a160f6f
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0008
techniques:
  - T1021
author: Tim Rauch, Elastic (idea)
date: '2022-09-27'
falsepositives:
  - Unknown
references:
  - https://www.elastic.co/guide/en/security/current/potential-remote-desktop-tunneling-detected.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_remote_desktop_tunneling.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Remote Desktop Tunneling
id: 8a3038e8-9c9d-46f8-b184-66234a160f6f
status: test
description: Detects potential use of an SSH utility to establish RDP over a reverse SSH Tunnel. This can be used by attackers to enable routing of network packets that would otherwise not reach their intended destination.
references:
    - https://www.elastic.co/guide/en/security/current/potential-remote-desktop-tunneling-detected.html
author: Tim Rauch, Elastic (idea)
date: 2022-09-27
tags:
    - attack.lateral-movement
    - attack.t1021
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: ':3389' # RDP port and usual SSH tunneling related switches in command line
    selection_opt:
        CommandLine|contains:
            - ' -L '
            - ' -P '
            - ' -R '
            - ' -pw '
            - ' -ssh '
    condition: all of selection*
falsepositives:
    - Unknown
level: medium
```
