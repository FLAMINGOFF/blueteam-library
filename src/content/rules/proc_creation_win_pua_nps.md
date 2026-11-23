---
title: PUA - NPS Tunneling Tool Execution
summary: Detects the use of NPS, a port forwarding and intranet penetration proxy server
sigma_id: 68d37776-61db-42f5-bf54-27e87072d17e
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1090
author: Florian Roth (Nextron Systems)
date: '2022-10-08'
modified: '2024-11-23'
falsepositives:
  - Legitimate use
references:
  - https://github.com/ehang-io/nps
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_pua_nps.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PUA - NPS Tunneling Tool Execution
id: 68d37776-61db-42f5-bf54-27e87072d17e
status: test
description: Detects the use of NPS, a port forwarding and intranet penetration proxy server
references:
    - https://github.com/ehang-io/nps
author: Florian Roth (Nextron Systems)
date: 2022-10-08
modified: 2024-11-23
tags:
    - attack.command-and-control
    - attack.t1090
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\npc.exe'
    selection_cli_1:
        CommandLine|contains|all:
            - ' -server='
            - ' -vkey='
            - ' -password='
    selection_cli_2:
        CommandLine|contains: ' -config=npc'
    selection_hashes:
        # v0.26.10
        Hashes|contains:
            - "MD5=AE8ACF66BFE3A44148964048B826D005"
            - "SHA1=CEA49E9B9B67F3A13AD0BE1C2655293EA3C18181"
            - "SHA256=5A456283392FFCEEEACA3D3426C306EB470304637520D72FED1CC1FEBBBD6856"
    condition: 1 of selection_*
falsepositives:
    - Legitimate use
level: high
```
