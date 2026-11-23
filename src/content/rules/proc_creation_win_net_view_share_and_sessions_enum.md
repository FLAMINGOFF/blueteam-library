---
title: Share And Session Enumeration Using Net.EXE
summary: Detects attempts to enumerate file shares, printer shares and sessions using "net.exe" with the "view" flag.
sigma_id: 62510e69-616b-4078-b371-847da438cc03
status: stable
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1018
author: Endgame, JHasenbusch (ported for oscd.community)
date: '2018-10-30'
modified: '2023-02-21'
falsepositives:
  - Legitimate use of net.exe utility by legitimate user
references:
  - https://eqllib.readthedocs.io/en/latest/analytics/b8a94d2f-dc75-4630-9d73-1edc6bd26fff.html
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1018/T1018.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_net_view_share_and_sessions_enum.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Share And Session Enumeration Using Net.EXE
id: 62510e69-616b-4078-b371-847da438cc03
status: stable
description: Detects attempts to enumerate file shares, printer shares and sessions using "net.exe" with the "view" flag.
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/b8a94d2f-dc75-4630-9d73-1edc6bd26fff.html
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1018/T1018.md
author: Endgame, JHasenbusch (ported for oscd.community)
date: 2018-10-30
modified: 2023-02-21
tags:
    - attack.discovery
    - attack.t1018
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\net.exe'
              - '\net1.exe'
        - OriginalFileName:
              - 'net.exe'
              - 'net1.exe'
    selection_cli:
        CommandLine|contains: 'view'
    filter:
        CommandLine|contains: '\\\\'
    condition: all of selection_* and not filter
falsepositives:
    - Legitimate use of net.exe utility by legitimate user
level: low
```
