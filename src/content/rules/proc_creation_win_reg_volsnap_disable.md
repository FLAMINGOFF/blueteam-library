---
title: Disabled Volume Snapshots
summary: Detects commands that temporarily turn off Volume Snapshots
sigma_id: dee4af55-1f22-4e1d-a9d2-4bdc7ecb472a
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1685
author: Florian Roth (Nextron Systems)
date: '2021-01-28'
modified: '2023-12-15'
falsepositives:
  - Legitimate administration
references:
  - https://twitter.com/0gtweet/status/1354766164166115331
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_reg_volsnap_disable.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Disabled Volume Snapshots
id: dee4af55-1f22-4e1d-a9d2-4bdc7ecb472a
status: test
description: Detects commands that temporarily turn off Volume Snapshots
references:
    - https://twitter.com/0gtweet/status/1354766164166115331
author: Florian Roth (Nextron Systems)
date: 2021-01-28
modified: 2023-12-15
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\Services\VSS\Diag'
            - '/d Disabled'
    condition: selection
falsepositives:
    - Legitimate administration
level: high
```
