---
title: Renamed Remote Utilities RAT (RURAT) Execution
summary: Detects execution of renamed Remote Utilities (RURAT) via Product PE header field
sigma_id: 9ef27c24-4903-4192-881a-3adde7ff92a5
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0009
  - TA0011
  - TA0007
  - TA0005
techniques: []
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-09-19'
modified: '2023-02-03'
falsepositives:
  - Unknown
references:
  - https://redcanary.com/blog/misbehaving-rats/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_rurat.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed Remote Utilities RAT (RURAT) Execution
id: 9ef27c24-4903-4192-881a-3adde7ff92a5
status: test
description: Detects execution of renamed Remote Utilities (RURAT) via Product PE header field
references:
    - https://redcanary.com/blog/misbehaving-rats/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-09-19
modified: 2023-02-03
tags:
    - attack.collection
    - attack.command-and-control
    - attack.discovery
    - attack.stealth
    - attack.s0592
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Product: 'Remote Utilities'
    filter:
        Image|endswith:
            - '\rutserv.exe'
            - '\rfusclient.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
```
