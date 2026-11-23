---
title: Stop Windows Service Via Net.EXE
summary: Detects the stopping of a Windows service via the "net" utility.
sigma_id: 88872991-7445-4a22-90b2-a3adadb0e827
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0040
techniques:
  - T1489
author: Jakob Weinzettl, oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: '2023-03-05'
falsepositives:
  - There are many legitimate reasons to stop a service. This rule isn't looking for any suspicious behaviour in particular. Filter legitimate activity accordingly
references:
  - https://ss64.com/nt/net-service.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_net_stop_service.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Stop Windows Service Via Net.EXE
id: 88872991-7445-4a22-90b2-a3adadb0e827
related:
    - id: eb87818d-db5d-49cc-a987-d5da331fbd90
      type: obsolete
status: test
description: Detects the stopping of a Windows service via the "net" utility.
references:
    - https://ss64.com/nt/net-service.html
author: Jakob Weinzettl, oscd.community, Nasreddine Bencherchali (Nextron Systems)
date: 2023-03-05
tags:
    - attack.impact
    - attack.t1489
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - OriginalFileName:
              - 'net.exe'
              - 'net1.exe'
        - Image|endswith:
              - '\net.exe'
              - '\net1.exe'
    selection_cli:
        CommandLine|contains: ' stop '
    condition: all of selection_*
falsepositives:
    - There are many legitimate reasons to stop a service. This rule isn't looking for any suspicious behaviour in particular. Filter legitimate activity accordingly
level: low
```
