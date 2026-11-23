---
title: Conhost.exe CommandLine Path Traversal
summary: detects the usage of path traversal in conhost.exe indicating possible command/argument confusion/hijacking
sigma_id: ee5e119b-1f75-4b34-add8-3be976961e39
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059.003
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-06-14'
falsepositives:
  - Unlikely
references:
  - https://pentestlab.blog/2020/07/06/indirect-command-execution/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_conhost_path_traversal.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Conhost.exe CommandLine Path Traversal
id: ee5e119b-1f75-4b34-add8-3be976961e39
status: test
description: detects the usage of path traversal in conhost.exe indicating possible command/argument confusion/hijacking
references:
    - https://pentestlab.blog/2020/07/06/indirect-command-execution/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-14
tags:
    - attack.execution
    - attack.t1059.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentCommandLine|contains: 'conhost'
        CommandLine|contains: '/../../'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
