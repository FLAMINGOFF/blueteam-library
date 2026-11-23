---
title: Renamed SysInternals DebugView Execution
summary: Detects suspicious renamed SysInternals DebugView execution
sigma_id: cd764533-2e07-40d6-a718-cfeec7f2da7f
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0042
techniques:
  - T1588.002
author: Florian Roth (Nextron Systems)
date: '2020-05-28'
modified: '2023-02-14'
falsepositives:
  - Unknown
references:
  - https://www.epicturla.com/blog/sysinturla
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_sysinternals_debugview.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed SysInternals DebugView Execution
id: cd764533-2e07-40d6-a718-cfeec7f2da7f
status: test
description: Detects suspicious renamed SysInternals DebugView execution
references:
    - https://www.epicturla.com/blog/sysinturla
author: Florian Roth (Nextron Systems)
date: 2020-05-28
modified: 2023-02-14
tags:
    - attack.resource-development
    - attack.t1588.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Product: 'Sysinternals DebugView'
    filter:
        OriginalFileName: 'Dbgview.exe'
        Image|endswith: '\Dbgview.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
