---
title: Potential Mftrace.EXE Abuse
summary: Detects child processes of the "Trace log generation tool for Media Foundation Tools" (Mftrace.exe) which can abused to execute arbitrary binaries.
sigma_id: 3d48c9d3-1aa6-418d-98d3-8fd3c01a564e
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1127
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-06-09'
modified: '2023-08-03'
falsepositives:
  - Legitimate use for tracing purposes
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Mftrace/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_mftrace_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Mftrace.EXE Abuse
id: 3d48c9d3-1aa6-418d-98d3-8fd3c01a564e
status: test
description: Detects child processes of the "Trace log generation tool for Media Foundation Tools" (Mftrace.exe) which can abused to execute arbitrary binaries.
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Mftrace/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-06-09
modified: 2023-08-03
tags:
    - attack.execution
    - attack.stealth
    - attack.t1127
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\mftrace.exe'
    condition: selection
falsepositives:
    - Legitimate use for tracing purposes
level: medium
```
