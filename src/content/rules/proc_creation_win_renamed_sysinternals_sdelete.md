---
title: Renamed Sysinternals Sdelete Execution
summary: Detects the use of a renamed SysInternals Sdelete, which is something an administrator shouldn't do (the renaming)
sigma_id: c1d867fe-8d95-4487-aab4-e53f2d339f90
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0040
techniques:
  - T1485
author: Florian Roth (Nextron Systems)
date: '2022-09-06'
modified: '2026-06-29'
falsepositives:
  - System administrator usage
references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1485/T1485.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_sysinternals_sdelete.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed Sysinternals Sdelete Execution
id: c1d867fe-8d95-4487-aab4-e53f2d339f90
status: test
description: Detects the use of a renamed SysInternals Sdelete, which is something an administrator shouldn't do (the renaming)
references:
    - https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1485/T1485.md
author: Florian Roth (Nextron Systems)
date: 2022-09-06
modified: 2026-06-29
tags:
    - attack.impact
    - attack.t1485
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'sdelete.exe'
    filter:
        Image|endswith:
            - '\sdelete.exe'
            - '\sdelete64.exe'
            - '\sdelete64a.exe'
    condition: selection and not filter
falsepositives:
    - System administrator usage
level: high
```
