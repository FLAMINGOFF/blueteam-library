---
title: Renamed Vmnat.exe Execution
summary: Detects renamed vmnat.exe or portable version that can be used for DLL side-loading
sigma_id: 7b4f794b-590a-4ad4-ba18-7964a2832205
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
  - TA0002
  - TA0005
techniques:
  - T1574.001
author: elhoim
date: '2022-09-09'
modified: '2023-02-03'
falsepositives:
  - Unknown
references:
  - https://twitter.com/malmoeb/status/1525901219247845376
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_vmnat.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed Vmnat.exe Execution
id: 7b4f794b-590a-4ad4-ba18-7964a2832205
status: test
description: Detects renamed vmnat.exe or portable version that can be used for DLL side-loading
references:
    - https://twitter.com/malmoeb/status/1525901219247845376
author: elhoim
date: 2022-09-09
modified: 2023-02-03
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.stealth
    - attack.t1574.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: 'vmnat.exe'
    filter_rename:
        Image|endswith: 'vmnat.exe'
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
level: high
```
