---
title: HackTool - F-Secure C3 Load by Rundll32
summary: F-Secure C3 produces DLLs with a default exported StartNodeRelay function.
sigma_id: b18c9d4c-fac9-4708-bd06-dd5bfacf200f
status: test
level: critical
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218.011
author: Alfie Champion (ajpc500)
date: '2021-06-02'
modified: '2023-03-05'
falsepositives:
  - Unknown
references:
  - https://github.com/FSecureLABS/C3/blob/11a081fd3be2aaf2a879f6b6e9a96ecdd24966ef/Src/NodeRelayDll/NodeRelayDll.cpp#L12
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_c3_rundll32_pattern.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - F-Secure C3 Load by Rundll32
id: b18c9d4c-fac9-4708-bd06-dd5bfacf200f
status: test
description: F-Secure C3 produces DLLs with a default exported StartNodeRelay function.
references:
    - https://github.com/FSecureLABS/C3/blob/11a081fd3be2aaf2a879f6b6e9a96ecdd24966ef/Src/NodeRelayDll/NodeRelayDll.cpp#L12
author: Alfie Champion (ajpc500)
date: 2021-06-02
modified: 2023-03-05
tags:
    - attack.stealth
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'rundll32.exe'
            - '.dll'
            - 'StartNodeRelay'
    condition: selection
falsepositives:
    - Unknown
level: critical
```
