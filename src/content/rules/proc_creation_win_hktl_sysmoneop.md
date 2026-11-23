---
title: HackTool - SysmonEOP Execution
summary: Detects the execution of the PoC that can be used to exploit Sysmon CVE-2022-41120
sigma_id: 8a7e90c5-fe6e-45dc-889e-057fe4378bd9
status: test
level: critical
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
techniques:
  - T1068
author: Florian Roth (Nextron Systems)
date: '2022-12-04'
modified: '2024-11-23'
falsepositives:
  - Unlikely
references:
  - https://github.com/Wh04m1001/SysmonEoP
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_sysmoneop.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - SysmonEOP Execution
id: 8a7e90c5-fe6e-45dc-889e-057fe4378bd9
status: test
description: Detects the execution of the PoC that can be used to exploit Sysmon CVE-2022-41120
references:
    - https://github.com/Wh04m1001/SysmonEoP
author: Florian Roth (Nextron Systems)
date: 2022-12-04
modified: 2024-11-23
tags:
    - cve.2022-41120
    - attack.t1068
    - attack.privilege-escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\SysmonEOP.exe'
    selection_hash:
        Hashes|contains:
            - 'IMPHASH=22F4089EB8ABA31E1BB162C6D9BF72E5'
            - 'IMPHASH=5123FA4C4384D431CD0D893EEB49BBEC'
    condition: 1 of selection_*
falsepositives:
    - Unlikely
level: critical
```
