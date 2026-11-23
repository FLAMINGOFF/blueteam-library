---
title: HackTool - CobaltStrike BOF Injection Pattern
summary: Detects a typical pattern of a CobaltStrike BOF which inject into other processes
sigma_id: 09706624-b7f6-455d-9d02-adee024cee1d
status: test
level: high
platform: windows
logsource: windows / process_access
tactics:
  - TA0002
  - TA0112
techniques:
  - T1106
  - T1685
author: Christian Burkard (Nextron Systems)
date: '2021-08-04'
modified: '2023-11-28'
falsepositives:
  - Unknown
references:
  - https://github.com/boku7/injectAmsiBypass
  - https://github.com/boku7/spawn
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_access/proc_access_win_hktl_cobaltstrike_bof_injection_pattern.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - CobaltStrike BOF Injection Pattern
id: 09706624-b7f6-455d-9d02-adee024cee1d
status: test
description: Detects a typical pattern of a CobaltStrike BOF which inject into other processes
references:
    - https://github.com/boku7/injectAmsiBypass
    - https://github.com/boku7/spawn
author: Christian Burkard (Nextron Systems)
date: 2021-08-04
modified: 2023-11-28
tags:
    - attack.execution
    - attack.defense-impairment
    - attack.t1106
    - attack.t1685
logsource:
    category: process_access
    product: windows
detection:
    selection:
        CallTrace|re: '^C:\\Windows\\SYSTEM32\\ntdll\.dll\+[a-z0-9]{4,6}\|C:\\Windows\\System32\\KERNELBASE\.dll\+[a-z0-9]{4,6}\|UNKNOWN\([A-Z0-9]{16}\)$'
        GrantedAccess:
            - '0x1028'
            - '0x1fffff'
    condition: selection
falsepositives:
    - Unknown
level: high
```
