---
title: Potentially Suspicious Execution Of Regasm/Regsvcs From Uncommon Location
summary: Detects potentially suspicious execution of the Regasm/Regsvcs utilities from a potentially suspicious location
sigma_id: cc368ed0-2411-45dc-a222-510ace303cb2
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218.009
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-08-25'
modified: '2023-02-13'
falsepositives:
  - Unknown
references:
  - https://www.fortiguard.com/threat-signal-report/4718?s=09
  - https://lolbas-project.github.io/lolbas/Binaries/Regasm/
  - https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_regasm_regsvcs_uncommon_location_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potentially Suspicious Execution Of Regasm/Regsvcs From Uncommon Location
id: cc368ed0-2411-45dc-a222-510ace303cb2
related:
    - id: e9f8f8cc-07cc-4e81-b724-f387db9175e4
      type: derived
status: test
description: Detects potentially suspicious execution of the Regasm/Regsvcs utilities from a potentially suspicious location
references:
    - https://www.fortiguard.com/threat-signal-report/4718?s=09
    - https://lolbas-project.github.io/lolbas/Binaries/Regasm/
    - https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-25
modified: 2023-02-13
tags:
    - attack.stealth
    - attack.t1218.009
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\Regsvcs.exe'
              - '\Regasm.exe'
        - OriginalFileName:
              - 'RegSvcs.exe'
              - 'RegAsm.exe'
    selection_dir:
        CommandLine|contains:
            # Note: Add more potentially suspicious directories
            - '\AppData\Local\Temp\'
            - '\Microsoft\Windows\Start Menu\Programs\Startup\'
            - '\PerfLogs\'
            - '\Users\Public\'
            - '\Windows\Temp\'
            # - '\Desktop\'
            # - '\Downloads\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
