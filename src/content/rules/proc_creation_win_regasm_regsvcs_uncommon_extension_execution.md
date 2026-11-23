---
title: Potentially Suspicious Execution Of Regasm/Regsvcs With Uncommon Extension
summary: Detects potentially suspicious execution of the Regasm/Regsvcs utilities with an uncommon extension.
sigma_id: e9f8f8cc-07cc-4e81-b724-f387db9175e4
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218.009
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-02-13'
falsepositives:
  - Unknown
references:
  - https://www.fortiguard.com/threat-signal-report/4718?s=09
  - https://lolbas-project.github.io/lolbas/Binaries/Regasm/
  - https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_regasm_regsvcs_uncommon_extension_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potentially Suspicious Execution Of Regasm/Regsvcs With Uncommon Extension
id: e9f8f8cc-07cc-4e81-b724-f387db9175e4
related:
    - id: cc368ed0-2411-45dc-a222-510ace303cb2
      type: derived
status: test
description: Detects potentially suspicious execution of the Regasm/Regsvcs utilities with an uncommon extension.
references:
    - https://www.fortiguard.com/threat-signal-report/4718?s=09
    - https://lolbas-project.github.io/lolbas/Binaries/Regasm/
    - https://lolbas-project.github.io/lolbas/Binaries/Regsvcs/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-02-13
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
    selection_extension:
        CommandLine|contains:
            # Note: Add more potentially uncommon extensions
            - '.dat'
            - '.gif'
            - '.jpeg'
            - '.jpg'
            - '.png'
            - '.txt'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
