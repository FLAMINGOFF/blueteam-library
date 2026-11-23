---
title: XBAP Execution From Uncommon Locations Via PresentationHost.EXE
summary: Detects the execution of ".xbap" (Browser Applications) files via PresentationHost.EXE from an uncommon location. These files can be abused to run malicious ".xbap" files any bypass AWL
sigma_id: d22e2925-cfd8-463f-96f6-89cec9d9bc5f
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1218
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-07-01'
modified: '2023-11-09'
falsepositives:
  - Legitimate ".xbap" being executed via "PresentationHost"
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Presentationhost/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_presentationhost_uncommon_location_exec.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: XBAP Execution From Uncommon Locations Via PresentationHost.EXE
id: d22e2925-cfd8-463f-96f6-89cec9d9bc5f
status: test
description: |
    Detects the execution of ".xbap" (Browser Applications) files via PresentationHost.EXE from an uncommon location. These files can be abused to run malicious ".xbap" files any bypass AWL
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Presentationhost/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-07-01
modified: 2023-11-09
tags:
    - attack.execution
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\presentationhost.exe'
        - OriginalFileName: 'PresentationHost.exe'
    selection_cli:
        CommandLine|contains: '.xbap'
    filter_main_generic:
        CommandLine|contains: # Filter out legitimate locations if you find them
            - ' C:\Windows\'
            - ' C:\Program Files'
    condition: all of selection* and not 1 of filter_main_*
falsepositives:
    - Legitimate ".xbap" being executed via "PresentationHost"
level: medium
```
