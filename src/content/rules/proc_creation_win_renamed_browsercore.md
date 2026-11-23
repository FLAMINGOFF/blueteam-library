---
title: Renamed BrowserCore.EXE Execution
summary: Detects process creation with a renamed BrowserCore.exe (used to extract Azure tokens)
sigma_id: 8a4519e8-e64a-40b6-ae85-ba8ad2177559
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1528
  - T1036.003
author: Max Altgelt (Nextron Systems)
date: '2022-06-02'
modified: '2023-02-03'
falsepositives:
  - Unknown
references:
  - https://twitter.com/mariuszbit/status/1531631015139102720
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_renamed_browsercore.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Renamed BrowserCore.EXE Execution
id: 8a4519e8-e64a-40b6-ae85-ba8ad2177559
status: test
description: Detects process creation with a renamed BrowserCore.exe (used to extract Azure tokens)
references:
    - https://twitter.com/mariuszbit/status/1531631015139102720
author: Max Altgelt (Nextron Systems)
date: 2022-06-02
modified: 2023-02-03
tags:
    - attack.credential-access
    - attack.stealth
    - attack.t1528
    - attack.t1036.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: BrowserCore.exe
    filter_realbrowsercore:
        Image|endswith: '\BrowserCore.exe'
    condition: selection and not 1 of filter_*
falsepositives:
    - Unknown
level: high
```
