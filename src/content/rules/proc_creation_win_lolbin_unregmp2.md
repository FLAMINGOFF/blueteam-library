---
title: Lolbin Unregmp2.exe Use As Proxy
summary: Detect usage of the "unregmp2.exe" binary as a proxy to launch a custom version of "wmpnscfg.exe"
sigma_id: 727454c0-d851-48b0-8b89-385611ab0704
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218
author: frack113
date: '2022-12-29'
modified: '2024-06-04'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Unregmp2/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_unregmp2.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Lolbin Unregmp2.exe Use As Proxy
id: 727454c0-d851-48b0-8b89-385611ab0704
status: test
description: Detect usage of the "unregmp2.exe" binary as a proxy to launch a custom version of "wmpnscfg.exe"
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Unregmp2/
author: frack113
date: 2022-12-29
modified: 2024-06-04
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\unregmp2.exe'
        - OriginalFileName: 'unregmp2.exe'
    selection_cmd:
        CommandLine|contains|windash: ' /HideWMP'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
