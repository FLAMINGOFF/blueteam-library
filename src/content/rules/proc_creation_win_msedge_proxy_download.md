---
title: Arbitrary File Download Via MSEDGE_PROXY.EXE
summary: Detects usage of "msedge_proxy.exe" to download arbitrary files
sigma_id: e84d89c4-f544-41ca-a6af-4b92fd38b023
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1218
author: Swachchhanda Shrawan Poudel
date: '2023-11-09'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/msedge_proxy/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_msedge_proxy_download.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Arbitrary File Download Via MSEDGE_PROXY.EXE
id: e84d89c4-f544-41ca-a6af-4b92fd38b023
status: test
description: Detects usage of "msedge_proxy.exe" to download arbitrary files
references:
    - https://lolbas-project.github.io/lolbas/Binaries/msedge_proxy/
author: Swachchhanda Shrawan Poudel
date: 2023-11-09
tags:
    - attack.execution
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\msedge_proxy.exe'
        - OriginalFileName: 'msedge_proxy.exe'
    selection_cli:
        CommandLine|contains:
            - 'http://'
            - 'https://'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
