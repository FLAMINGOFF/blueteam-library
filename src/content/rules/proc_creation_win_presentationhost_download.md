---
title: Arbitrary File Download Via PresentationHost.EXE
summary: Detects usage of "PresentationHost" which is a utility that runs ".xbap" (Browser Applications) files to download arbitrary files
sigma_id: b124ddf4-778d-418e-907f-6dd3fc0d31cd
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1218
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-08-19'
modified: '2023-11-09'
falsepositives:
  - Unknown
references:
  - https://github.com/LOLBAS-Project/LOLBAS/pull/239/files
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_presentationhost_download.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Arbitrary File Download Via PresentationHost.EXE
id: b124ddf4-778d-418e-907f-6dd3fc0d31cd
status: test
description: Detects usage of "PresentationHost" which is a utility that runs ".xbap" (Browser Applications) files to download arbitrary files
references:
    - https://github.com/LOLBAS-Project/LOLBAS/pull/239/files
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-19
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
        CommandLine|contains:
            - 'http://'
            - 'https://'
            - 'ftp://'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
