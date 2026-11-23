---
title: Arbitrary File Download Via MSPUB.EXE
summary: Detects usage of "MSPUB" (Microsoft Publisher) to download arbitrary files
sigma_id: 3b3c7f55-f771-4dd6-8a6e-08d057a17caf
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
modified: '2023-02-08'
falsepositives:
  - Unknown
references:
  - https://github.com/LOLBAS-Project/LOLBAS/pull/238/files
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_mspub_download.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Arbitrary File Download Via MSPUB.EXE
id: 3b3c7f55-f771-4dd6-8a6e-08d057a17caf
status: test
description: Detects usage of "MSPUB" (Microsoft Publisher) to download arbitrary files
references:
    - https://github.com/LOLBAS-Project/LOLBAS/pull/238/files
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-08-19
modified: 2023-02-08
tags:
    - attack.execution
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\MSPUB.exe'
        - OriginalFileName: 'MSPUB.exe'
    selection_cli:
        CommandLine|contains:
            - 'ftp://'
            - 'http://'
            - 'https://'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
