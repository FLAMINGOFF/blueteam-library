---
title: Arbitrary File Download Via MSOHTMED.EXE
summary: Detects usage of "MSOHTMED" to download arbitrary files
sigma_id: 459f2f98-397b-4a4a-9f47-6a5ec2f1c69d
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1218
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-08-19'
modified: '2023-11-09'
falsepositives:
  - Unknown
references:
  - https://github.com/LOLBAS-Project/LOLBAS/pull/238/files
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_msohtmed_download.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Arbitrary File Download Via MSOHTMED.EXE
id: 459f2f98-397b-4a4a-9f47-6a5ec2f1c69d
status: test
description: Detects usage of "MSOHTMED" to download arbitrary files
references:
    - https://github.com/LOLBAS-Project/LOLBAS/pull/238/files
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
        - Image|endswith: '\MSOHTMED.exe'
        - OriginalFileName: 'MsoHtmEd.exe'
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
