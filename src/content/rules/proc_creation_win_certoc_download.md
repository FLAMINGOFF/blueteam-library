---
title: File Download via CertOC.EXE
summary: Detects when a user downloads a file by using CertOC.exe
sigma_id: 70ad0861-d1fe-491c-a45f-fa48148a300d
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1105
author: Nasreddine Bencherchali (Nextron Systems)
date: '2022-05-16'
modified: '2023-10-18'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Certoc/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_certoc_download.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: File Download via CertOC.EXE
id: 70ad0861-d1fe-491c-a45f-fa48148a300d
related:
    - id: b86f6dea-0b2f-41f5-bdcc-a057bd19cd6a
      type: similar
status: test
description: Detects when a user downloads a file by using CertOC.exe
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Certoc/
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-05-16
modified: 2023-10-18
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\certoc.exe'
        - OriginalFileName: 'CertOC.exe'
    selection_cli:
        CommandLine|contains|all:
            - '-GetCACAPS'
            - 'http'
    condition: all of selection*
falsepositives:
    - Unknown
level: medium
```
