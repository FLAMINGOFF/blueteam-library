---
title: Compressed File Creation Via Tar.EXE
summary: |-
  Detects execution of "tar.exe" in order to create a compressed file.
  Adversaries may abuse various utilities to compress or encrypt data before exfiltration.
sigma_id: 418a3163-3247-4b7b-9933-dcfcb7c52ea9
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0009
  - TA0010
techniques:
  - T1560
  - T1560.001
author: Nasreddine Bencherchali (Nextron Systems), AdmU3
date: '2023-12-19'
falsepositives:
  - Likely
references:
  - https://unit42.paloaltonetworks.com/chromeloader-malware/
  - https://lolbas-project.github.io/lolbas/Binaries/Tar/
  - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/cicada-apt10-japan-espionage
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_tar_compression.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Compressed File Creation Via Tar.EXE
id: 418a3163-3247-4b7b-9933-dcfcb7c52ea9
status: test
description: |
    Detects execution of "tar.exe" in order to create a compressed file.
    Adversaries may abuse various utilities to compress or encrypt data before exfiltration.
references:
    - https://unit42.paloaltonetworks.com/chromeloader-malware/
    - https://lolbas-project.github.io/lolbas/Binaries/Tar/
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/cicada-apt10-japan-espionage
author: Nasreddine Bencherchali (Nextron Systems), AdmU3
date: 2023-12-19
tags:
    - attack.collection
    - attack.exfiltration
    - attack.t1560
    - attack.t1560.001
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\tar.exe'
        - OriginalFileName: 'bsdtar'
    selection_create:
        CommandLine|contains:
            - '-c'
            - '-r'
            - '-u'
    condition: all of selection_*
falsepositives:
    - Likely
level: low
```
