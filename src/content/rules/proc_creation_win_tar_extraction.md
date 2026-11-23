---
title: Compressed File Extraction Via Tar.EXE
summary: |-
  Detects execution of "tar.exe" in order to extract compressed file.
  Adversaries may abuse various utilities in order to decompress data to avoid detection.
sigma_id: bf361876-6620-407a-812f-bfe11e51e924
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
author: AdmU3
date: '2023-12-19'
falsepositives:
  - Likely
references:
  - https://unit42.paloaltonetworks.com/chromeloader-malware/
  - https://lolbas-project.github.io/lolbas/Binaries/Tar/
  - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/cicada-apt10-japan-espionage
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_tar_extraction.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Compressed File Extraction Via Tar.EXE
id: bf361876-6620-407a-812f-bfe11e51e924
status: test
description: |
    Detects execution of "tar.exe" in order to extract compressed file.
    Adversaries may abuse various utilities in order to decompress data to avoid detection.
references:
    - https://unit42.paloaltonetworks.com/chromeloader-malware/
    - https://lolbas-project.github.io/lolbas/Binaries/Tar/
    - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/cicada-apt10-japan-espionage
author: AdmU3
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
    selection_extract:
        CommandLine|contains: '-x'
    condition: all of selection_*
falsepositives:
    - Likely
level: low
```
