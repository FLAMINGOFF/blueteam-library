---
title: Compress Data and Lock With Password for Exfiltration With 7-ZIP
summary: An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party utilities
sigma_id: 9fbf5927-5261-4284-a71d-f681029ea574
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0009
techniques:
  - T1560.001
author: frack113
date: '2021-07-27'
modified: '2026-06-05'
falsepositives:
  - Legitimate activity is expected since compressing files with a password is common.
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1560.001/T1560.001.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_7zip_password_compression.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Compress Data and Lock With Password for Exfiltration With 7-ZIP
id: 9fbf5927-5261-4284-a71d-f681029ea574
status: test
description: An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party utilities
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1560.001/T1560.001.md
author: frack113
date: 2021-07-27
modified: 2026-06-05
tags:
    - attack.collection
    - attack.t1560.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Description|contains: '7-Zip'
        - Image|endswith:
              - '\7z.exe'
              - '\7zr.exe'
              - '\7za.exe'
        - OriginalFileName:
              - '7z.exe'
              - '7za.exe'
              - '7zr.exe'
    selection_password:
        CommandLine|contains: ' -p'
    selection_action:
        CommandLine|contains:
            - ' a '
            - ' u '
    condition: all of selection_*
falsepositives:
    - Legitimate activity is expected since compressing files with a password is common.
level: medium
```
