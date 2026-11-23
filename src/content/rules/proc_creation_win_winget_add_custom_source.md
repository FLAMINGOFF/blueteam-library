---
title: Add New Download Source To Winget
summary: Detects usage of winget to add new additional download sources
sigma_id: 05ebafc8-7aa2-4bcd-a269-2aec93f9e842
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-04-17'
falsepositives:
  - False positive are expected with legitimate sources
references:
  - https://learn.microsoft.com/en-us/windows/package-manager/winget/source
  - https://web.archive.org/web/20250828100901/https://github.com/nasbench/Misc-Research/tree/b9596e8109dcdb16ec353f316678927e507a5b8d/LOLBINs/Winget
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_winget_add_custom_source.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Add New Download Source To Winget
id: 05ebafc8-7aa2-4bcd-a269-2aec93f9e842
related:
    - id: 81a0ecb5-0a41-4ba1-b2ba-c944eb92bfa2
      type: similar
    - id: c15a46a0-07d4-4c87-b4b6-89207835a83b
      type: similar
status: test
description: Detects usage of winget to add new additional download sources
references:
    - https://learn.microsoft.com/en-us/windows/package-manager/winget/source
    - https://web.archive.org/web/20250828100901/https://github.com/nasbench/Misc-Research/tree/b9596e8109dcdb16ec353f316678927e507a5b8d/LOLBINs/Winget
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-04-17
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\winget.exe'
        - OriginalFileName: 'winget.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'source '
            - 'add '
    condition: all of selection_*
falsepositives:
    - False positive are expected with legitimate sources
level: medium
```
