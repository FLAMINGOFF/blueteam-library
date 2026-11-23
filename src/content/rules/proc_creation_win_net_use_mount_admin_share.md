---
title: Windows Admin Share Mount Via Net.EXE
summary: Detects when an admin share is mounted using net.exe
sigma_id: 3abd6094-7027-475f-9630-8ab9be7b9725
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0008
techniques:
  - T1021.002
author: oscd.community, Teymur Kheirkhabarov @HeirhabarovT, Zach Stanford @svch0st, wagga
date: '2020-10-05'
modified: '2023-02-21'
falsepositives:
  - Administrators
references:
  - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_net_use_mount_admin_share.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Windows Admin Share Mount Via Net.EXE
id: 3abd6094-7027-475f-9630-8ab9be7b9725
related:
    - id: f117933c-980c-4f78-b384-e3d838111165
      type: similar
status: test
description: Detects when an admin share is mounted using net.exe
references:
    - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view
author: oscd.community, Teymur Kheirkhabarov @HeirhabarovT, Zach Stanford @svch0st, wagga
date: 2020-10-05
modified: 2023-02-21
tags:
    - attack.lateral-movement
    - attack.t1021.002
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\net.exe'
              - '\net1.exe'
        - OriginalFileName:
              - 'net.exe'
              - 'net1.exe'
    selection_cli:
        CommandLine|contains|all:
            - ' use '
            - ' \\\\*\\*$'
    condition: all of selection_*
falsepositives:
    - Administrators
level: medium
```
