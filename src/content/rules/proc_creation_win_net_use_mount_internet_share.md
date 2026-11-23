---
title: Windows Internet Hosted WebDav Share Mount Via Net.EXE
summary: Detects when an internet hosted webdav share is mounted using the "net.exe" utility
sigma_id: 7e6237fe-3ddb-438f-9381-9bf9de5af8d0
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0008
techniques:
  - T1021.002
author: Nasreddine Bencherchali (Nextron Systems)
date: '2023-02-21'
modified: '2023-07-25'
falsepositives:
  - Unknown
references:
  - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_net_use_mount_internet_share.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Windows Internet Hosted WebDav Share Mount Via Net.EXE
id: 7e6237fe-3ddb-438f-9381-9bf9de5af8d0
status: test
description: Detects when an internet hosted webdav share is mounted using the "net.exe" utility
references:
    - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-02-21
modified: 2023-07-25
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
            - ' http'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
