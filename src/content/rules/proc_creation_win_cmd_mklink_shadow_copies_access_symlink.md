---
title: VolumeShadowCopy Symlink Creation Via Mklink
summary: Shadow Copies storage symbolic link creation using operating systems utilities
sigma_id: 40b19fa6-d835-400c-b301-41f3a2baacaf
status: stable
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1003.002
  - T1003.003
author: Teymur Kheirkhabarov, oscd.community
date: '2019-10-22'
modified: '2023-03-06'
falsepositives:
  - Legitimate administrator working with shadow copies, access for backup purposes
references:
  - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_cmd_mklink_shadow_copies_access_symlink.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: VolumeShadowCopy Symlink Creation Via Mklink
id: 40b19fa6-d835-400c-b301-41f3a2baacaf
status: stable
description: Shadow Copies storage symbolic link creation using operating systems utilities
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
author: Teymur Kheirkhabarov, oscd.community
date: 2019-10-22
modified: 2023-03-06
tags:
    - attack.credential-access
    - attack.t1003.002
    - attack.t1003.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'mklink'
            - 'HarddiskVolumeShadowCopy'
    condition: selection
falsepositives:
    - Legitimate administrator working with shadow copies, access for backup purposes
level: high
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_cmd_mklink_shadow_copies_access_symlink/info.yml
```
