---
title: Unmount Share Via Net.EXE
summary: Detects when when a mounted share is removed. Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation
sigma_id: cb7c4a03-2871-43c0-9bbb-18bbdb079896
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1070.005
author: oscd.community, @redcanary, Zach Stanford @svch0st
date: '2020-10-08'
modified: '2023-02-21'
falsepositives:
  - Administrators or Power users may remove their shares via cmd line
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.005/T1070.005.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_net_share_unmount.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Unmount Share Via Net.EXE
id: cb7c4a03-2871-43c0-9bbb-18bbdb079896
status: test
description: Detects when when a mounted share is removed. Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1070.005/T1070.005.md
author: oscd.community, @redcanary, Zach Stanford @svch0st
date: 2020-10-08
modified: 2023-02-21
tags:
    - attack.stealth
    - attack.t1070.005
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
            - 'share'
            - '/delete'
    condition: all of selection*
falsepositives:
    - Administrators or Power users may remove their shares via cmd line
level: low
```
