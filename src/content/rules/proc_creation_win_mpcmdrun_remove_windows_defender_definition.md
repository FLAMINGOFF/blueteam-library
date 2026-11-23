---
title: Windows Defender Definition Files Removed
summary: Adversaries may disable security tools to avoid possible detection of their tools and activities by removing Windows Defender Definition Files
sigma_id: 9719a8aa-401c-41af-8108-ced7ec9cd75c
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1685
author: frack113
date: '2021-07-07'
modified: '2023-07-18'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
  - https://unit42.paloaltonetworks.com/unit42-gorgon-group-slithering-nation-state-cybercrime/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_mpcmdrun_remove_windows_defender_definition.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Windows Defender Definition Files Removed
id: 9719a8aa-401c-41af-8108-ced7ec9cd75c
status: test
description: Adversaries may disable security tools to avoid possible detection of their tools and activities by removing Windows Defender Definition Files
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
    - https://unit42.paloaltonetworks.com/unit42-gorgon-group-slithering-nation-state-cybercrime/
author: frack113
date: 2021-07-07
modified: 2023-07-18
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\MpCmdRun.exe'
        - OriginalFileName: MpCmdRun.exe
    selection_cli:
        CommandLine|contains|all:
            - ' -RemoveDefinitions'
            - ' -All'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
