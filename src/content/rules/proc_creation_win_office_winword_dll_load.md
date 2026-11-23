---
title: Potential Arbitrary DLL Load Using Winword
summary: Detects potential DLL sideloading using the Microsoft Office winword process via the '/l' flag.
sigma_id: f7375e28-5c14-432f-b8d1-1db26c832df3
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1202
author: Victor Sergeev, oscd.community
date: '2020-10-09'
modified: '2023-03-29'
falsepositives:
  - Unknown
references:
  - https://github.com/D4Vinci/One-Lin3r/blob/9fdfa5f0b9c698dfbd4cdfe7d2473192777ae1c6/one_lin3r/core/liners/windows/cmd/dll_loader_word.py
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_office_winword_dll_load.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Arbitrary DLL Load Using Winword
id: f7375e28-5c14-432f-b8d1-1db26c832df3
related:
    - id: 2621b3a6-3840-4810-ac14-a02426086171
      type: obsolete
status: test
description: Detects potential DLL sideloading using the Microsoft Office winword process via the '/l' flag.
references:
    - https://github.com/D4Vinci/One-Lin3r/blob/9fdfa5f0b9c698dfbd4cdfe7d2473192777ae1c6/one_lin3r/core/liners/windows/cmd/dll_loader_word.py
author: Victor Sergeev, oscd.community
date: 2020-10-09
modified: 2023-03-29
tags:
    - attack.stealth
    - attack.t1202
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\WINWORD.exe'
        - OriginalFileName: 'WinWord.exe'
    selection_dll:
        CommandLine|contains|all:
            - '/l '
            - '.dll'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
