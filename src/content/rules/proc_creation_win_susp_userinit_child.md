---
title: Suspicious Userinit Child Process
summary: Detects a suspicious child process of userinit
sigma_id: b655a06a-31c0-477a-95c2-3726b83d649d
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0005
techniques:
  - T1055
author: Florian Roth (Nextron Systems), Samir Bousseaden (idea)
date: '2019-06-17'
modified: '2025-10-17'
falsepositives:
  - Administrative scripts
references:
  - https://twitter.com/SBousseaden/status/1139811587760562176
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_userinit_child.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Userinit Child Process
id: b655a06a-31c0-477a-95c2-3726b83d649d
status: test
description: Detects a suspicious child process of userinit
references:
    - https://twitter.com/SBousseaden/status/1139811587760562176
author: Florian Roth (Nextron Systems), Samir Bousseaden (idea)
date: 2019-06-17
modified: 2025-10-17
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\userinit.exe'
    filter_main_netlogon:
        CommandLine|contains: '\netlogon\'
    filter_main_explorer:
        - Image|endswith: '\explorer.exe'
        - OriginalFileName: 'explorer.exe'
        - CommandLine: 'C:\Windows\Explorer.EXE'
    filter_main_null:
        Image: null
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Administrative scripts
level: medium
```
