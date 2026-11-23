---
title: Suspicious Process Parents
summary: Detects suspicious parent processes that should not have any children or should only have a single possible child program
sigma_id: cbec226f-63d9-4eca-9f52-dfb6652f24df
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1036
author: Florian Roth (Nextron Systems)
date: '2022-03-21'
modified: '2022-09-08'
falsepositives:
  - Unknown
references:
  - https://web.archive.org/web/20220731153253/https://twitter.com/x86matthew/status/1505476263464607744
  - https://svch0st.medium.com/stats-from-hunting-cobalt-strike-beacons-c17e56255f9b
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_parents.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Process Parents
id: cbec226f-63d9-4eca-9f52-dfb6652f24df
status: test
description: Detects suspicious parent processes that should not have any children or should only have a single possible child program
references:
    - https://web.archive.org/web/20220731153253/https://twitter.com/x86matthew/status/1505476263464607744
    - https://svch0st.medium.com/stats-from-hunting-cobalt-strike-beacons-c17e56255f9b
author: Florian Roth (Nextron Systems)
date: 2022-03-21
modified: 2022-09-08
tags:
    - attack.stealth
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\minesweeper.exe'
            - '\winver.exe'
            - '\bitsadmin.exe'
    selection_special:
        ParentImage|endswith:
            - '\csrss.exe'
            - '\certutil.exe'
         # - '\schtasks.exe'
            - '\eventvwr.exe'
            - '\calc.exe'
            - '\notepad.exe'
    filter_special:
        Image|endswith:
            - '\WerFault.exe'
            - '\wermgr.exe'
            - '\conhost.exe' # csrss.exe, certutil.exe
            - '\mmc.exe'     # eventvwr.exe
            - '\win32calc.exe' # calc.exe
            - '\notepad.exe'
    filter_null:
        Image: null
    condition: selection or ( selection_special and not 1 of filter_* )
falsepositives:
    - Unknown
level: high
```
