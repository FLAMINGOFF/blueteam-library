---
title: Findstr Launching .lnk File
summary: Detects usage of findstr to identify and execute a lnk file as seen within the HHS redirect attack
sigma_id: 33339be3-148b-4e16-af56-ad16ec6c7e7b
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1036
  - T1202
  - T1027.003
author: Trent Liffick
date: '2020-05-01'
modified: '2024-01-15'
falsepositives:
  - Unknown
references:
  - https://www.bleepingcomputer.com/news/security/hhsgov-open-redirect-used-by-coronavirus-phishing-to-spread-malware/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_findstr_lnk.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Findstr Launching .lnk File
id: 33339be3-148b-4e16-af56-ad16ec6c7e7b
status: test
description: Detects usage of findstr to identify and execute a lnk file as seen within the HHS redirect attack
references:
    - https://www.bleepingcomputer.com/news/security/hhsgov-open-redirect-used-by-coronavirus-phishing-to-spread-malware/
author: Trent Liffick
date: 2020-05-01
modified: 2024-01-15
tags:
    - attack.stealth
    - attack.t1036
    - attack.t1202
    - attack.t1027.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith:
              - '\find.exe'
              - '\findstr.exe'
        - OriginalFileName:
              - 'FIND.EXE'
              - 'FINDSTR.EXE'
    selection_cli:
        CommandLine|endswith:
            - '.lnk'
            - '.lnk"'
            - ".lnk'"
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
