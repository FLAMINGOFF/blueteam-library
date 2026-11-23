---
title: Potential MsiExec Masquerading
summary: Detects the execution of msiexec.exe from an uncommon directory
sigma_id: e22a6eb2-f8a5-44b5-8b44-a2dbd47b1144
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1036.005
author: Florian Roth (Nextron Systems)
date: '2019-11-14'
modified: '2026-10-31'
falsepositives:
  - Unknown
references:
  - https://web.archive.org/web/20191114000442/https://twitter.com/200_okay_/status/1194765831911215104
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_msiexec_masquerading.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential MsiExec Masquerading
id: e22a6eb2-f8a5-44b5-8b44-a2dbd47b1144
status: test
description: Detects the execution of msiexec.exe from an uncommon directory
references:
    - https://web.archive.org/web/20191114000442/https://twitter.com/200_okay_/status/1194765831911215104
author: Florian Roth (Nextron Systems)
date: 2019-11-14
modified: 2026-10-31
tags:
    - attack.stealth
    - attack.t1036.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\msiexec.exe'
        - OriginalFileName: 'msiexec.exe'
    filter:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Windows\WinSxS\'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
```
