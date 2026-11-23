---
title: Execution via stordiag.exe
summary: Detects the use of stordiag.exe to execute schtasks.exe systeminfo.exe and fltmc.exe
sigma_id: 961e0abb-1b1e-4c84-a453-aafe56ad0d34
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218
author: Austin Songer (@austinsonger)
date: '2021-10-21'
modified: '2022-12-25'
falsepositives:
  - Legitimate usage of stordiag.exe.
references:
  - https://strontic.github.io/xcyclopedia/library/stordiag.exe-1F08FC87C373673944F6A7E8B18CD845.html
  - https://twitter.com/eral4m/status/1451112385041911809
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_stordiag_susp_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Execution via stordiag.exe
id: 961e0abb-1b1e-4c84-a453-aafe56ad0d34
status: test
description: Detects the use of stordiag.exe to execute schtasks.exe systeminfo.exe and fltmc.exe
references:
    - https://strontic.github.io/xcyclopedia/library/stordiag.exe-1F08FC87C373673944F6A7E8B18CD845.html
    - https://twitter.com/eral4m/status/1451112385041911809
author: Austin Songer (@austinsonger)
date: 2021-10-21
modified: 2022-12-25
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\stordiag.exe'
        Image|endswith:
            - '\schtasks.exe'
            - '\systeminfo.exe'
            - '\fltmc.exe'
    filter:
        ParentImage|startswith: # as first is "Copy c:\windows\system32\stordiag.exe to a folder"
            - 'c:\windows\system32\'
            - 'c:\windows\syswow64\'
    condition: selection and not filter
falsepositives:
    - Legitimate usage of stordiag.exe.
level: high
```
