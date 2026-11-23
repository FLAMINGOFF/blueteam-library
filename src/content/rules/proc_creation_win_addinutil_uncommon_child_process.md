---
title: Uncommon Child Process Of AddinUtil.EXE
summary: >-
  Detects uncommon child processes of the Add-In deployment cache updating utility (AddInutil.exe) which could be a sign of potential abuse of the binary to proxy execution via a custom Addins.Store
  payload.
sigma_id: b5746143-59d6-4603-8d06-acbd60e166ee
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218
author: Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri)
date: '2023-09-18'
falsepositives:
  - Unknown
references:
  - https://www.blue-prints.blog/content/blog/posts/lolbin/addinutil-lolbas.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_addinutil_uncommon_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Uncommon Child Process Of AddinUtil.EXE
id: b5746143-59d6-4603-8d06-acbd60e166ee
status: test
description: |
    Detects uncommon child processes of the Add-In deployment cache updating utility (AddInutil.exe) which could be a sign of potential abuse of the binary to proxy execution via a custom Addins.Store payload.
references:
    - https://www.blue-prints.blog/content/blog/posts/lolbin/addinutil-lolbas.html
author: Michael McKinley (@McKinleyMike), Tony Latteri (@TheLatteri)
date: 2023-09-18
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\addinutil.exe'
    filter_main_werfault:
        Image|endswith:
            - ':\Windows\System32\conhost.exe'
            - ':\Windows\System32\werfault.exe'
            - ':\Windows\SysWOW64\werfault.exe'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
```
