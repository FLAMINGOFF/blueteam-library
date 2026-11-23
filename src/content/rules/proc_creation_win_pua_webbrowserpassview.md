---
title: PUA - WebBrowserPassView Execution
summary: >-
  Detects the execution of WebBrowserPassView.exe. A password recovery tool that reveals the passwords stored by the following Web browsers, Internet Explorer (Version 4.0 - 11.0), Mozilla Firefox
  (All Versions), Google Chrome, Safari, and Opera
sigma_id: d0dae994-26c6-4d2d-83b5-b3c8b79ae513
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1555.003
author: frack113
date: '2022-08-20'
modified: '2023-02-14'
falsepositives:
  - Legitimate use
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1555.003/T1555.003.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_pua_webbrowserpassview.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PUA - WebBrowserPassView Execution
id: d0dae994-26c6-4d2d-83b5-b3c8b79ae513
status: test
description: Detects the execution of WebBrowserPassView.exe. A password recovery tool that reveals the passwords stored by the following Web browsers, Internet Explorer (Version 4.0 - 11.0), Mozilla Firefox (All Versions), Google Chrome, Safari, and Opera
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/40b77d63808dd4f4eafb83949805636735a1fd15/atomics/T1555.003/T1555.003.md
author: frack113
date: 2022-08-20
modified: 2023-02-14
tags:
    - attack.credential-access
    - attack.t1555.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Description: 'Web Browser Password Viewer'
        - Image|endswith: '\WebBrowserPassView.exe'
    condition: selection
falsepositives:
    - Legitimate use
level: medium
```
