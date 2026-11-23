---
title: Use of UltraVNC Remote Access Software
summary: An adversary may use legitimate desktop support and remote access software,to establish an interactive command and control channel to target systems within networks
sigma_id: 145322e4-0fd3-486b-81ca-9addc75736d8
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1219.002
author: frack113
date: '2022-10-02'
falsepositives:
  - Legitimate use
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/9e5b12c4912c07562aec7500447b11fa3e17e254/atomics/T1219/T1219.md
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_ultravnc.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Use of UltraVNC Remote Access Software
id: 145322e4-0fd3-486b-81ca-9addc75736d8
status: test
description: An adversary may use legitimate desktop support and remote access software,to establish an interactive command and control channel to target systems within networks
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/9e5b12c4912c07562aec7500447b11fa3e17e254/atomics/T1219/T1219.md
author: frack113
date: 2022-10-02
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Description: VNCViewer
        - Product: UltraVNC VNCViewer
        - Company: UltraVNC
        - OriginalFileName: VNCViewer.exe
    condition: selection
falsepositives:
    - Legitimate use
level: medium
```
