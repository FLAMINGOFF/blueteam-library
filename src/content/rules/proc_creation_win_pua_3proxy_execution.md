---
title: PUA - 3Proxy Execution
summary: Detects the use of 3proxy, a tiny free proxy server
sigma_id: f38a82d2-fba3-4781-b549-525efbec8506
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1572
author: Florian Roth (Nextron Systems)
date: '2022-09-13'
modified: '2023-02-21'
falsepositives:
  - Administrative activity
references:
  - https://github.com/3proxy/3proxy
  - https://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_pua_3proxy_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PUA - 3Proxy Execution
id: f38a82d2-fba3-4781-b549-525efbec8506
status: test
description: Detects the use of 3proxy, a tiny free proxy server
references:
    - https://github.com/3proxy/3proxy
    - https://blog.talosintelligence.com/2022/09/lazarus-three-rats.html
author: Florian Roth (Nextron Systems)
date: 2022-09-13
modified: 2023-02-21
tags:
    - attack.command-and-control
    - attack.t1572
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith: '\3proxy.exe'
    selection_pe:
        Description: '3proxy - tiny proxy server'
    selection_params: # param combos seen in the wild
        CommandLine|contains: '.exe -i127.0.0.1 -p'
    condition: 1 of selection_*
falsepositives:
    - Administrative activity
level: high
```
