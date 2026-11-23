---
title: Use of W32tm as Timer
summary: When configured with suitable command line arguments, w32tm can act as a delay mechanism
sigma_id: 6da2c9f5-7c53-401b-aacb-92c040ce1215
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
techniques:
  - T1124
author: frack113
date: '2022-09-25'
falsepositives:
  - Legitimate use
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/d0dad62dbcae9c60c519368e82c196a3db577055/atomics/T1124/T1124.md
  - https://blogs.blackberry.com/en/2022/05/dirty-deeds-done-dirt-cheap-russian-rat-offers-backdoor-bargains
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_w32tm.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Use of W32tm as Timer
id: 6da2c9f5-7c53-401b-aacb-92c040ce1215
status: test
description: When configured with suitable command line arguments, w32tm can act as a delay mechanism
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/d0dad62dbcae9c60c519368e82c196a3db577055/atomics/T1124/T1124.md
    - https://blogs.blackberry.com/en/2022/05/dirty-deeds-done-dirt-cheap-russian-rat-offers-backdoor-bargains
author: frack113
date: 2022-09-25
tags:
    - attack.discovery
    - attack.t1124
logsource:
    category: process_creation
    product: windows
detection:
    selection_w32tm:
        - Image|endswith: '\w32tm.exe'
        - OriginalFileName: 'w32time.dll'
    selection_cmd:
        CommandLine|contains|all:
            - '/stripchart'
            - '/computer:'
            - '/period:'
            - '/dataonly'
            - '/samples:'
    condition: all of selection_*
falsepositives:
    - Legitimate use
level: high
```
