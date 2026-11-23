---
title: Touch Suspicious Service File
summary: Detects usage of the "touch" process in service file.
sigma_id: 31545105-3444-4584-bebf-c466353230d2
status: test
level: medium
platform: linux
logsource: linux / process_creation
tactics: []
techniques:
  - T1070.006
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: '2023-01-11'
falsepositives:
  - Admin changing date of files.
references:
  - https://blogs.blackberry.com/
  - https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/linux/process_creation/proc_creation_lnx_touch_susp.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Touch Suspicious Service File
id: 31545105-3444-4584-bebf-c466353230d2
status: test
description: Detects usage of the "touch" process in service file.
references:
    - https://blogs.blackberry.com/
    - https://twitter.com/Joseliyo_Jstnk/status/1620131033474822144
author: Joseliyo Sanchez, @Joseliyo_Jstnk
date: 2023-01-11
tags:
    - attack.stealth
    - attack.t1070.006
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith: '/touch'
        CommandLine|contains: ' -t '
        CommandLine|endswith: '.service'
    condition: selection
falsepositives:
    - Admin changing date of files.
level: medium
```
