---
title: Potential LethalHTA Technique Execution
summary: Detects potential LethalHTA technique where the "mshta.exe" is spawned by an "svchost.exe" process
sigma_id: ed5d72a6-f8f4-479d-ba79-02f6a80d7471
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
techniques:
  - T1218.005
author: Markus Neis
date: '2018-06-07'
modified: '2023-02-07'
falsepositives:
  - Unknown
references:
  - https://codewhitesec.blogspot.com/2018/07/lethalhta.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_mshta_lethalhta_technique.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential LethalHTA Technique Execution
id: ed5d72a6-f8f4-479d-ba79-02f6a80d7471
status: test
description: Detects potential LethalHTA technique where the "mshta.exe" is spawned by an "svchost.exe" process
references:
    - https://codewhitesec.blogspot.com/2018/07/lethalhta.html
author: Markus Neis
date: 2018-06-07
modified: 2023-02-07
tags:
    - attack.stealth
    - attack.t1218.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\svchost.exe'
        Image|endswith: '\mshta.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
```
