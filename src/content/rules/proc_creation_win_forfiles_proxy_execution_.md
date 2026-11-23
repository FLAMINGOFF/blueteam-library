---
title: Forfiles Command Execution
summary: |-
  Detects the execution of "forfiles" with the "/c" flag.
  While this is an expected behavior of the tool, it can be abused in order to proxy execution through it with any binary.
  Can be used to bypass application whitelisting.
sigma_id: 9aa5106d-bce3-4b13-86df-3a20f1d5cf0b
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1059
author: Tim Rauch, Elastic, E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
date: '2022-06-14'
modified: '2024-03-05'
falsepositives:
  - Legitimate use via a batch script or by an administrator.
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Forfiles/
  - https://pentestlab.blog/2020/07/06/indirect-command-execution/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_forfiles_proxy_execution_.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Forfiles Command Execution
id: 9aa5106d-bce3-4b13-86df-3a20f1d5cf0b
related:
    - id: a85cf4e3-56ee-4e79-adeb-789f8fb209a8
      type: obsolete
    - id: fa47597e-90e9-41cd-ab72-c3b74cfb0d02
      type: obsolete
status: test
description: |
    Detects the execution of "forfiles" with the "/c" flag.
    While this is an expected behavior of the tool, it can be abused in order to proxy execution through it with any binary.
    Can be used to bypass application whitelisting.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Forfiles/
    - https://pentestlab.blog/2020/07/06/indirect-command-execution/
author: Tim Rauch, Elastic, E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
date: 2022-06-14
modified: 2024-03-05
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\forfiles.exe'
        - OriginalFileName: 'forfiles.exe'
    selection_cli:
        CommandLine|contains|windash: ' -c '
    condition: all of selection_*
falsepositives:
    - Legitimate use via a batch script or by an administrator.
level: medium
```
