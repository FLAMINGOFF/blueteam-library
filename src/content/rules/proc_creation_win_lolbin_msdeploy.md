---
title: Execute Files with Msdeploy.exe
summary: Detects file execution using the msdeploy.exe lolbin
sigma_id: 646bc99f-6682-4b47-a73a-17b1b64c9d34
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218
author: Beyu Denis, oscd.community
date: '2020-10-18'
modified: '2021-11-27'
falsepositives:
  - System administrator Usage
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Msdeploy/
  - https://twitter.com/pabraeken/status/995837734379032576
  - https://twitter.com/pabraeken/status/999090532839313408
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_msdeploy.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Execute Files with Msdeploy.exe
id: 646bc99f-6682-4b47-a73a-17b1b64c9d34
status: test
description: Detects file execution using the msdeploy.exe lolbin
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Msdeploy/
    - https://twitter.com/pabraeken/status/995837734379032576
    - https://twitter.com/pabraeken/status/999090532839313408
author: Beyu Denis, oscd.community
date: 2020-10-18
modified: 2021-11-27
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'verb:sync'
            - '-source:RunCommand'
            - '-dest:runCommand'
        Image|endswith: '\msdeploy.exe'
    condition: selection
falsepositives:
    - System administrator Usage
level: medium
```
