---
title: Devtoolslauncher.exe Executes Specified Binary
summary: The Devtoolslauncher.exe executes other binary
sigma_id: cc268ac1-42d9-40fd-9ed3-8c4e1a5b87e6
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics: []
techniques:
  - T1218
author: Beyu Denis, oscd.community (rule), @_felamos (idea)
date: '2019-10-12'
modified: '2021-11-27'
falsepositives:
  - Legitimate use of devtoolslauncher.exe by legitimate user
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Devtoolslauncher/
  - https://twitter.com/_felamos/status/1179811992841797632
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_devtoolslauncher.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Devtoolslauncher.exe Executes Specified Binary
id: cc268ac1-42d9-40fd-9ed3-8c4e1a5b87e6
status: test
description: The Devtoolslauncher.exe executes other binary
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Devtoolslauncher/
    - https://twitter.com/_felamos/status/1179811992841797632
author: Beyu Denis, oscd.community (rule), @_felamos (idea)
date: 2019-10-12
modified: 2021-11-27
tags:
    - attack.stealth
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\devtoolslauncher.exe'
        CommandLine|contains: 'LaunchForDeploy'
    condition: selection
falsepositives:
    - Legitimate use of devtoolslauncher.exe by legitimate user
level: high
```
