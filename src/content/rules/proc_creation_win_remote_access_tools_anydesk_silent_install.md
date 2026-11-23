---
title: Remote Access Tool - AnyDesk Silent Installation
summary: Detects AnyDesk Remote Desktop silent installation. Which can be used by attackers to gain remote access.
sigma_id: 114e7f1c-f137-48c8-8f54-3088c24ce4b9
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1219.002
author: Ján Trenčanský
date: '2021-08-06'
modified: '2023-03-05'
falsepositives:
  - Legitimate deployment of AnyDesk
references:
  - https://twitter.com/TheDFIRReport/status/1423361119926816776?s=20
  - https://support.anydesk.com/Automatic_Deployment
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_silent_install.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remote Access Tool - AnyDesk Silent Installation
id: 114e7f1c-f137-48c8-8f54-3088c24ce4b9
status: test
description: Detects AnyDesk Remote Desktop silent installation. Which can be used by attackers to gain remote access.
references:
    - https://twitter.com/TheDFIRReport/status/1423361119926816776?s=20
    - https://support.anydesk.com/Automatic_Deployment
author: Ján Trenčanský
date: 2021-08-06
modified: 2023-03-05
tags:
    - attack.command-and-control
    - attack.t1219.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '--install'
            - '--start-with-win'
            - '--silent'
    condition: selection
falsepositives:
    - Legitimate deployment of AnyDesk
level: high
```
