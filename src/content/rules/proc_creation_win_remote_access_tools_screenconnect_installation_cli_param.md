---
title: Remote Access Tool - ScreenConnect Installation Execution
summary: Detects ScreenConnect program starts that establish a remote access to a system.
sigma_id: 75bfe6e6-cd8e-429e-91d3-03921e1d7962
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0003
  - TA0001
techniques:
  - T1133
author: Florian Roth (Nextron Systems)
date: '2021-02-11'
modified: '2024-02-26'
falsepositives:
  - Legitimate use by administrative staff
references:
  - https://www.anomali.com/blog/probable-iranian-cyber-actors-static-kitten-conducting-cyberespionage-campaign-targeting-uae-and-kuwait-government-agencies
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect_installation_cli_param.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remote Access Tool - ScreenConnect Installation Execution
id: 75bfe6e6-cd8e-429e-91d3-03921e1d7962
status: test
description: Detects ScreenConnect program starts that establish a remote access to a system.
references:
    - https://www.anomali.com/blog/probable-iranian-cyber-actors-static-kitten-conducting-cyberespionage-campaign-targeting-uae-and-kuwait-government-agencies
author: Florian Roth (Nextron Systems)
date: 2021-02-11
modified: 2024-02-26
tags:
    - attack.persistence
    - attack.initial-access
    - attack.t1133
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'e=Access&'
            - 'y=Guest&'
            - '&p='
            - '&c='
            - '&k='
    condition: selection
falsepositives:
    - Legitimate use by administrative staff
level: medium
```
