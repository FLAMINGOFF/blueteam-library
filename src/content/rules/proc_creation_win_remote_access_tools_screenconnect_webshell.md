---
title: Remote Access Tool - ScreenConnect Server Web Shell Execution
summary: Detects potential web shell execution from the ScreenConnect server process.
sigma_id: b19146a3-25d4-41b4-928b-1e2a92641b1b
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0001
techniques:
  - T1190
author: Jason Rathbun (Blackpoint Cyber)
date: '2024-02-26'
falsepositives:
  - Unlikely
references:
  - https://blackpointcyber.com/resources/blog/breaking-through-the-screen/
  - https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect_webshell.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Remote Access Tool - ScreenConnect Server Web Shell Execution
id: b19146a3-25d4-41b4-928b-1e2a92641b1b
status: test
description: Detects potential web shell execution from the ScreenConnect server process.
references:
    - https://blackpointcyber.com/resources/blog/breaking-through-the-screen/
    - https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8
author: Jason Rathbun (Blackpoint Cyber)
date: 2024-02-26
tags:
    - attack.initial-access
    - attack.t1190
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage|endswith: '\ScreenConnect.Service.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\csc.exe'
    condition: selection
falsepositives:
    - Unlikely
level: high
```
