---
title: PktMon.EXE Execution
summary: Detects execution of PktMon, a tool that captures network packets.
sigma_id: f956c7c1-0f60-4bc5-b7d7-b39ab3c08908
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
  - TA0006
techniques:
  - T1040
author: frack113
date: '2022-03-17'
modified: '2023-06-23'
falsepositives:
  - Legitimate use
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Pktmon/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_pktmon_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: PktMon.EXE Execution
id: f956c7c1-0f60-4bc5-b7d7-b39ab3c08908
status: test
description: Detects execution of PktMon, a tool that captures network packets.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Pktmon/
author: frack113
date: 2022-03-17
modified: 2023-06-23
tags:
    - attack.discovery
    - attack.credential-access
    - attack.t1040
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\pktmon.exe'
        - OriginalFileName: 'PktMon.exe'
    condition: selection
falsepositives:
    - Legitimate use
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_pktmon_execution/info.yml
```
