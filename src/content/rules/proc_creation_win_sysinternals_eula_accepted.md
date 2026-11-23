---
title: Potential Execution of Sysinternals Tools
summary: Detects command lines that contain the 'accepteula' flag which could be a sign of execution of one of the Sysinternals tools
sigma_id: 7cccd811-7ae9-4ebe-9afd-cb5c406b824b
status: test
level: low
platform: windows
logsource: windows / process_creation
tactics:
  - TA0042
techniques:
  - T1588.002
author: Markus Neis
date: '2017-08-28'
modified: '2024-03-13'
falsepositives:
  - Legitimate use of SysInternals tools
  - Programs that use the same command line flag
references:
  - https://twitter.com/Moti_B/status/1008587936735035392
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_sysinternals_eula_accepted.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential Execution of Sysinternals Tools
id: 7cccd811-7ae9-4ebe-9afd-cb5c406b824b
related:
    - id: 25ffa65d-76d8-4da5-a832-3f2b0136e133
      type: derived
status: test
description: Detects command lines that contain the 'accepteula' flag which could be a sign of execution of one of the Sysinternals tools
references:
    - https://twitter.com/Moti_B/status/1008587936735035392
author: Markus Neis
date: 2017-08-28
modified: 2024-03-13
tags:
    - attack.resource-development
    - attack.t1588.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|windash: ' -accepteula'
    condition: selection
falsepositives:
    - Legitimate use of SysInternals tools
    - Programs that use the same command line flag
level: low
```
