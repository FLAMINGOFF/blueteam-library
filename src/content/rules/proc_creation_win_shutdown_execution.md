---
title: Suspicious Execution of Shutdown
summary: Use of the commandline to shutdown or reboot windows
sigma_id: 34ebb878-1b15-4895-b352-ca2eeb99b274
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0040
techniques:
  - T1529
author: frack113
date: '2022-01-01'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1529/T1529.md
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/shutdown
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_shutdown_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Execution of Shutdown
id: 34ebb878-1b15-4895-b352-ca2eeb99b274
status: test
description: Use of the commandline to shutdown or reboot windows
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1529/T1529.md
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/shutdown
author: frack113
date: 2022-01-01
tags:
    - attack.impact
    - attack.t1529
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\shutdown.exe'
        CommandLine|contains:
            - '/r '
            - '/s '
    condition: selection
falsepositives:
    - Unknown
level: medium
```
