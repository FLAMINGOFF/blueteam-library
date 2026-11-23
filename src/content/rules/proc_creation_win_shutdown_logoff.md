---
title: Suspicious Execution of Shutdown to Log Out
summary: Detects the rare use of the command line tool shutdown to logoff a user
sigma_id: ec290c06-9b6b-4338-8b6b-095c0f284f10
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0040
techniques:
  - T1529
author: frack113
date: '2022-10-01'
falsepositives:
  - Unknown
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/9e5b12c4912c07562aec7500447b11fa3e17e254/atomics/T1529/T1529.md
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/shutdown
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_shutdown_logoff.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Execution of Shutdown to Log Out
id: ec290c06-9b6b-4338-8b6b-095c0f284f10
status: test
description: Detects the rare use of the command line tool shutdown to logoff a user
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/9e5b12c4912c07562aec7500447b11fa3e17e254/atomics/T1529/T1529.md
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/shutdown
author: frack113
date: 2022-10-01
tags:
    - attack.impact
    - attack.t1529
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\shutdown.exe'
        CommandLine|contains: '/l'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
