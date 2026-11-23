---
title: Suspicious Diantz Download and Compress Into a CAB File
summary: Download and compress a remote file and store it in a cab file on local machine.
sigma_id: 185d7418-f250-42d0-b72e-0c8b70661e93
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0011
techniques:
  - T1105
author: frack113
date: '2021-11-26'
modified: '2022-08-13'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Diantz/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_diantz_remote_cab.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Diantz Download and Compress Into a CAB File
id: 185d7418-f250-42d0-b72e-0c8b70661e93
status: test
description: Download and compress a remote file and store it in a cab file on local machine.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Diantz/
author: frack113
date: 2021-11-26
modified: 2022-08-13
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - diantz.exe
            - ' \\\\'
            - '.cab'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
