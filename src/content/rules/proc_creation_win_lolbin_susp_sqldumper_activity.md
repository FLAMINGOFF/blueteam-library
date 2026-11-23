---
title: Dumping Process via Sqldumper.exe
summary: Detects process dump via legitimate sqldumper.exe binary
sigma_id: 23ceaf5c-b6f1-4a32-8559-f2ff734be516
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1003.001
author: Kirill Kiryanov, oscd.community
date: '2020-10-08'
modified: '2021-11-27'
falsepositives:
  - Legitimate MSSQL Server actions
references:
  - https://twitter.com/countuponsec/status/910977826853068800
  - https://twitter.com/countuponsec/status/910969424215232518
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Sqldumper/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_susp_sqldumper_activity.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Dumping Process via Sqldumper.exe
id: 23ceaf5c-b6f1-4a32-8559-f2ff734be516
status: test
description: Detects process dump via legitimate sqldumper.exe binary
references:
    - https://twitter.com/countuponsec/status/910977826853068800
    - https://twitter.com/countuponsec/status/910969424215232518
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Sqldumper/
author: Kirill Kiryanov, oscd.community
date: 2020-10-08
modified: 2021-11-27
tags:
    - attack.credential-access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\sqldumper.exe'
        CommandLine|contains:
            - '0x0110'
            - '0x01100:40'
    condition: selection
falsepositives:
    - Legitimate MSSQL Server actions
level: medium
```
