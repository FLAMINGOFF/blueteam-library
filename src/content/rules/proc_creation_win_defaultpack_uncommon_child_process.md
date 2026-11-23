---
title: Uncommon Child Process Of Defaultpack.EXE
summary: Detects uncommon child processes of "DefaultPack.EXE" binary as a proxy to launch other programs
sigma_id: b2309017-4235-44fe-b5af-b15363011957
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0005
  - TA0002
techniques:
  - T1218
author: frack113
date: '2022-12-31'
modified: '2024-04-22'
falsepositives:
  - Unknown
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/DefaultPack/
  - https://web.archive.org/web/20231017001226/https://www.echotrail.io/insights/search/defaultpack.exe
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_defaultpack_uncommon_child_process.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Uncommon Child Process Of Defaultpack.EXE
id: b2309017-4235-44fe-b5af-b15363011957
status: test
description: Detects uncommon child processes of "DefaultPack.EXE" binary as a proxy to launch other programs
references:
    - https://lolbas-project.github.io/lolbas/OtherMSBinaries/DefaultPack/
    - https://web.archive.org/web/20231017001226/https://www.echotrail.io/insights/search/defaultpack.exe
author: frack113
date: 2022-12-31
modified: 2024-04-22
tags:
    - attack.stealth
    - attack.t1218
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\DefaultPack.exe'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
