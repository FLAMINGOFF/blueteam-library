---
title: Suspicious Extrac32 Execution
summary: Download or Copy file with Extrac32
sigma_id: aa8e035d-7be4-48d3-a944-102aec04400d
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
  - https://lolbas-project.github.io/lolbas/Binaries/Extrac32/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_lolbin_extrac32.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious Extrac32 Execution
id: aa8e035d-7be4-48d3-a944-102aec04400d
status: test
description: Download or Copy file with Extrac32
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Extrac32/
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
    selection_lolbas:
        - CommandLine|contains: extrac32.exe
        - Image|endswith: '\extrac32.exe'
        - OriginalFileName: 'extrac32.exe'
    selection_archive:
        CommandLine|contains: '.cab'
    selection_options:
        CommandLine|contains:
            - /C
            - /Y
            - ' \\\\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
