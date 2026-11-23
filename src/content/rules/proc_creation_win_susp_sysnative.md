---
title: Process Creation Using Sysnative Folder
summary: Detects process creation events that use the Sysnative folder (common for CobaltStrike spawns)
sigma_id: 3c1b5fb0-c72f-45ba-abd1-4d4c353144ab
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0005
techniques:
  - T1055
author: Max Altgelt (Nextron Systems)
date: '2022-08-23'
modified: '2025-10-08'
falsepositives:
  - Unknown
references:
  - https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_susp_sysnative.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Process Creation Using Sysnative Folder
id: 3c1b5fb0-c72f-45ba-abd1-4d4c353144ab
status: test
description: Detects process creation events that use the Sysnative folder (common for CobaltStrike spawns)
references:
    - https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/
author: Max Altgelt (Nextron Systems)
date: 2022-08-23
modified: 2025-10-08
tags:
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - CommandLine|contains: ':\Windows\Sysnative\'
        - Image|contains: ':\Windows\Sysnative\'
    filter_main_ngen:
        Image|contains:
            - 'C:\Windows\Microsoft.NET\Framework64\v'
            - 'C:\Windows\Microsoft.NET\Framework\v'
            - 'C:\Windows\Microsoft.NET\FrameworkArm\v'
            - 'C:\Windows\Microsoft.NET\FrameworkArm64\v'
        Image|endswith: '\ngen.exe'
        CommandLine|contains: 'install'
    filter_optional_xampp:
        CommandLine|contains|all:
            - '"C:\Windows\sysnative\cmd.exe"'
            - '\xampp\'
            - '\catalina_start.bat'
    condition: selection and not 1 of filter_main_* and not 1 of filter_optional_*
falsepositives:
    - Unknown
level: medium
```
