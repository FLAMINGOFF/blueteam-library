---
title: Shell32 DLL Execution in Suspicious Directory
summary: Detects shell32.dll executing a DLL in a suspicious directory
sigma_id: 32b96012-7892-429e-b26c-ac2bf46066ff
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
techniques:
  - T1218.011
author: Christian Burkard (Nextron Systems)
date: '2021-11-24'
modified: '2023-02-09'
falsepositives:
  - Unknown
references:
  - https://www.group-ib.com/resources/threat-research/red-curl-2.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_rundll32_shell32_susp_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Shell32 DLL Execution in Suspicious Directory
id: 32b96012-7892-429e-b26c-ac2bf46066ff
status: test
description: Detects shell32.dll executing a DLL in a suspicious directory
references:
    - https://www.group-ib.com/resources/threat-research/red-curl-2.html
author: Christian Burkard (Nextron Systems)
date: 2021-11-24
modified: 2023-02-09
tags:
    - attack.execution
    - attack.stealth
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\rundll32.exe'
        - OriginalFileName: 'RUNDLL32.EXE'
    selection_cli:
        CommandLine|contains|all:
            - 'shell32.dll'
            - 'Control_RunDLL'
        CommandLine|contains:
            - '%AppData%'
            - '%LocalAppData%'
            - '%Temp%'
            - '%tmp%'
            - '\AppData\'
            - '\Temp\'
            - '\Users\Public\'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
```
