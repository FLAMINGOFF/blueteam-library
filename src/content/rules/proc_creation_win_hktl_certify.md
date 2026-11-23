---
title: HackTool - Certify Execution
summary: Detects Certify a tool for Active Directory certificate abuse based on PE metadata characteristics and common command line arguments.
sigma_id: 762f2482-ff21-4970-8939-0aa317a886bb
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0007
  - TA0006
techniques:
  - T1649
author: pH-T (Nextron Systems)
date: '2023-04-17'
modified: '2023-04-25'
falsepositives:
  - Unknown
references:
  - https://github.com/GhostPack/Certify
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_certify.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - Certify Execution
id: 762f2482-ff21-4970-8939-0aa317a886bb
status: test
description: Detects Certify a tool for Active Directory certificate abuse based on PE metadata characteristics and common command line arguments.
references:
    - https://github.com/GhostPack/Certify
author: pH-T (Nextron Systems)
date: 2023-04-17
modified: 2023-04-25
tags:
    - attack.discovery
    - attack.credential-access
    - attack.t1649
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\Certify.exe'
        - OriginalFileName: 'Certify.exe'
        - Description|contains: 'Certify'
    selection_cli_commands:
        CommandLine|contains:
            - '.exe cas '
            - '.exe find '
            - '.exe pkiobjects '
            - '.exe request '
            - '.exe download '
    selection_cli_options:
        CommandLine|contains:
            - ' /vulnerable'
            - ' /template:'
            - ' /altname:'
            - ' /domain:'
            - ' /path:'
            - ' /ca:'
    condition: selection_img or all of selection_cli_*
falsepositives:
    - Unknown
level: high
```
