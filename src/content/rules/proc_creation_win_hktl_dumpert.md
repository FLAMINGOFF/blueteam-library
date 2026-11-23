---
title: HackTool - Dumpert Process Dumper Execution
summary: Detects the use of Dumpert process dumper, which dumps the lsass.exe process memory
sigma_id: 2704ab9e-afe2-4854-a3b1-0c0706d03578
status: test
level: critical
platform: windows
logsource: windows / process_creation
tactics:
  - TA0006
techniques:
  - T1003.001
author: Florian Roth (Nextron Systems)
date: '2020-02-04'
modified: '2026-09-16'
falsepositives:
  - Very unlikely
references:
  - https://github.com/outflanknl/Dumpert
  - https://unit42.paloaltonetworks.com/actors-still-exploiting-sharepoint-vulnerability/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_hktl_dumpert.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: HackTool - Dumpert Process Dumper Execution
id: 2704ab9e-afe2-4854-a3b1-0c0706d03578
status: test
description: Detects the use of Dumpert process dumper, which dumps the lsass.exe process memory
references:
    - https://github.com/outflanknl/Dumpert
    - https://unit42.paloaltonetworks.com/actors-still-exploiting-sharepoint-vulnerability/
author: Florian Roth (Nextron Systems)
date: 2020-02-04
modified: 2026-09-16
tags:
    - attack.credential-access
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Hashes|contains: 'IMPHASH=09D278F9DE118EF09163C6140255C690'
        - CommandLine|contains:
              - 'Dumpert.dll'
              - 'Dumpert.exe'
    condition: selection
falsepositives:
    - Very unlikely
level: critical
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_hktl_dumpert/info.yml
```
