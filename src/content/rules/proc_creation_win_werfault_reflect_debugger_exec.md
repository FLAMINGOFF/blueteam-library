---
title: Potential ReflectDebugger Content Execution Via WerFault.EXE
summary: >-
  Detects execution of "WerFault.exe" with the "-pr" commandline flag that is used to run files stored in the ReflectDebugger key which could be used to store the path to the malware in order to
  masquerade the execution flow
sigma_id: fabfb3a7-3ce1-4445-9c7c-3c27f1051cdd
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1036
author: X__Junior (Nextron Systems)
date: '2023-06-30'
falsepositives:
  - Unknown
references:
  - https://cocomelonc.github.io/malware/2022/11/02/malware-pers-18.html
  - https://www.hexacorn.com/blog/2018/08/31/beyond-good-ol-run-key-part-85/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_werfault_reflect_debugger_exec.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Potential ReflectDebugger Content Execution Via WerFault.EXE
id: fabfb3a7-3ce1-4445-9c7c-3c27f1051cdd
related:
    - id: 0cf2e1c6-8d10-4273-8059-738778f981ad
      type: derived
status: test
description: Detects execution of "WerFault.exe" with the "-pr" commandline flag that is used to run files stored in the ReflectDebugger key which could be used to store the path to the malware in order to masquerade the execution flow
references:
    - https://cocomelonc.github.io/malware/2022/11/02/malware-pers-18.html
    - https://www.hexacorn.com/blog/2018/08/31/beyond-good-ol-run-key-part-85/
author: X__Junior (Nextron Systems)
date: 2023-06-30
tags:
    - attack.execution
    - attack.stealth
    - attack.t1036
logsource:
    product: windows
    category: process_creation
detection:
    selection_img:
        - Image|endswith: '\WerFault.exe'
        - OriginalFileName: 'WerFault.exe'
    selection_cli:
        CommandLine|contains: ' -pr '
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
```
