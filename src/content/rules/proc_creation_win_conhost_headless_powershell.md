---
title: Powershell Executed From Headless ConHost Process
summary: |-
  Detects the use of powershell commands from headless ConHost window.
  The "--headless" flag hides the windows from the user upon execution.
sigma_id: 056c7317-9a09-4bd4-9067-d051312752ea
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0002
  - TA0005
techniques:
  - T1059.001
  - T1059.003
  - T1564.003
author: Matt Anderson (Huntress)
date: '2024-07-23'
falsepositives:
  - Unknown
references:
  - https://www.huntress.com/blog/fake-browser-updates-lead-to-boinc-volunteer-computing-software
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_conhost_headless_powershell.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Powershell Executed From Headless ConHost Process
id: 056c7317-9a09-4bd4-9067-d051312752ea
related:
    - id: 00ca75ab-d5ce-43be-b86c-55ff39c6abfc
      type: derived
status: test
description: |
    Detects the use of powershell commands from headless ConHost window.
    The "--headless" flag hides the windows from the user upon execution.
references:
    - https://www.huntress.com/blog/fake-browser-updates-lead-to-boinc-volunteer-computing-software
author: Matt Anderson (Huntress)
date: 2024-07-23
tags:
    - attack.execution
    - attack.stealth
    - attack.t1059.001
    - attack.t1059.003
    - attack.t1564.003
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\conhost.exe'
        - OriginalFileName: 'CONHOST.EXE'
    selection_cli:
        CommandLine|contains|all:
            - '--headless'
            - 'powershell'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
regression_tests_path: regression_data/rules/windows/process_creation/proc_creation_win_conhost_headless_powershell/info.yml
```
