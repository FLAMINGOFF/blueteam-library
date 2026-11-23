---
title: DLL Execution Via Register-cimprovider.exe
summary: Detects using register-cimprovider.exe to execute arbitrary dll file.
sigma_id: a2910908-e86f-4687-aeba-76a5f996e652
status: test
level: medium
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
  - TA0002
  - TA0005
techniques:
  - T1574
author: Ivan Dyachkov, Yulia Fomina, oscd.community
date: '2020-10-07'
modified: '2021-11-27'
falsepositives:
  - Unknown
references:
  - https://twitter.com/PhilipTsukerman/status/992021361106268161
  - https://lolbas-project.github.io/lolbas/Binaries/Register-cimprovider/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_registry_cimprovider_dll_load.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: DLL Execution Via Register-cimprovider.exe
id: a2910908-e86f-4687-aeba-76a5f996e652
status: test
description: Detects using register-cimprovider.exe to execute arbitrary dll file.
references:
    - https://twitter.com/PhilipTsukerman/status/992021361106268161
    - https://lolbas-project.github.io/lolbas/Binaries/Register-cimprovider/
author: Ivan Dyachkov, Yulia Fomina, oscd.community
date: 2020-10-07
modified: 2021-11-27
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.stealth
    - attack.t1574
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\register-cimprovider.exe'
        CommandLine|contains|all:
            - '-path'
            - 'dll'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
