---
title: Suspicious GUP Usage
summary: Detects execution of the Notepad++ updater in a suspicious directory, which is often used in DLL side-loading attacks
sigma_id: 0a4f6091-223b-41f6-8743-f322ec84930b
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
  - TA0002
  - TA0005
techniques:
  - T1574.001
author: Florian Roth (Nextron Systems)
date: '2019-02-06'
modified: '2022-08-13'
falsepositives:
  - Execution of tools named GUP.exe and located in folders different than Notepad++\updater
references:
  - https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_gup_suspicious_execution.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Suspicious GUP Usage
id: 0a4f6091-223b-41f6-8743-f322ec84930b
status: test
description: Detects execution of the Notepad++ updater in a suspicious directory, which is often used in DLL side-loading attacks
references:
    - https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html
author: Florian Roth (Nextron Systems)
date: 2019-02-06
modified: 2022-08-13
tags:
    - attack.privilege-escalation
    - attack.persistence
    - attack.execution
    - attack.stealth
    - attack.t1574.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\GUP.exe'
    filter_programfiles:
        Image|endswith:
            - '\Program Files\Notepad++\updater\GUP.exe'
            - '\Program Files (x86)\Notepad++\updater\GUP.exe'
    filter_user:
        Image|contains: '\Users\'
        Image|endswith:
            - '\AppData\Local\Notepad++\updater\GUP.exe'
            - '\AppData\Roaming\Notepad++\updater\GUP.exe'
    condition: selection and not 1 of filter_*
falsepositives:
    - Execution of tools named GUP.exe and located in folders different than Notepad++\updater
level: high
```
