---
title: Xwizard.EXE Execution From Non-Default Location
summary: |-
  Detects the execution of Xwizard tool from a non-default directory.
  When executed from a non-default directory, this utility can be abused in order to side load a custom version of "xwizards.dll".
sigma_id: 193d5ccd-6f59-40c6-b5b0-8e32d5ddd3d1
status: test
level: high
platform: windows
logsource: windows / process_creation
tactics:
  - TA0004
  - TA0003
  - TA0002
techniques:
  - T1574.001
author: Christian Burkard (Nextron Systems)
date: '2021-09-20'
modified: '2024-08-15'
falsepositives:
  - Windows installed on non-C drive
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Xwizard/
  - http://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/
source:
  name: SigmaHQ
  url: https://github.com/SigmaHQ/sigma/blob/698f0912f571d5fac3bf8c51f5421139834a011c/rules/windows/process_creation/proc_creation_win_xwizard_execution_non_default_location.yml
  license: DRL-1.1
  license_url: https://github.com/SigmaHQ/Detection-Rule-License
format: Sigma
---

```yaml
title: Xwizard.EXE Execution From Non-Default Location
id: 193d5ccd-6f59-40c6-b5b0-8e32d5ddd3d1
status: test
description: |
    Detects the execution of Xwizard tool from a non-default directory.
    When executed from a non-default directory, this utility can be abused in order to side load a custom version of "xwizards.dll".
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Xwizard/
    - http://www.hexacorn.com/blog/2017/07/31/the-wizard-of-x-oppa-plugx-style/
author: Christian Burkard (Nextron Systems)
date: 2021-09-20
modified: 2024-08-15
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
        - Image|endswith: '\xwizard.exe'
        - OriginalFileName: 'xwizard.exe'
    filter_main_legit_location:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Windows\WinSxS\'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Windows installed on non-C drive
level: high
```
